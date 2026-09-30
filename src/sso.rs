//! Single sign-on via OpenID Connect: an administrator points DENIS at an identity provider
//! (Entra ID, Okta, Google Workspace, Keycloak, anything speaking OIDC), and users sign in with
//! it instead of a local password. Local accounts (and the initial admin password) keep working
//! alongside it — this is an additional way in, not a replacement for the one already there.
//!
//! **Identity, and why it changed (SECURITY_ARCHITECTURE_REVIEW.md H2, 2026-09-30).** An account
//! is linked by `(issuer, sub)` — the identity provider's own stable identifier, stored in
//! `sso_identities` — never by email. An email can be reassigned or spoofed at a self-registering
//! IdP; `sub` is what the IdP itself promises never changes for one account. The first successful
//! sign-in for a `(issuer, sub)` the store has never seen creates a new local account, `viewer`
//! role, keyed on the IdP's email as its username. If a local account with that email *already
//! exists* but is not yet linked, sign-in is refused — an administrator links the two accounts
//! explicitly (`AuthStore::link_sso_identity`), never automatically. An SSO-signed-in account
//! never has a usable local password (a random one is set and never revealed) and is never asked
//! to change it.
//!
//! **Also required, every time (H2):** the global on/off switch is checked in `start` and
//! `finish` themselves, not only by the console's decision to show a button — a direct request to
//! the login/callback routes is refused exactly the same way. `email_verified` must be `true`
//! whenever the claim is present at all. An administrator must configure at least one allowed
//! email domain before SSO can be enabled at all — an empty list is refused by `validate()`, so
//! there is no way to turn SSO on for "anyone at this IdP" by omission.
//!
//! **The TOTP/passkey question, decided:** an SSO sign-in does **not** need to separately satisfy
//! a local account's authenticator-app or passkey-only requirement. Delegating authentication to
//! an IdP *is* the point of SSO — DENIS has no visibility into whatever the IdP itself required
//! (its own MFA, conditional access, etc.), and an SSO-provisioned account has no usable local
//! password to even attempt a second local factor against. Requiring one anyway would either be
//! impossible to satisfy or would silently reduce to "the random password DENIS generated,"
//! neither of which adds real assurance. This is a deliberate product decision, not an oversight.
//!
//! What is deliberately out of scope: SAML (OIDC covers every provider this project has seen
//! asked for, at a fraction of the complexity — a SAML relying party is a much larger, more
//! fragile piece of code for the same outcome), and SCIM/directory sync (accounts are still
//! provisioned by first sign-in, not pushed ahead of time).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};

use crate::store::SettingsStore;

pub const KEY: &str = "sso";

/// An administrator's OIDC configuration. Absent (the default) means SSO is not offered at all.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SsoConfig {
    pub enabled: bool,
    /// e.g. `https://login.microsoftonline.com/<tenant>/v2.0`, `https://accounts.google.com`.
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// What the sign-in button says, e.g. "Sign in with Okta". Falls back to a generic label.
    #[serde(default)]
    pub button_label: String,
    /// Email domains (e.g. `acme.com`, case-insensitive, no leading `@`) allowed to sign in.
    /// Required non-empty whenever `enabled` (see `validate`) — the fix for "any account at a
    /// public issuer gets a viewer session" (SECURITY_ARCHITECTURE_REVIEW.md H2): an empty list
    /// must refuse configuring SSO at all, not silently allow every domain.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

pub fn load(store: &dyn SettingsStore) -> Result<SsoConfig> {
    Ok(store.get_setting(KEY)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default())
}

pub fn save(store: &dyn SettingsStore, c: &SsoConfig, now: i64) -> Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(c)?, now)
}

/// What the console needs to decide whether to show a sign-in button, without exposing the
/// client secret to anyone (this is served to a signed-out visitor).
#[derive(Serialize)]
pub struct PublicStatus {
    pub enabled: bool,
    pub button_label: String,
}

impl SsoConfig {
    pub fn public(&self) -> PublicStatus {
        PublicStatus {
            enabled: self.enabled && !self.issuer_url.is_empty() && !self.client_id.is_empty(),
            button_label: if self.button_label.is_empty() { "Single sign-on".into() } else { self.button_label.clone() },
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.enabled {
            if self.issuer_url.is_empty() || !(self.issuer_url.starts_with("https://") || self.issuer_url.starts_with("http://")) {
                return Err("issuer URL must be a full https:// address");
            }
            if self.client_id.is_empty() {
                return Err("client ID is required");
            }
            if self.client_secret.is_empty() {
                return Err("client secret is required");
            }
            if self.allowed_domains.is_empty() {
                return Err("at least one allowed email domain is required");
            }
        }
        Ok(())
    }

    /// Whether `email` may sign in at all, per the allowed-domains list. Case-insensitive; a
    /// domain with no `@` in `email` never matches anything.
    fn domain_allowed(&self, email: &str) -> bool {
        let Some(domain) = email.rsplit('@').next().filter(|_| email.contains('@')) else { return false };
        self.allowed_domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
    }
}

/// One authorization request in flight, between the redirect out and the callback in. Kept in
/// memory only (a login interrupted by a restart just starts over) and single-use.
struct Pending {
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    created_at: i64,
    /// The random value handed to the browser as a short-lived cookie at `start` (M9: login CSRF,
    /// see the module docs). `finish` refuses unless the browser presents this same value back,
    /// so a link captured by an attacker and opened by the victim cannot complete a sign-in: the
    /// attacker's browser holds the cookie, not the victim's.
    browser_token: String,
}

static PENDING: Mutex<Option<HashMap<String, Pending>>> = Mutex::new(None);
/// A request abandoned this long ago (never came back from the identity provider) is forgotten.
const PENDING_TTL_SECS: i64 = 600;

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn stash_pending(state: String, nonce: Nonce, pkce_verifier: PkceCodeVerifier, browser_token: String) {
    let mut g = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    let now = now_secs();
    map.retain(|_, p: &mut Pending| now - p.created_at < PENDING_TTL_SECS);
    map.insert(state, Pending { nonce, pkce_verifier, created_at: now, browser_token });
}

/// `browser_token` is whatever the request's own short-lived cookie carried (empty if there was
/// none) - compared against what `start` handed that same browser, not merely checked for
/// presence, so a captured `state`/`code` pair is useless without also holding the cookie.
fn take_pending(state: &str, browser_token: &str) -> Option<(Nonce, PkceCodeVerifier)> {
    let mut g = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.as_mut()?;
    // Peek before removing: a wrong or missing cookie must not burn the real pending login, since
    // the legitimate browser (which never sent this request) still needs to be able to complete
    // it - only an actual match, or an expiry, consumes the entry.
    let p = map.get(state)?;
    if now_secs() - p.created_at >= PENDING_TTL_SECS {
        map.remove(state);
        return None;
    }
    if browser_token.is_empty() || p.browser_token != browser_token {
        return None;
    }
    let p = map.remove(state)?;
    Some((p.nonce, p.pkce_verifier))
}

#[cfg(test)]
pub fn clear_pending_for_test() {
    *PENDING.lock().unwrap() = None;
}

fn http_client() -> openidconnect::ureq::Agent {
    // Following redirects on these calls would open the door to SSRF via a malicious or
    // compromised identity provider redirecting the discovery/token requests elsewhere.
    openidconnect::ureq::AgentBuilder::new().redirects(0).build()
}

type SsoClient = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

fn build_client(cfg: &SsoConfig, redirect_url: &str) -> Result<SsoClient> {
    cfg.validate().map_err(|e| anyhow!("{e}"))?;
    let issuer = IssuerUrl::new(cfg.issuer_url.clone()).context("invalid issuer URL")?;
    let http = http_client();
    let metadata = CoreProviderMetadata::discover(&issuer, &http).map_err(|e| anyhow!("could not reach the identity provider's discovery document: {e}"))?;
    let redirect = RedirectUrl::new(redirect_url.to_string()).context("invalid redirect URL")?;
    Ok(CoreClient::from_provider_metadata(metadata, ClientId::new(cfg.client_id.clone()), Some(ClientSecret::new(cfg.client_secret.clone()))).set_redirect_uri(redirect))
}

/// Start a sign-in: the URL to send the browser to, and a random value the caller must set as a
/// short-lived, `HttpOnly`, `SameSite=Lax` cookie on this same response (M9) - `finish` will
/// refuse unless that exact cookie comes back with the callback. Having stashed what the callback
/// needs to verify it really is the same request coming back (CSRF state, nonce, PKCE verifier).
pub fn start(cfg: &SsoConfig, redirect_url: &str) -> Result<(String, String)> {
    // Checked here, not only by the console's decision to show a button
    // (SECURITY_ARCHITECTURE_REVIEW.md H2): a direct request to this route must be refused too,
    // so turning SSO off in Settings actually stops it, including for anyone who bookmarked the
    // login URL while it was on.
    if !cfg.enabled {
        bail!("single sign-on is turned off");
    }
    let client = build_client(cfg, redirect_url)?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = client
        .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    let browser_token = CsrfToken::new_random().secret().clone();
    stash_pending(csrf_state.secret().clone(), nonce, pkce_verifier, browser_token.clone());
    Ok((auth_url.to_string(), browser_token))
}

/// A verified identity handed back by the provider: enough to find or provision a local account.
#[derive(Debug)]
pub struct Identity {
    /// The configured issuer URL - half of the `(issuer, sub)` linking key (see the module docs).
    /// The configured value, not one re-read from the token: there is exactly one issuer per
    /// installation's SSO config, so this is simpler than extracting it from the claims and
    /// cannot be spoofed by a token claiming a different issuer than the one DENIS was told to
    /// trust (the token verifier already checks the issuer matches this same configured one).
    pub issuer: String,
    /// The other half of the linking key: the IdP's own stable subject identifier.
    pub sub: String,
    /// What the *new* local account is keyed on, the first time this `(issuer, sub)` is seen.
    pub email: String,
    /// For the audit log and, the first time, as a friendlier starting display name.
    pub name: Option<String>,
}

/// Finish a sign-in: exchange the code, verify the ID token's signature and claims (issuer,
/// audience, expiry, and — critically — the nonce from `start`, which is what stops a token
/// meant for a different login attempt from being replayed into this one). `browser_token` is the
/// cookie `start` asked to be set on this same browser (M9): without a match, this is refused
/// before ever contacting the identity provider, which is what actually stops the classic OIDC
/// login-CSRF (an attacker completes their own sign-in, then gets the victim to open the callback
/// URL, landing the victim in the attacker's account).
pub fn finish(cfg: &SsoConfig, redirect_url: &str, code: &str, state: &str, browser_token: &str) -> Result<Identity> {
    // Same reasoning as `start` (SECURITY_ARCHITECTURE_REVIEW.md H2): checked here too, not only
    // where the button is shown.
    if !cfg.enabled {
        bail!("single sign-on is turned off");
    }
    let (nonce, pkce_verifier) = take_pending(state, browser_token).ok_or_else(|| anyhow!("this sign-in link was already used, took too long, or does not belong to this browser — start again"))?;
    let client = build_client(cfg, redirect_url)?;
    let http = http_client();
    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .map_err(|e| anyhow!("{e}"))?
        .set_pkce_verifier(pkce_verifier)
        .request(&http)
        .map_err(|e| anyhow!("could not reach the identity provider's token endpoint: {e}"))?;
    let id_token = token_response.extra_fields().id_token().ok_or_else(|| anyhow!("the identity provider did not return an ID token (is 'openid' scope enabled for this client?)"))?;
    let claims = id_token.claims(&client.id_token_verifier(), &nonce).map_err(|e| anyhow!("the identity provider's token did not check out: {e}"))?;
    let email = claims.email().ok_or_else(|| anyhow!("the identity provider did not include an email address (add the 'email' scope/claim for this client)"))?;
    // `false` (present and explicitly unverified) is refused; `None` (the claim was simply not
    // sent) is not - many IdPs never send it at all, and treating "absent" the same as "false"
    // would refuse every sign-in at those providers (SECURITY_ARCHITECTURE_REVIEW.md H2 only asks
    // to check it "whenever the claim is present at all").
    if claims.email_verified() == Some(false) {
        bail!("the identity provider says this email address is not verified");
    }
    let email = email.as_str().to_lowercase();
    if !cfg.domain_allowed(&email) {
        bail!("{email} is not at an allowed domain for this identity provider");
    }
    let name = claims.name().and_then(|n| n.get(None)).map(|n| n.as_str().to_string());
    Ok(Identity { issuer: cfg.issuer_url.clone(), sub: claims.subject().as_str().to_string(), email, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SsoConfig {
        SsoConfig { enabled: true, issuer_url: "https://idp.example.com".into(), client_id: "abc".into(), client_secret: "s3cr3t".into(), button_label: String::new(), allowed_domains: vec!["acme.com".into()] }
    }

    #[test]
    fn disabled_or_unconfigured_never_shows_a_button() {
        assert!(!SsoConfig::default().public().enabled);
        let mut c = cfg();
        c.enabled = false;
        assert!(!c.public().enabled);
        let mut c = cfg();
        c.client_id = String::new();
        assert!(!c.public().enabled);
    }

    #[test]
    fn configured_and_enabled_shows_a_button_with_a_default_label() {
        let p = cfg().public();
        assert!(p.enabled);
        assert_eq!(p.button_label, "Single sign-on");
        let mut c = cfg();
        c.button_label = "Sign in with Acme".into();
        assert_eq!(c.public().button_label, "Sign in with Acme");
    }

    #[test]
    fn validation_only_applies_while_enabled() {
        let mut c = cfg();
        c.enabled = false;
        c.issuer_url.clear();
        assert!(c.validate().is_ok(), "an unfinished, disabled config is never rejected");
        c.enabled = true;
        assert!(c.validate().is_err());
        let mut c = cfg();
        c.issuer_url = "not a url".into();
        assert!(c.validate().is_err());
        let mut c = cfg();
        c.client_secret.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn an_empty_allowed_domains_list_refuses_to_enable_sso_at_all() {
        // SECURITY_ARCHITECTURE_REVIEW.md H2: no way to turn SSO on for "anyone at this IdP" by
        // simply never filling in the domain list.
        let mut c = cfg();
        c.allowed_domains.clear();
        assert!(c.validate().is_err());
        c.allowed_domains.push("acme.com".into());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn domain_matching_is_case_insensitive_and_needs_an_at_sign() {
        let c = cfg(); // allowed_domains: ["acme.com"]
        assert!(c.domain_allowed("alice@acme.com"));
        assert!(c.domain_allowed("alice@ACME.COM"), "case-insensitive");
        assert!(!c.domain_allowed("alice@evil.com"));
        assert!(!c.domain_allowed("not-an-email"), "no @ at all never matches");
    }

    #[test]
    fn start_and_finish_both_refuse_outright_when_sso_is_disabled() {
        // SECURITY_ARCHITECTURE_REVIEW.md H2: turning SSO off in Settings must actually stop it,
        // not just hide the button - checked here, not only by the console's own decision to
        // show a sign-in link.
        let mut c = cfg();
        c.enabled = false;
        assert!(start(&c, "https://denis.example/callback").unwrap_err().to_string().contains("turned off"));
        assert!(finish(&c, "https://denis.example/callback", "code", "state", "tok").unwrap_err().to_string().contains("turned off"));
    }

    #[test]
    fn a_pending_login_is_single_use_and_a_wrong_state_is_refused() {
        clear_pending_for_test();
        stash_pending("state1".into(), Nonce::new("n1".into()), PkceCodeVerifier::new("v1".into()), "tok1".into());
        assert!(take_pending("no-such-state", "tok1").is_none());
        let (nonce, verifier) = take_pending("state1", "tok1").expect("was stashed");
        assert_eq!(nonce.secret(), "n1");
        assert_eq!(verifier.secret(), "v1");
        // used once: a replay of the same callback (e.g. the browser's back button) fails closed
        assert!(take_pending("state1", "tok1").is_none());
    }

    #[test]
    fn a_pending_login_older_than_the_ttl_is_forgotten() {
        clear_pending_for_test();
        let mut g = PENDING.lock().unwrap();
        g.get_or_insert_with(HashMap::new).insert(
            "stale".to_string(),
            Pending { nonce: Nonce::new("n".into()), pkce_verifier: PkceCodeVerifier::new("v".into()), created_at: now_secs() - PENDING_TTL_SECS - 1, browser_token: "tok".into() },
        );
        drop(g);
        assert!(take_pending("stale", "tok").is_none());
    }

    #[test]
    fn a_pending_login_is_refused_without_the_matching_browser_cookie() {
        // M9: this is the actual login-CSRF fix - a captured (state, code) pair is useless to an
        // attacker who cannot also present the victim's browser_token cookie.
        clear_pending_for_test();
        stash_pending("state1".into(), Nonce::new("n1".into()), PkceCodeVerifier::new("v1".into()), "victims-cookie".into());
        assert!(take_pending("state1", "attackers-cookie").is_none(), "wrong cookie: refused");
        assert!(take_pending("state1", "").is_none(), "no cookie at all: refused");
        // the pending entry is untouched by a refused attempt: the real browser can still complete it
        assert!(take_pending("state1", "victims-cookie").is_some(), "the right cookie still works");
    }
}
