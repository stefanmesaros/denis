//! Single sign-on via OpenID Connect: an administrator points DENIS at an identity provider
//! (Entra ID, Okta, Google Workspace, Keycloak, anything speaking OIDC), and users sign in with
//! it instead of a local password. Local accounts (and the initial admin password) keep working
//! alongside it — this is an additional way in, not a replacement for the one already there.
//!
//! Provisioning: the first successful sign-in for an email creates a local account for it,
//! `viewer` role by default (an administrator raises it afterwards, same as any other account).
//! An existing local account whose username matches the identity provider's email is used as-is,
//! so migrating an existing user to SSO needs nothing on DENIS's side. An SSO-signed-in account
//! never has a usable local password (a random one is set and never revealed) and is never asked
//! to change it.
//!
//! What is deliberately out of scope: SAML (OIDC covers every provider this project has seen
//! asked for, at a fraction of the complexity — a SAML relying party is a much larger, more
//! fragile piece of code for the same outcome), and SCIM/directory sync (accounts are still
//! provisioned by first sign-in, not pushed ahead of time).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
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
        }
        Ok(())
    }
}

/// One authorization request in flight, between the redirect out and the callback in. Kept in
/// memory only (a login interrupted by a restart just starts over) and single-use.
struct Pending {
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    created_at: i64,
}

static PENDING: Mutex<Option<HashMap<String, Pending>>> = Mutex::new(None);
/// A request abandoned this long ago (never came back from the identity provider) is forgotten.
const PENDING_TTL_SECS: i64 = 600;

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn stash_pending(state: String, nonce: Nonce, pkce_verifier: PkceCodeVerifier) {
    let mut g = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    let now = now_secs();
    map.retain(|_, p: &mut Pending| now - p.created_at < PENDING_TTL_SECS);
    map.insert(state, Pending { nonce, pkce_verifier, created_at: now });
}

fn take_pending(state: &str) -> Option<(Nonce, PkceCodeVerifier)> {
    let mut g = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.as_mut()?;
    let p = map.remove(state)?;
    if now_secs() - p.created_at >= PENDING_TTL_SECS {
        return None;
    }
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

/// Start a sign-in: the URL to send the browser to, having stashed what the callback needs to
/// verify it really is the same request coming back (CSRF state, nonce, PKCE verifier).
pub fn start(cfg: &SsoConfig, redirect_url: &str) -> Result<String> {
    let client = build_client(cfg, redirect_url)?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = client
        .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    stash_pending(csrf_state.secret().clone(), nonce, pkce_verifier);
    Ok(auth_url.to_string())
}

/// A verified identity handed back by the provider: enough to find or provision a local account.
pub struct Identity {
    /// Always present: what the local account is keyed on (see the module docs).
    pub email: String,
    /// For the audit log and, the first time, as a friendlier starting display name.
    pub name: Option<String>,
}

/// Finish a sign-in: exchange the code, verify the ID token's signature and claims (issuer,
/// audience, expiry, and — critically — the nonce from `start`, which is what stops a token
/// meant for a different login attempt from being replayed into this one).
pub fn finish(cfg: &SsoConfig, redirect_url: &str, code: &str, state: &str) -> Result<Identity> {
    let (nonce, pkce_verifier) = take_pending(state).ok_or_else(|| anyhow!("this sign-in link was already used, took too long, or does not belong to this browser — start again"))?;
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
    let name = claims.name().and_then(|n| n.get(None)).map(|n| n.as_str().to_string());
    Ok(Identity { email: email.as_str().to_lowercase(), name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SsoConfig {
        SsoConfig { enabled: true, issuer_url: "https://idp.example.com".into(), client_id: "abc".into(), client_secret: "s3cr3t".into(), button_label: String::new() }
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
    fn a_pending_login_is_single_use_and_a_wrong_state_is_refused() {
        clear_pending_for_test();
        stash_pending("state1".into(), Nonce::new("n1".into()), PkceCodeVerifier::new("v1".into()));
        assert!(take_pending("no-such-state").is_none());
        let (nonce, verifier) = take_pending("state1").expect("was stashed");
        assert_eq!(nonce.secret(), "n1");
        assert_eq!(verifier.secret(), "v1");
        // used once: a replay of the same callback (e.g. the browser's back button) fails closed
        assert!(take_pending("state1").is_none());
    }

    #[test]
    fn a_pending_login_older_than_the_ttl_is_forgotten() {
        clear_pending_for_test();
        let mut g = PENDING.lock().unwrap();
        g.get_or_insert_with(HashMap::new).insert(
            "stale".to_string(),
            Pending { nonce: Nonce::new("n".into()), pkce_verifier: PkceCodeVerifier::new("v".into()), created_at: now_secs() - PENDING_TTL_SECS - 1 },
        );
        drop(g);
        assert!(take_pending("stale").is_none());
    }
}
