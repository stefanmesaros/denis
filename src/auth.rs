//! Authentication, sessions and per-agent tokens.
//!
//! Design rules (this is security software and will be pentested):
//! * No default or hard-coded credentials: the first start creates `admin`
//!   with a random password that must be changed at first login.
//! * Passwords are Argon2id hashes; session and agent tokens are 256-bit random
//!   values of which only a SHA-256 hash is stored, so a database leak does not
//!   hand out live credentials.
//! * Unknown users cost the same as wrong passwords (no user enumeration by
//!   timing or message), and repeated failures lock the account out with
//!   exponential back-off.
//! * Sessions expire when idle and absolutely; changing a password signs the
//!   user out everywhere else.
//! * The last enabled administrator cannot be removed.
//! * A person can add a second step: a code from an authenticator app. The password alone then only earns a
//!   short-lived, single-use *ticket*; the session comes when the code (or a recovery code) is right. A right
//!   password does not reset the count of wrong codes, so the code cannot be guessed by re-entering the password.
//!   Signing in with a passkey already is two factors and asks for nothing more.
//!
//! Time is passed in so all of it is testable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Result};
use argon2::password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use sha2::{Digest, Sha256};

use crate::model::User;
use crate::store::{AgentToken, Store};

pub const ROLES: &[&str] = &["viewer", "editor", "admin"];
pub const SESSION_IDLE_SECS: i64 = 12 * 3600;
pub const SESSION_MAX_SECS: i64 = 7 * 86_400;
pub const MIN_PASSWORD_LEN: usize = 12;

pub fn role_rank(role: &str) -> u8 {
    match role {
        "admin" => 3,
        "editor" => 2,
        "viewer" => 1,
        _ => 0,
    }
}

#[derive(Debug)]
pub enum AuthError {
    /// Wrong username or password (deliberately indistinguishable).
    Invalid,
    /// Too many failures: try again in this many seconds.
    Locked(i64),
    /// The request itself is unacceptable (weak password, bad username...).
    Rejected(String),
    /// The password was right but a one-time code is needed too: this ticket goes with it.
    MfaRequired(String),
    Internal(anyhow::Error),
}

impl From<serde_json::Error> for AuthError {
    fn from(e: serde_json::Error) -> Self {
        AuthError::Internal(e.into())
    }
}

impl From<anyhow::Error> for AuthError {
    fn from(e: anyhow::Error) -> Self {
        AuthError::Internal(e)
    }
}

#[derive(Default)]
struct Attempts {
    fails: u32,
    locked_until: i64,
}

pub struct Auth {
    store: Arc<dyn Store>,
    attempts: Mutex<HashMap<String, Attempts>>,
    last_agent_touch: Mutex<HashMap<String, i64>>,
    /// Failed sign-ins per client address: (count, window start). Complements the
    /// per-account lock-out, which cannot stop one address trying *many* accounts.
    ip_failures: Mutex<HashMap<std::net::IpAddr, (u32, i64)>>,
    /// Where passkeys are valid (`None` = passkeys are off on this setup) and the challenges in flight.
    pub passkey_cfg: Mutex<Option<crate::passkey::Config>>,
    pub ceremonies: Mutex<crate::passkey::Ceremonies>,
    /// Passwords that were right and now wait for a code: ticket hash -> who, until when, wrong codes so far.
    mfa_tickets: Mutex<HashMap<String, MfaTicket>>,
    /// The policy "who must use a second step" (`off`, `admins`, `all`) and when it was read.
    mfa_policy: Mutex<Option<(String, i64)>>,
}

struct MfaTicket {
    user_id: i64,
    /// The account's lock-out key, so wrong codes count against the account.
    key: String,
    expires: i64,
    fails: u32,
}

/// How long a right password waits for its code, and how many wrong codes end the wait.
const MFA_TICKET_SECS: i64 = 300;
const MFA_TICKET_MAX_FAILS: u32 = 5;
/// The setting that holds who must use a second step.
pub const SECURITY_KEY: &str = "security";
pub const MFA_POLICIES: &[&str] = &["off", "admins", "all"];

/// Failed sign-ins one address may make per window before it is refused outright.
const IP_MAX_FAILURES: u32 = 20;
const IP_WINDOW_SECS: i64 = 600;

pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| anyhow!("no secure randomness available: {e}"))?;
    Ok(b)
}

/// 256 bits of randomness as 64 hex characters.
pub fn random_token() -> Result<String> {
    Ok(random_bytes::<32>()?.iter().map(|b| format!("{b:02x}")).collect())
}

/// A readable random password (no look-alike characters), uniformly sampled.
pub fn random_password() -> Result<String> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let limit = 256 - (256 % ALPHABET.len()); // rejection sampling: no modulo bias
    let mut out = String::new();
    while out.len() < 20 {
        for b in random_bytes::<32>()? {
            if (b as usize) < limit && out.len() < 20 {
                out.push(ALPHABET[b as usize % ALPHABET.len()] as char);
            }
        }
    }
    Ok(out)
}

pub fn hash_password(pw: &str) -> Result<String> {
    Ok(Argon2::default()
        .hash_password(pw.as_bytes())
        .map_err(|e| anyhow!("hashing failed: {e}"))?
        .to_string())
}

pub fn verify_password(hash: &str, pw: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// Verified against when the user does not exist, so both paths cost the same.
fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| hash_password("dummy-password-for-timing").expect("hashing works"))
}

const COMMON: &[&str] = &["password", "passw0rd", "123456789012", "qwertyuiop12", "administrator", "changeme123", "letmein12345"];

pub fn validate_password(pw: &str, username: &str) -> Result<(), String> {
    let n = pw.chars().count();
    if n < MIN_PASSWORD_LEN {
        return Err(format!("password must be at least {MIN_PASSWORD_LEN} characters"));
    }
    if n > 128 {
        return Err("password must be at most 128 characters".into());
    }
    let lower = pw.to_lowercase();
    if lower.contains(&username.to_lowercase()) && !username.is_empty() {
        return Err("password must not contain the username".into());
    }
    if pw.chars().all(|c| c == pw.chars().next().unwrap()) || COMMON.iter().any(|c| lower.contains(c)) {
        return Err("password is too easy to guess".into());
    }
    Ok(())
}

pub fn validate_username(u: &str) -> Result<(), String> {
    let ok = (3..=64).contains(&u.len())
        && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
        && u.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    ok.then_some(()).ok_or_else(|| "username must be 3-64 characters of letters, digits and . _ - @".to_string())
}

impl Auth {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Auth { store, attempts: Mutex::new(HashMap::new()), last_agent_touch: Mutex::new(HashMap::new()), ip_failures: Mutex::new(HashMap::new()), passkey_cfg: Mutex::new(None), ceremonies: Mutex::new(Default::default()), mfa_tickets: Mutex::new(HashMap::new()), mfa_policy: Mutex::new(None) }
    }

    /// First run: create `admin` with a random one-time password. Returns it
    /// (once) if a user was created.
    pub fn bootstrap(&self, now: i64) -> Result<Option<String>> {
        if !self.store.list_users()?.is_empty() {
            return Ok(None);
        }
        let pw = random_password()?;
        self.store.create_user("admin", &hash_password(&pw)?, "admin", true, now)?;
        Ok(Some(pw))
    }

    // ----------------------------------------------------------- login

    /// Seconds this address must wait before it may try to sign in again (0 = free to try).
    pub fn ip_wait(&self, ip: std::net::IpAddr, now: i64) -> i64 {
        self.ip_failures
            .lock()
            .unwrap()
            .get(&ip)
            .filter(|(n, start)| *n >= IP_MAX_FAILURES && now - start < IP_WINDOW_SECS)
            .map_or(0, |(_, start)| IP_WINDOW_SECS - (now - start))
    }

    /// Count a failed sign-in against the address (memory is bounded).
    pub fn ip_failure(&self, ip: std::net::IpAddr, now: i64) {
        let mut m = self.ip_failures.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, (_, start)| now - *start < IP_WINDOW_SECS);
        }
        let e = m.entry(ip).or_insert((0, now));
        if now - e.1 >= IP_WINDOW_SECS {
            *e = (0, now);
        }
        e.0 += 1;
    }

    fn lock_remaining(&self, key: &str, now: i64) -> i64 {
        self.attempts.lock().unwrap().get(key).map_or(0, |a| (a.locked_until - now).max(0))
    }

    fn record_failure(&self, key: &str, now: i64) {
        let mut m = self.attempts.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, a| a.locked_until > now);
        }
        let a = m.entry(key.to_string()).or_default();
        a.fails += 1;
        if a.fails >= 5 {
            // 30 s, then doubling every further 5 failures, capped at 15 min
            let step = ((a.fails - 5) / 5).min(5);
            a.locked_until = now + (30i64 << step).min(900);
        }
    }

    /// Open a session for a user who has already proven who they are (a verified passkey).
    /// Refused for disabled accounts and for accounts that still owe a password change.
    pub fn start_session_for(&self, user_id: i64, now: i64) -> Result<(String, User), AuthError> {
        let rec = self.store.get_user_record(user_id)?.ok_or(AuthError::Invalid)?;
        if rec.user.disabled {
            return Err(AuthError::Invalid);
        }
        if rec.user.must_change {
            return Err(AuthError::Rejected("change your password first, then use a passkey".into()));
        }
        let token = random_token()?;
        self.store.create_session(&sha256_hex(&token), rec.user.id, now, now + SESSION_MAX_SECS)?;
        self.store.set_last_login(rec.user.id, now)?;
        let mut user = rec.user;
        user.last_login = Some(now);
        Ok((token, user))
    }

    /// Returns the raw session token (to be set as a cookie) and the user.
    pub fn login(&self, username: &str, password: &str, now: i64) -> Result<(String, User), AuthError> {
        let key = username.trim().to_lowercase();
        let wait = self.lock_remaining(&key, now);
        if wait > 0 {
            return Err(AuthError::Locked(wait));
        }
        let rec = self.store.find_user(username.trim())?;
        // Always pay for one Argon2 verification.
        let ok = match &rec {
            Some(r) => verify_password(&r.password_hash, password),
            None => {
                verify_password(dummy_hash(), password);
                false
            }
        };
        let Some(r) = rec.filter(|r| ok && !r.user.disabled) else {
            self.record_failure(&key, now);
            return Err(AuthError::Invalid);
        };
        if self.store.get_totp(r.user.id)?.is_some_and(|t| t.enabled) {
            // the failure counter stays as it is: a right password must not wipe out the wrong codes tried so far
            return Err(AuthError::MfaRequired(self.new_ticket(r.user.id, &key, now)?));
        }
        self.attempts.lock().unwrap().remove(&key);
        self.open_session(r.user, now)
    }

    fn open_session(&self, mut user: User, now: i64) -> Result<(String, User), AuthError> {
        let token = random_token()?;
        self.store.create_session(&sha256_hex(&token), user.id, now, now + SESSION_MAX_SECS)?;
        self.store.set_last_login(user.id, now)?;
        user.last_login = Some(now);
        Ok((token, user))
    }

    fn new_ticket(&self, user_id: i64, key: &str, now: i64) -> Result<String, AuthError> {
        let ticket = random_token()?;
        let mut m = self.mfa_tickets.lock().unwrap();
        m.retain(|_, t| t.expires > now);
        if m.len() >= 1000 {
            // a flood of right passwords cannot grow this without bound: the oldest go first
            let oldest = m.iter().min_by_key(|(_, t)| t.expires).map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                m.remove(&k);
            }
        }
        m.insert(sha256_hex(&ticket), MfaTicket { user_id, key: key.to_string(), expires: now + MFA_TICKET_SECS, fails: 0 });
        Ok(ticket)
    }

    /// The second step: a 6-digit code from the app, or a recovery code. Returns the session token, the user and
    /// which kind of code was used (`totp` or `recovery`). Every wrong code counts against the account (the same
    /// lock-out as wrong passwords) and against the ticket, which is void after a few.
    pub fn complete_mfa(&self, ticket: &str, typed: &str, now: i64) -> Result<(String, User, &'static str), AuthError> {
        let th = sha256_hex(ticket);
        let (user_id, key) = {
            let mut m = self.mfa_tickets.lock().unwrap();
            match m.get(&th) {
                Some(t) if t.expires > now => (t.user_id, t.key.clone()),
                Some(_) => {
                    m.remove(&th);
                    return Err(AuthError::Invalid);
                }
                None => return Err(AuthError::Invalid),
            }
        };
        let wait = self.lock_remaining(&key, now);
        if wait > 0 {
            return Err(AuthError::Locked(wait));
        }
        let rec = self.store.get_user_record(user_id)?.filter(|r| !r.user.disabled).ok_or(AuthError::Invalid)?;
        let totp = self.store.get_totp(user_id)?.filter(|t| t.enabled).ok_or(AuthError::Invalid)?;
        let method = if crate::totp::looks_like_recovery(typed) { "recovery" } else { "totp" };
        let ok = if method == "recovery" {
            self.store.use_recovery_code(user_id, &crate::totp::hash_recovery(typed), now)?
        } else {
            match crate::totp::verify(&totp.secret, typed, now, totp.last_step) {
                Some(step) => self.store.advance_totp_step(user_id, step)?,
                None => false,
            }
        };
        if !ok {
            self.record_failure(&key, now);
            let mut m = self.mfa_tickets.lock().unwrap();
            if let Some(t) = m.get_mut(&th) {
                t.fails += 1;
                if t.fails >= MFA_TICKET_MAX_FAILS {
                    m.remove(&th);
                }
            }
            return Err(AuthError::Invalid);
        }
        self.mfa_tickets.lock().unwrap().remove(&th);
        self.attempts.lock().unwrap().remove(&key);
        let (token, user) = self.open_session(rec.user, now)?;
        Ok((token, user, method))
    }

    /// The current password, asked again before something sensitive (starting or stopping the second step). Wrong
    /// answers count against the account exactly like wrong sign-ins, so this cannot be used to guess the password.
    pub fn confirm_password(&self, user: &User, password: &str, now: i64) -> Result<(), AuthError> {
        let key = user.username.trim().to_lowercase();
        let wait = self.lock_remaining(&key, now);
        if wait > 0 {
            return Err(AuthError::Locked(wait));
        }
        let rec = self.store.get_user_record(user.id)?.ok_or(AuthError::Invalid)?;
        if verify_password(&rec.password_hash, password) {
            Ok(())
        } else {
            self.record_failure(&key, now);
            Err(AuthError::Invalid)
        }
    }

    /// A wrong code typed while setting up or renewing: the same back-off as wrong passwords.
    pub fn code_check(&self, user: &User, now: i64) -> Result<(), AuthError> {
        let wait = self.lock_remaining(&user.username.trim().to_lowercase(), now);
        if wait > 0 { Err(AuthError::Locked(wait)) } else { Ok(()) }
    }

    pub fn code_failed(&self, user: &User, now: i64) {
        self.record_failure(&user.username.trim().to_lowercase(), now);
    }

    // ------------------------------------------------------ who must use a second step

    /// `off`, `admins` or `all`. Read from the database at most every few seconds.
    pub fn mfa_policy(&self, now: i64) -> String {
        let mut c = self.mfa_policy.lock().unwrap();
        if let Some((p, at)) = c.as_ref() {
            if now - at < 10 {
                return p.clone();
            }
        }
        let p = self
            .store
            .get_setting(SECURITY_KEY)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["mfa_required"].as_str().map(String::from))
            .filter(|p| MFA_POLICIES.contains(&p.as_str()))
            .unwrap_or_else(|| "off".into());
        *c = Some((p.clone(), now));
        p
    }

    pub fn set_mfa_policy(&self, policy: &str, now: i64) -> Result<(), AuthError> {
        if !MFA_POLICIES.contains(&policy) {
            return Err(AuthError::Rejected("the policy must be off, admins or all".into()));
        }
        self.store.set_setting(SECURITY_KEY, &serde_json::to_vec(&serde_json::json!({ "mfa_required": policy }))?, now)?;
        *self.mfa_policy.lock().unwrap() = Some((policy.to_string(), now));
        Ok(())
    }

    /// Has this person a second factor: a working authenticator app or at least one passkey?
    pub fn has_mfa(&self, user_id: i64) -> Result<bool> {
        Ok(self.store.get_totp(user_id)?.is_some_and(|t| t.enabled) || !self.store.list_passkeys(user_id)?.is_empty())
    }

    /// Must this person set up a second step before anything else works? (Never on a database error: that must not lock everybody out.)
    pub fn must_enrol(&self, user: &User, now: i64) -> bool {
        let required = match self.mfa_policy(now).as_str() {
            "all" => true,
            "admins" => user.role == "admin",
            _ => false,
        };
        required && self.has_mfa(user.id).is_ok_and(|has| !has)
    }

    /// The user behind a session cookie, if it is valid, unexpired, not idle
    /// too long, and the account is still enabled.
    pub fn session_user(&self, token: &str, now: i64) -> Option<User> {
        if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let hash = sha256_hex(token);
        let s = self.store.get_session(&hash).ok()??;
        if s.user.disabled || now >= s.expires_at || now - s.last_used > SESSION_IDLE_SECS {
            let _ = self.store.delete_session(&hash);
            return None;
        }
        if now - s.last_used >= 60 {
            let _ = self.store.touch_session(&hash, now);
        }
        Some(s.user)
    }

    pub fn logout(&self, token: &str) {
        let _ = self.store.delete_session(&sha256_hex(token));
    }

    // -------------------------------------------------------- passwords

    /// Change one's own password. Signs the user out everywhere but here.
    pub fn change_password(&self, user_id: i64, current: &str, new: &str, keep_token: Option<&str>) -> Result<(), AuthError> {
        let rec = self.store.get_user_record(user_id)?.ok_or(AuthError::Invalid)?;
        if !verify_password(&rec.password_hash, current) {
            return Err(AuthError::Invalid);
        }
        validate_password(new, &rec.user.username).map_err(AuthError::Rejected)?;
        if new == current {
            return Err(AuthError::Rejected("the new password must differ from the current one".into()));
        }
        self.store.update_user(user_id, None, None, Some(&hash_password(new)?), Some(false))?;
        self.store.delete_user_sessions(user_id, keep_token.map(sha256_hex).as_deref())?;
        Ok(())
    }

    /// Admin action: set a fresh random password the user must change at next login.
    pub fn reset_password(&self, user_id: i64) -> Result<String, AuthError> {
        let pw = random_password()?;
        if !self.store.update_user(user_id, None, None, Some(&hash_password(&pw)?), Some(true))? {
            return Err(AuthError::Rejected("no such user".into()));
        }
        self.store.delete_user_sessions(user_id, None)?;
        Ok(pw)
    }

    // ------------------------------------------------------------ users

    /// Returns the new user and their one-time password.
    pub fn create_user(&self, username: &str, role: &str, now: i64) -> Result<(User, String), AuthError> {
        validate_username(username).map_err(AuthError::Rejected)?;
        if !ROLES.contains(&role) {
            return Err(AuthError::Rejected(format!("role must be one of {}", ROLES.join(", "))));
        }
        if self.store.find_user(username)?.is_some() {
            return Err(AuthError::Rejected("that username is taken".into()));
        }
        let pw = random_password()?;
        Ok((self.store.create_user(username, &hash_password(&pw)?, role, true, now)?, pw))
    }

    fn enabled_admins(&self) -> Result<usize> {
        Ok(self.store.list_users()?.iter().filter(|u| u.role == "admin" && !u.disabled).count())
    }

    /// Change role and/or enabled state, refusing to remove the last admin.
    pub fn update_user(&self, id: i64, role: Option<&str>, disabled: Option<bool>) -> Result<(), AuthError> {
        let cur = self.store.get_user_record(id)?.ok_or_else(|| AuthError::Rejected("no such user".into()))?.user;
        if let Some(r) = role {
            if !ROLES.contains(&r) {
                return Err(AuthError::Rejected(format!("role must be one of {}", ROLES.join(", "))));
            }
        }
        let loses_admin = cur.role == "admin" && !cur.disabled && (role.is_some_and(|r| r != "admin") || disabled == Some(true));
        if loses_admin && self.enabled_admins()? <= 1 {
            return Err(AuthError::Rejected("this is the last enabled administrator".into()));
        }
        self.store.update_user(id, role, disabled, None, None)?;
        if disabled == Some(true) || role.is_some() {
            self.store.delete_user_sessions(id, None)?; // permissions changed: sign in again
        }
        Ok(())
    }

    /// Permanently remove a user — only once they are already disabled (an active account is
    /// disabled first, as a reversible step; deleting is not). Their audit log entries keep their
    /// username as plain text and are unaffected.
    pub fn delete_user(&self, id: i64) -> Result<(), AuthError> {
        let cur = self.store.get_user_record(id)?.ok_or_else(|| AuthError::Rejected("no such user".into()))?.user;
        if !cur.disabled {
            return Err(AuthError::Rejected("disable this user first, then delete them".into()));
        }
        if !self.store.delete_user(id)? {
            return Err(AuthError::Rejected("no such user".into()));
        }
        Ok(())
    }

    // ----------------------------------------------------- agent tokens

    /// Issue (or rotate) the token for `agent_id`. Shown once.
    pub fn issue_agent_token(&self, agent_id: &str, label: &str, now: i64) -> Result<String, AuthError> {
        let ok = !agent_id.is_empty() && agent_id.len() <= 64 && agent_id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !ok {
            return Err(AuthError::Rejected("agent id must be 1-64 characters of [A-Za-z0-9._-]".into()));
        }
        let token = format!("dat_{}", random_token()?);
        self.store.set_agent_token(agent_id, &sha256_hex(&token), label, now)?;
        Ok(token)
    }

    /// Create an API token for scripts and integrations. Never `admin`: a leaked
    /// token must not be able to manage users, tokens or the audit log. The value
    /// is returned once; only its hash is stored.
    pub fn issue_api_token(&self, label: &str, role: &str, by: &str, now: i64) -> Result<(i64, String), AuthError> {
        if !matches!(role, "viewer" | "editor") {
            return Err(AuthError::Rejected("an API token's role must be viewer or editor".into()));
        }
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 60 || label.chars().any(char::is_control) {
            return Err(AuthError::Rejected("give the token a label of 1-60 characters (what it is used for)".into()));
        }
        let token = format!("dnt_{}", random_token()?);
        let id = self.store.create_api_token(&sha256_hex(&token), label, role, by, now)?;
        Ok((id, token))
    }

    /// The API token a bearer value belongs to, if valid and not revoked.
    pub fn verify_api_token(&self, token: &str, now: i64) -> Option<crate::store::ApiToken> {
        if !token.starts_with("dnt_") || token.len() != 68 {
            return None;
        }
        let hash = sha256_hex(token);
        let t = self.store.find_api_token(&hash).ok()??;
        if t.revoked {
            return None;
        }
        let mut touched = self.last_agent_touch.lock().unwrap();
        if now - touched.get(&hash).copied().unwrap_or(0) >= 60 {
            touched.insert(hash.clone(), now);
            let _ = self.store.touch_api_token(&hash, now);
        }
        Some(t)
    }

    /// The agent a token belongs to, if the token is valid and not revoked.
    pub fn verify_agent_token(&self, token: &str, now: i64) -> Option<AgentToken> {
        if !token.starts_with("dat_") || token.len() != 68 {
            return None;
        }
        let hash = sha256_hex(token);
        let t = self.store.find_agent_token(&hash).ok()??;
        if t.revoked {
            return None;
        }
        let mut touched = self.last_agent_touch.lock().unwrap();
        if now - touched.get(&hash).copied().unwrap_or(0) >= 60 {
            touched.insert(hash.clone(), now);
            let _ = self.store.touch_agent_token(&hash, now);
        }
        Some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    fn auth() -> Auth {
        Auth::new(Arc::new(SqliteStore::open_in_memory().unwrap()))
    }

    fn admin_with(a: &Auth, pw: &str) -> User {
        a.store.create_user("admin", &hash_password(pw).unwrap(), "admin", false, 0).unwrap()
    }

    #[test]
    fn hashes_verify_and_are_salted() {
        let h1 = hash_password("correct horse battery").unwrap();
        let h2 = hash_password("correct horse battery").unwrap();
        assert_ne!(h1, h2);
        assert!(h1.starts_with("$argon2id$"));
        assert!(verify_password(&h1, "correct horse battery"));
        assert!(!verify_password(&h1, "correct horse batterY"));
        assert!(!verify_password("not-a-hash", "x"));
    }

    #[test]
    fn random_values_have_the_right_shape() {
        let t = random_token().unwrap();
        assert_eq!(t.len(), 64);
        assert_ne!(t, random_token().unwrap());
        let p = random_password().unwrap();
        assert_eq!(p.len(), 20);
        assert!(!p.contains(['l', 'I', 'O', '0', '1']));
        assert!(validate_password(&p, "admin").is_ok());
    }

    #[test]
    fn first_start_creates_one_admin_with_a_forced_password_change() {
        let a = auth();
        let pw = a.bootstrap(100).unwrap().expect("created");
        assert!(a.bootstrap(101).unwrap().is_none(), "only when there are no users");
        let (_, u) = a.login("admin", &pw, 200).unwrap();
        assert!((u.role.as_str(), u.must_change) == ("admin", true));
        assert_eq!(a.store.list_users().unwrap().len(), 1);
        // the stored hash is not the password
        assert!(!a.store.find_user("admin").unwrap().unwrap().password_hash.contains(&pw));
    }

    #[test]
    fn login_sessions_and_logout() {
        let a = auth();
        admin_with(&a, "a-long-passphrase-1");
        assert!(matches!(a.login("admin", "wrong", 10), Err(AuthError::Invalid)));
        assert!(matches!(a.login("nobody", "a-long-passphrase-1", 10), Err(AuthError::Invalid)), "same error for unknown users");
        let (tok, user) = a.login(" Admin ", "a-long-passphrase-1", 100).unwrap(); // case-insensitive, trimmed
        assert_eq!(user.username, "admin");
        assert_eq!(a.session_user(&tok, 200).unwrap().id, user.id);
        // the raw token is not what is stored
        assert!(a.store.get_session(&tok).unwrap().is_none());
        assert!(a.store.get_session(&sha256_hex(&tok)).unwrap().is_some());
        a.logout(&tok);
        assert!(a.session_user(&tok, 201).is_none());
        // malformed tokens never touch the database
        assert!(a.session_user("short", 1).is_none());
        assert!(a.session_user(&"z".repeat(64), 1).is_none());
    }

    #[test]
    fn sessions_expire_when_idle_and_absolutely() {
        let a = auth();
        admin_with(&a, "a-long-passphrase-1");
        let (tok, _) = a.login("admin", "a-long-passphrase-1", 0).unwrap();
        assert!(a.session_user(&tok, SESSION_IDLE_SECS - 1).is_some());
        // activity keeps it alive, up to the absolute limit
        let mut t = 0;
        while t + 3600 < SESSION_MAX_SECS {
            t += 3600;
            assert!(a.session_user(&tok, t).is_some(), "t={t}");
        }
        assert!(a.session_user(&tok, SESSION_MAX_SECS).is_none());
        // idle expiry
        let (tok2, _) = a.login("admin", "a-long-passphrase-1", 1_000_000).unwrap();
        assert!(a.session_user(&tok2, 1_000_000 + SESSION_IDLE_SECS + 1).is_none());
        assert!(a.session_user(&tok2, 1_000_000 + 10).is_none(), "an expired session is deleted, not resurrected");
    }

    #[test]
    fn repeated_failures_lock_the_account_with_backoff_and_success_resets() {
        let a = auth();
        admin_with(&a, "a-long-passphrase-1");
        for _ in 0..5 {
            assert!(matches!(a.login("admin", "bad", 1000), Err(AuthError::Invalid)));
        }
        // now locked: even the right password is refused, with a retry time
        match a.login("admin", "a-long-passphrase-1", 1001) {
            Err(AuthError::Locked(s)) => assert_eq!(s, 29),
            other => panic!("{other:?}"),
        }
        assert!(a.login("admin", "a-long-passphrase-1", 1031).is_ok(), "lock expires");
        // success cleared the counter: four more failures don't lock
        for _ in 0..4 {
            let _ = a.login("admin", "bad", 2000);
        }
        assert!(a.login("admin", "a-long-passphrase-1", 2000).is_ok());
        // back-off grows: failures 5..9 -> 30 s, 10..14 -> 60 s
        for _ in 0..10 {
            let _ = a.login("admin", "bad", 5000);
            // wait out any lock so every attempt counts
            let _ = a.attempts.lock().unwrap().get_mut("admin").map(|x| x.locked_until = 0);
        }
        let _ = a.login("admin", "bad", 6000);
        match a.login("admin", "x", 6001) {
            Err(AuthError::Locked(s)) => assert!(s > 30, "{s}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn disabled_users_cannot_log_in_and_lose_sessions() {
        let a = auth();
        let admin = admin_with(&a, "a-long-passphrase-1");
        let (u, pw) = a.create_user("jana", "viewer", 5).unwrap();
        let (tok, _) = a.login("jana", &pw, 10).unwrap();
        a.update_user(u.id, None, Some(true)).unwrap();
        assert!(a.session_user(&tok, 11).is_none());
        assert!(matches!(a.login("jana", &pw, 12), Err(AuthError::Invalid)), "indistinguishable from a wrong password");
        a.update_user(u.id, None, Some(false)).unwrap();
        assert!(a.login("jana", &pw, 13).is_ok());
        let _ = admin;
    }

    #[test]
    fn the_last_admin_is_protected() {
        let a = auth();
        let admin = admin_with(&a, "a-long-passphrase-1");
        for (role, disabled) in [(Some("viewer"), None), (None, Some(true))] {
            assert!(matches!(a.update_user(admin.id, role, disabled), Err(AuthError::Rejected(_))));
        }
        // with a second admin the first may step down
        let (second, _) = a.create_user("second", "admin", 1).unwrap();
        a.update_user(admin.id, Some("viewer"), None).unwrap();
        assert!(matches!(a.update_user(second.id, Some("editor"), None), Err(AuthError::Rejected(_))));
        assert!(matches!(a.update_user(999, None, None), Err(AuthError::Rejected(_))));
        assert!(matches!(a.update_user(second.id, Some("root"), None), Err(AuthError::Rejected(_))));
    }

    #[test]
    fn changing_a_password_checks_policy_and_signs_out_other_sessions() {
        let a = auth();
        let admin = admin_with(&a, "a-long-passphrase-1");
        let (keep, _) = a.login("admin", "a-long-passphrase-1", 10).unwrap();
        let (other, _) = a.login("admin", "a-long-passphrase-1", 11).unwrap();
        assert!(matches!(a.change_password(admin.id, "wrong", "another-long-pass-2", Some(&keep)), Err(AuthError::Invalid)));
        for weak in ["short", "aaaaaaaaaaaaaaaa", "myPassword123456", "admin-admin-admin-1", "a-long-passphrase-1"] {
            assert!(matches!(a.change_password(admin.id, "a-long-passphrase-1", weak, Some(&keep)), Err(AuthError::Rejected(_))), "{weak}");
        }
        a.change_password(admin.id, "a-long-passphrase-1", "another-long-pass-2", Some(&keep)).unwrap();
        assert!(a.session_user(&keep, 20).is_some());
        assert!(a.session_user(&other, 20).is_none(), "other sessions are revoked");
        assert!(a.login("admin", "a-long-passphrase-1", 30).is_err());
        assert!(a.login("admin", "another-long-pass-2", 31).is_ok());
    }

    #[test]
    fn admin_reset_forces_a_change_and_kills_sessions() {
        let a = auth();
        admin_with(&a, "a-long-passphrase-1");
        let (u, pw) = a.create_user("jana", "editor", 1).unwrap();
        let (tok, _) = a.login("jana", &pw, 2).unwrap();
        let new = a.reset_password(u.id).unwrap();
        assert!(a.session_user(&tok, 3).is_none());
        assert!(a.login("jana", &pw, 4).is_err());
        let (_, user) = a.login("jana", &new, 5).unwrap();
        assert!(user.must_change);
        assert!(matches!(a.reset_password(999), Err(AuthError::Rejected(_))));
    }

    #[test]
    fn usernames_and_roles_are_validated() {
        let a = auth();
        for bad in ["", "ab", "-lead", "has space", "semi;colon", "quote'", "<script>", &"x".repeat(65)] {
            assert!(matches!(a.create_user(bad, "viewer", 0), Err(AuthError::Rejected(_))), "{bad:?}");
        }
        assert!(matches!(a.create_user("valid.name", "superuser", 0), Err(AuthError::Rejected(_))));
        a.create_user("valid.name", "viewer", 0).unwrap();
        assert!(matches!(a.create_user("VALID.NAME", "viewer", 0), Err(AuthError::Rejected(_))), "usernames are case-insensitive");
    }

    #[test]
    fn agent_tokens_bind_to_an_agent_rotate_and_revoke() {
        let a = auth();
        let t1 = a.issue_agent_token("branch-1", "Branch office", 10).unwrap();
        assert!(t1.starts_with("dat_") && t1.len() == 68);
        let v = a.verify_agent_token(&t1, 20).unwrap();
        assert_eq!(v.agent_id, "branch-1");
        assert!(a.verify_agent_token("dat_wrong", 20).is_none());
        assert!(a.verify_agent_token(&format!("dat_{}", "0".repeat(64)), 20).is_none());
        // the stored value is a hash
        assert!(a.store.find_agent_token(&t1).unwrap().is_none());
        // rotating invalidates the old token
        let t2 = a.issue_agent_token("branch-1", "Branch office", 30).unwrap();
        assert!(a.verify_agent_token(&t1, 31).is_none());
        assert!(a.verify_agent_token(&t2, 31).is_some());
        assert!(a.store.revoke_agent_token("branch-1").unwrap());
        assert!(a.verify_agent_token(&t2, 32).is_none());
        assert!(matches!(a.issue_agent_token("../etc", "x", 0), Err(AuthError::Rejected(_))));
    }
}
