//! Notification channels: getting alerts out of the console and in front of an
//! administrator, in the tools they already watch.
//!
//! Supported: **Slack**, **Microsoft Teams** (a Workflows "webhook request"
//! trigger; Adaptive Card), **Discord**, **PagerDuty** (Events API v2), **Pushover**,
//! **ntfy** (ntfy.sh or your own server), **e-mail**
//! (SMTP), **Jira** and **ServiceNow** (a real issue/incident per alert, via each one's REST
//! API) and a **generic signed webhook** (JSON, HMAC-SHA256 signature) for anything else
//! (Mattermost, Zapier, your own code).
//!
//! # How delivery works
//!
//! Channels are configured in the console and stored in the database. A background
//! dispatcher reads new events after a *per-channel cursor* (like the exporters),
//! keeps those at or above the channel's minimum score, and sends them one at a
//! time. So:
//!
//! * a channel that is down delays only itself, and catches up when it returns;
//! * a **storm** does not become a flood: when more than [`DIGEST_ABOVE`] alerts are
//!   waiting for a channel they go out as one digest message;
//! * **maintenance mode** (all channels) and a device's *mute until* date silence
//!   outgoing notifications without hiding anything in the console;
//! * events older than 24 h are not sent (a channel that was broken for a day does
//!   not wake anybody with yesterday's news).
//!
//! # Trust
//!
//! Webhook URLs, routing keys, SMTP passwords and signing secrets are **secrets**:
//! they are never returned by the API (only "set"), never logged, and scrubbed from
//! error messages. Text from the network (device names!) ends up in messages, so it
//! is escaped for each target: Slack's `<`, `>`, `&`; Discord's mentions are disabled
//! outright so a hostile hostname cannot ping `@everyone`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::model::{Asset, AssetMeta, Event};
use crate::store::{Store};

pub const KEY: &str = "channels";
pub const MAINTENANCE_KEY: &str = "maintenance";
pub const KINDS: &[&str] = &["slack", "teams", "discord", "pagerduty", "pushover", "ntfy", "email", "webhook", "jira", "servicenow"];
/// More waiting alerts than this for one channel are sent as a single digest.
pub const DIGEST_ABOVE: usize = 5;
/// Alerts older than this are not sent.
const MAX_AGE_SECS: i64 = 24 * 3600;
const MAX_CHANNELS: usize = 20;
const PAGERDUTY_URL: &str = "https://events.pagerduty.com/v2/enqueue";
const PUSHOVER_URL: &str = "https://api.pushover.net/1/messages.json";

// ------------------------------------------------------------------ config

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Smtp {
    pub host: String,
    pub port: u16,
    /// `starttls` (usually port 587), `tls` (port 465) or `none` (only for a local relay).
    pub security: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    /// Only alerts scoring at least this much are sent.
    pub min_score: i32,
    /// Webhook URL (slack, teams, discord, webhook); optional endpoint override for pagerduty.
    #[serde(default)]
    pub url: Option<String>,
    /// PagerDuty routing (integration) key, the webhook's signing secret, Pushover's application token, or ntfy's access token.
    #[serde(default)]
    pub secret: Option<String>,
    /// Pushover: the user (or group) key the message goes to; Jira: the account e-mail (Basic
    /// auth is `email:api_token` for Jira Cloud).
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub smtp: Option<Smtp>,
    /// Jira: the project key an issue is filed under (e.g. `OPS`).
    #[serde(default)]
    pub project: Option<String>,
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// `(scheme, host)` of a URL, or an error naming the problem. No credentials in URLs.
fn split_url(url: &str) -> Result<(&str, &str), String> {
    let (scheme, rest) = url.split_once("://").ok_or("the URL must start with https://")?;
    if !matches!(scheme, "http" | "https") {
        return Err("the URL must start with https://".into());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || url.chars().any(|c| c.is_whitespace() || c.is_control()) || url.len() > 1024 {
        return Err("that does not look like a valid webhook URL".into());
    }
    let host = authority.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(authority, |(h, _)| h);
    Ok((scheme, host))
}

fn short(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

impl Channel {
    /// Check a channel is complete and sane. Called on every create and update.
    pub fn validate(&self) -> Result<(), String> {
        if !KINDS.contains(&self.kind.as_str()) {
            return Err(format!("kind must be one of {}", KINDS.join(", ")));
        }
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
            return Err("give the channel a name of 1-60 characters".into());
        }
        if !(0..=100).contains(&self.min_score) {
            return Err("the minimum score must be between 0 and 100".into());
        }
        match self.kind.as_str() {
            "slack" | "teams" | "discord" | "webhook" => {
                let url = self.url.as_deref().ok_or("a webhook URL is required")?;
                let (scheme, host) = split_url(url)?;
                // Real chat services are https. Plain http is for a generic webhook to your own
                // systems, or a local test; it is refused for the public services.
                if scheme == "http" && !is_loopback_host(host) && self.kind != "webhook" {
                    return Err("Slack, Teams and Discord webhooks must use https://".into());
                }
                if self.kind == "webhook" && self.secret.as_deref().is_some_and(|s| s.len() < 16 || s.len() > 200) {
                    return Err("the signing secret must be 16-200 characters".into());
                }
            }
            "pagerduty" => {
                let key = self.secret.as_deref().ok_or("the PagerDuty integration (routing) key is required")?;
                if key.len() < 8 || key.len() > 64 || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err("that does not look like a PagerDuty integration key (letters and digits)".into());
                }
                if let Some(u) = &self.url {
                    let (scheme, host) = split_url(u)?;
                    if scheme == "http" && !is_loopback_host(host) {
                        return Err("the PagerDuty endpoint must use https://".into());
                    }
                }
            }
            "pushover" => {
                let key_ok = |k: &str| (20..=40).contains(&k.len()) && k.chars().all(|c| c.is_ascii_alphanumeric());
                if !self.secret.as_deref().is_some_and(key_ok) {
                    return Err("give the Pushover application token (30 letters and digits, from pushover.net/apps)".into());
                }
                if !self.user.as_deref().is_some_and(key_ok) {
                    return Err("give the Pushover user or group key (30 letters and digits, shown on your Pushover dashboard)".into());
                }
                if let Some(u) = &self.url {
                    let (scheme, host) = split_url(u)?;
                    if scheme == "http" && !is_loopback_host(host) {
                        return Err("the Pushover endpoint must use https://".into());
                    }
                }
            }
            "ntfy" => {
                let url = self.url.as_deref().ok_or("the ntfy topic address is required, like https://ntfy.sh/your-topic")?;
                let (scheme, host) = split_url(url)?;
                ntfy_target(url)?;
                // an access token must not cross the network in clear; without one, a private server on http is the owner's call
                if scheme == "http" && !is_loopback_host(host) && self.secret.is_some() {
                    return Err("an access token would cross the network unencrypted: use https://".into());
                }
                if self.secret.as_deref().is_some_and(|t| t.len() > 200 || t.chars().any(|c| c.is_whitespace() || c.is_control())) {
                    return Err("that does not look like an ntfy access token".into());
                }
            }
            "email" => {
                let s = self.smtp.as_ref().ok_or("SMTP settings are required")?;
                if s.host.is_empty() || s.host.len() > 253 || s.host.chars().any(|c| c.is_whitespace() || c.is_control() || c == '/') {
                    return Err("the SMTP host is not valid".into());
                }
                if s.port == 0 {
                    return Err("the SMTP port is not valid".into());
                }
                if !matches!(s.security.as_str(), "starttls" | "tls" | "none") {
                    return Err("security must be starttls, tls or none".into());
                }
                if s.security == "none" && s.username.is_some() && !is_loopback_host(&s.host) {
                    return Err("a password would cross the network unencrypted: use starttls or tls".into());
                }
                if s.from.parse::<lettre::message::Mailbox>().is_err() {
                    return Err("the From address is not valid".into());
                }
                if s.to.is_empty() || s.to.len() > 20 || s.to.iter().any(|a| a.parse::<lettre::message::Mailbox>().is_err()) {
                    return Err("give 1-20 valid recipient addresses".into());
                }
            }
            "jira" => {
                let url = self.url.as_deref().ok_or("the Jira site URL is required, like https://yourorg.atlassian.net")?;
                let (scheme, host) = split_url(url)?;
                if scheme == "http" && !is_loopback_host(host) {
                    return Err("the Jira site URL must use https://".into());
                }
                let email = self.user.as_deref().ok_or("the Jira account e-mail is required")?;
                if email.parse::<lettre::message::Mailbox>().is_err() {
                    return Err("that does not look like a valid Jira account e-mail".into());
                }
                let token = self.secret.as_deref().ok_or("the Jira API token is required (id.atlassian.com/manage-profile/security/api-tokens)")?;
                if token.len() < 10 || token.len() > 300 || token.chars().any(char::is_whitespace) {
                    return Err("that does not look like a Jira API token".into());
                }
                let project = self.project.as_deref().ok_or("the Jira project key is required, like OPS")?;
                let key_ok = project.len() >= 2
                    && project.len() <= 10
                    && project.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && project.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
                if !key_ok {
                    return Err("the Jira project key must be 2-10 uppercase letters/digits, like OPS".into());
                }
            }
            "servicenow" => {
                let url = self.url.as_deref().ok_or("the ServiceNow instance URL is required, like https://yourinstance.service-now.com")?;
                let (scheme, host) = split_url(url)?;
                if scheme == "http" && !is_loopback_host(host) {
                    return Err("the ServiceNow instance URL must use https://".into());
                }
                let user = self.user.as_deref().ok_or("the ServiceNow username is required")?;
                if user.is_empty() || user.chars().count() > 100 || user.chars().any(char::is_control) {
                    return Err("that does not look like a valid ServiceNow username".into());
                }
                let pass = self.secret.as_deref().ok_or("the ServiceNow password is required")?;
                if pass.chars().count() < 4 || pass.chars().count() > 300 || pass.chars().any(char::is_control) {
                    return Err("that does not look like a valid ServiceNow password".into());
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    /// The channel as the API shows it: identifying and non-secret settings, plus
    /// whether each secret is set. Never the secrets themselves.
    pub fn masked(&self) -> Value {
        let url_shown = self.url.as_deref().map(|u| {
            let (scheme, host) = split_url(u).unwrap_or(("https", "?"));
            format!("{scheme}://{host}/…")
        });
        json!({
            "id": self.id, "name": self.name, "kind": self.kind, "enabled": self.enabled, "min_score": self.min_score,
            "url": url_shown, "has_url": self.url.is_some(), "has_secret": self.secret.is_some(), "has_user": self.user.is_some(),
            "project": self.project,
            "smtp": self.smtp.as_ref().map(|s| json!({
                "host": s.host, "port": s.port, "security": s.security, "username": s.username,
                "has_password": s.password.is_some(), "from": s.from, "to": s.to,
            })),
        })
    }

    /// Text that must never appear in logs or error messages.
    fn secrets(&self) -> Vec<&str> {
        let mut v: Vec<&str> = Vec::new();
        v.extend(self.url.as_deref());
        v.extend(self.secret.as_deref());
        v.extend(self.user.as_deref());
        if let Some(s) = &self.smtp {
            v.extend(s.password.as_deref());
        }
        v.retain(|s| s.len() >= 4);
        v
    }

    fn scrub(&self, msg: String) -> String {
        let mut m = msg;
        for s in self.secrets() {
            m = m.replace(s, "[hidden]");
        }
        // a webhook URL's path is the credential even when only the host is shown
        if let Some(u) = &self.url {
            if let Some((_, rest)) = u.split_once("://") {
                if let Some((_, path)) = rest.split_once('/') {
                    if path.len() >= 8 {
                        m = m.replace(path, "[hidden]");
                    }
                }
            }
        }
        m
    }
}

/// Build a channel from an API body. `existing` is the channel being edited (its
/// secrets are kept when the body does not send new ones).
pub fn from_body(body: &Value, existing: Option<&Channel>) -> Result<Channel, String> {
    let obj = body.as_object().ok_or("expected a JSON object")?;
    const ALLOWED: &[&str] = &["name", "kind", "enabled", "min_score", "url", "secret", "user", "smtp", "project"];
    if let Some(k) = obj.keys().find(|k| !ALLOWED.contains(&k.as_str())) {
        return Err(format!("unknown field {k:?}"));
    }
    let mut c = existing.cloned().unwrap_or(Channel {
        id: String::new(), name: String::new(), kind: String::new(), enabled: true, min_score: 50, url: None, secret: None, user: None, smtp: None, project: None,
    });
    if let Some(k) = obj.get("kind") {
        let k = k.as_str().ok_or("kind must be text")?;
        if existing.is_some_and(|e| e.kind != k) {
            return Err("a channel's kind cannot change; create a new channel".into());
        }
        c.kind = k.into();
        if existing.is_none() && k == "pagerduty" && !obj.contains_key("min_score") {
            c.min_score = 70; // page people only for the serious things unless told otherwise
        }
    }
    let text = |k: &str| -> Result<Option<Option<String>>, String> {
        Ok(match obj.get(k) {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::String(s)) => Some(Some(s.trim().to_string()).filter(|s| !s.is_empty())),
            Some(_) => return Err(format!("{k} must be text")),
        })
    };
    if let Some(Some(n)) = text("name")? {
        c.name = n;
    }
    if let Some(v) = obj.get("enabled") {
        c.enabled = v.as_bool().ok_or("enabled must be true or false")?;
    }
    if let Some(v) = obj.get("min_score") {
        c.min_score = v.as_i64().and_then(|n| i32::try_from(n).ok()).ok_or("min_score must be a whole number")?;
    }
    if let Some(v) = text("url")? {
        c.url = v;
    }
    if let Some(v) = text("secret")? {
        c.secret = v;
    }
    if let Some(v) = text("user")? {
        c.user = v;
    }
    if let Some(v) = text("project")? {
        c.project = v.map(|p| p.to_ascii_uppercase());
    }
    if let Some(s) = obj.get("smtp") {
        let o = s.as_object().ok_or("smtp must be an object")?;
        let prev = c.smtp.clone();
        let get = |k: &str| o.get(k).and_then(Value::as_str).map(|s| s.trim().to_string());
        let to: Vec<String> = match o.get("to") {
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect(),
            Some(Value::String(s)) => s.split([',', ';', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
            _ => prev.as_ref().map(|p| p.to.clone()).unwrap_or_default(),
        };
        c.smtp = Some(Smtp {
            host: get("host").or_else(|| prev.as_ref().map(|p| p.host.clone())).unwrap_or_default(),
            port: o.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).or(prev.as_ref().map(|p| p.port)).unwrap_or(587),
            security: get("security").or_else(|| prev.as_ref().map(|p| p.security.clone())).unwrap_or_else(|| "starttls".into()),
            username: match o.get("username") {
                Some(Value::Null) => None,
                Some(v) => v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from),
                None => prev.as_ref().and_then(|p| p.username.clone()),
            },
            // an omitted password keeps the stored one; null or "" removes it
            password: match o.get("password") {
                Some(Value::Null) => None,
                Some(v) => v.as_str().filter(|s| !s.is_empty()).map(String::from),
                None => prev.as_ref().and_then(|p| p.password.clone()),
            },
            from: get("from").or_else(|| prev.as_ref().map(|p| p.from.clone())).unwrap_or_default(),
            to,
        });
    }
    c.validate()?;
    Ok(c)
}

pub fn load(store: &dyn Store) -> Result<Vec<Channel>> {
    Ok(store.get_setting(KEY)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default())
}

pub fn save(store: &dyn Store, list: &[Channel], now: i64) -> Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(list)?, now)
}

/// Add a channel (assigning its id).
pub fn add(list: &mut Vec<Channel>, mut c: Channel) -> Result<Channel, String> {
    if list.len() >= MAX_CHANNELS {
        return Err(format!("at most {MAX_CHANNELS} channels"));
    }
    c.id = format!("c{}", &crate::auth::random_token().map_err(|e| e.to_string())?[..10]);
    list.push(c.clone());
    Ok(c)
}

// ------------------------------------------------------------- maintenance

/// While active, no channel sends anything (the console still shows everything).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Maintenance {
    pub until: i64,
    #[serde(default)]
    pub note: String,
}

pub fn load_maintenance(store: &dyn Store) -> Result<Maintenance> {
    Ok(store.get_setting(MAINTENANCE_KEY)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default())
}

impl Maintenance {
    pub fn active(&self, now: i64) -> bool {
        self.until > now
    }
}

// ------------------------------------------------------------ notification

/// One alert as it will be sent, independent of the target's format.
#[derive(Clone, Debug)]
pub struct Notification {
    pub id: i64,
    pub kind: String,
    pub severity: String,
    pub score: i32,
    pub ts: i64,
    pub summary: String,
    pub reasons: Vec<String>,
    pub advice: Option<String>,
    pub name: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub site: Option<String>,
    pub asset_id: Option<i64>,
    pub test: bool,
    pub details: Value,
}

/// Names and addresses of the device an event is about.
pub fn describe_asset(assets: &[Asset], metas: &HashMap<i64, AssetMeta>, id: i64) -> (Option<String>, Option<String>, Option<String>) {
    let Some(a) = assets.iter().find(|a| a.id == id) else { return (None, None, None) };
    let name = metas.get(&id).and_then(|m| m.display_name.clone()).or_else(|| a.hostnames.first().cloned());
    (name, a.current_ip().map(|i| i.to_string()), Some(a.mac.to_string()))
}

pub fn from_event(e: &Event, assets: &[Asset], metas: &HashMap<i64, AssetMeta>) -> Notification {
    let (name, ip, mac) = describe_asset(assets, metas, e.asset_id);
    Notification {
        id: e.id,
        kind: e.kind.clone(),
        severity: e.severity.clone(),
        score: e.score,
        ts: e.timestamp,
        summary: short(e.raw_details["summary"].as_str().unwrap_or(""), 500),
        reasons: e.raw_details["reasons"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| short(s, 300)).take(10).collect()).unwrap_or_default(),
        advice: crate::detect::advice(&e.kind).map(String::from),
        name: name.map(|n| short(&n, 100)),
        ip,
        mac,
        site: e.agent_id.clone(),
        asset_id: Some(e.asset_id),
        test: false,
        details: e.raw_details.clone(),
    }
}

impl Notification {
    pub fn test() -> Self {
        Notification {
            id: 0, kind: "test".into(), severity: "low".into(), score: 30, ts: crate::model::now_ts(),
            summary: "This is a test notification from DENIS. If you can read it, this channel works.".into(),
            reasons: vec![], advice: None, name: Some("test device".into()), ip: Some("192.0.2.1".into()), mac: None, site: None, asset_id: None, test: true, details: json!({}),
        }
    }

    /// One message standing for several waiting alerts.
    pub fn digest(items: &[Notification]) -> Self {
        let mut top: Vec<&Notification> = items.iter().collect();
        top.sort_by_key(|n| std::cmp::Reverse(n.score));
        let worst = top.first().map_or(0, |n| n.score);
        Notification {
            id: items.last().map_or(0, |n| n.id),
            kind: "digest".into(),
            severity: top.first().map_or("low", |n| n.severity.as_str()).into(),
            score: worst,
            ts: items.last().map_or(0, |n| n.ts),
            summary: format!("{} alerts are waiting; the most serious {} are listed. Open the console for the rest.", items.len(), top.len().min(5)),
            reasons: top.iter().take(5).map(|n| format!("{} {}: {}{}", n.severity.to_uppercase(), n.score, n.kind, if n.summary.is_empty() { String::new() } else { format!(" - {}", short(&n.summary, 120)) })).collect(),
            advice: None, name: None, ip: None, mac: None, site: None, asset_id: None, test: false, details: json!({ "count": items.len() }),
        }
    }

    fn headline(&self) -> String {
        if self.test {
            return "DENIS test notification".into();
        }
        format!("{} {} · {}", self.severity.to_uppercase(), self.score, self.kind)
    }

    /// `name (ip)` for the device, if known.
    fn device(&self) -> Option<String> {
        match (&self.name, &self.ip) {
            (Some(n), Some(i)) => Some(format!("{n} ({i})")),
            (Some(n), None) => Some(n.clone()),
            (None, Some(i)) => Some(i.clone()),
            _ => self.mac.clone(),
        }
    }

    /// Plain text used by e-mail and as the fallback line of the chat formats.
    pub fn plain(&self) -> String {
        let mut t = format!("{}\n{}\n", self.headline(), self.summary);
        if let Some(d) = self.device() {
            t.push_str(&format!("Device: {d}\n"));
        }
        if let Some(s) = &self.site {
            t.push_str(&format!("Site: {s}\n"));
        }
        if !self.reasons.is_empty() {
            t.push_str("\nWhy:\n");
            for r in &self.reasons {
                t.push_str(&format!("  - {r}\n"));
            }
        }
        if let Some(a) = &self.advice {
            t.push_str(&format!("\nWhat to do:\n{a}\n"));
        }
        t
    }
}

// ---------------------------------------------------------------- formats

fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { format!("{}…", s.chars().take(max - 1).collect::<String>()) }
}

pub fn slack_payload(n: &Notification) -> Value {
    let emoji = match n.severity.as_str() { "high" => ":rotating_light:", "medium" => ":warning:", _ => ":information_source:" };
    let mut body = format!("{emoji} *{}*\n{}", slack_escape(&n.headline()), slack_escape(&n.summary));
    if let Some(d) = n.device() {
        body.push_str(&format!("\n*Device:* {}", slack_escape(&d)));
    }
    if !n.reasons.is_empty() {
        body.push_str("\n*Why:*\n");
        body.push_str(&n.reasons.iter().map(|r| format!("• {}", slack_escape(r))).collect::<Vec<_>>().join("\n"));
    }
    if let Some(a) = &n.advice {
        body.push_str(&format!("\n*What to do:* {}", slack_escape(a)));
    }
    json!({
        // the fallback line is parsed as mrkdwn too, so it needs the same escaping
        "text": slack_escape(&cut(&n.plain().replace('\n', " "), 300)),
        // a section's text is limited to about 3000 characters; stay well under
        "blocks": [{ "type": "section", "text": { "type": "mrkdwn", "text": cut(&body, 2800) } }],
    })
}

pub fn teams_payload(n: &Notification) -> Value {
    let colour = match n.severity.as_str() { "high" => "Attention", "medium" => "Warning", _ => "Default" };
    let mut body = vec![
        json!({ "type": "TextBlock", "text": n.headline(), "weight": "Bolder", "size": "Medium", "color": colour, "wrap": true }),
        json!({ "type": "TextBlock", "text": n.summary, "wrap": true }),
    ];
    let mut facts = Vec::new();
    if let Some(d) = n.device() {
        facts.push(json!({ "title": "Device", "value": d }));
    }
    if let Some(s) = &n.site {
        facts.push(json!({ "title": "Site", "value": s }));
    }
    if !facts.is_empty() {
        body.push(json!({ "type": "FactSet", "facts": facts }));
    }
    if !n.reasons.is_empty() {
        body.push(json!({ "type": "TextBlock", "text": format!("Why: {}", n.reasons.join("; ")), "wrap": true, "isSubtle": true }));
    }
    if let Some(a) = &n.advice {
        body.push(json!({ "type": "TextBlock", "text": format!("What to do: {a}"), "wrap": true }));
    }
    // Teams' "Workflows" webhook trigger expects a message carrying an Adaptive Card attachment.
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": { "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.2", "body": body },
        }],
    })
}

pub fn discord_payload(n: &Notification) -> Value {
    let colour = match n.severity.as_str() { "high" => 0xdc2626, "medium" => 0xf59e0b, _ => 0x3b82f6 };
    let mut fields = Vec::new();
    if let Some(d) = n.device() {
        fields.push(json!({ "name": "Device", "value": cut(&d, 1000), "inline": true }));
    }
    if let Some(s) = &n.site {
        fields.push(json!({ "name": "Site", "value": cut(s, 1000), "inline": true }));
    }
    if !n.reasons.is_empty() {
        fields.push(json!({ "name": "Why", "value": cut(&n.reasons.iter().map(|r| format!("• {r}")).collect::<Vec<_>>().join("\n"), 1000) }));
    }
    if let Some(a) = &n.advice {
        fields.push(json!({ "name": "What to do", "value": cut(a, 1000) }));
    }
    json!({
        // a hostile device name must not be able to ping @everyone or a role
        "allowed_mentions": { "parse": [] },
        "embeds": [{ "title": cut(&n.headline(), 250), "description": cut(&n.summary, 3900), "color": colour, "fields": fields }],
    })
}

pub fn pagerduty_payload(n: &Notification, routing_key: &str, source: &str) -> Value {
    let severity = match (n.severity.as_str(), n.score) {
        ("high", s) if s >= 90 => "critical",
        ("high", _) => "error",
        ("medium", _) => "warning",
        _ => "info",
    };
    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        // repeats of the same kind of alert about the same device fold into one incident
        "dedup_key": match n.asset_id { Some(a) if !n.test => format!("denis-{}-{a}", n.kind), _ => format!("denis-{}", n.kind) },
        "payload": {
            "summary": cut(&format!("{} - {}", n.headline(), n.summary), 1024),
            "source": if source.is_empty() { "denis" } else { source },
            "severity": severity,
            "timestamp": crate::report::iso(n.ts.max(0)).replace('Z', ".000+0000"),
            "component": n.device().unwrap_or_default(),
            "class": n.kind,
            "custom_details": { "score": n.score, "reasons": n.reasons, "advice": n.advice, "mac": n.mac, "site": n.site },
        },
    })
}

/// Pushover message (their API accepts JSON). Priority follows severity; nothing needs an acknowledgement.
pub fn pushover_payload(n: &Notification, token: &str, user: &str) -> Value {
    let priority = match n.severity.as_str() {
        _ if n.test => 0,
        "high" => 1, // bypasses the recipient's quiet hours
        "medium" => 0,
        _ => -1,
    };
    let mut msg = n.summary.clone();
    if let Some(d) = n.device() {
        msg.push_str(&format!("\nDevice: {d}"));
    }
    if let Some(a) = &n.advice {
        msg.push_str(&format!("\nWhat to do: {a}"));
    }
    json!({ "token": token, "user": user, "title": cut(&n.headline(), 250), "message": cut(&msg, 1024), "priority": priority, "timestamp": n.ts.max(0) })
}

/// One Atlassian Document Format paragraph of plain text (Jira Cloud's REST API v3 requires ADF
/// for a rich-text field, even for what is really just a few lines of text).
fn adf_paragraph(text: &str) -> Value {
    json!({ "type": "paragraph", "content": [{ "type": "text", "text": text }] })
}

/// Jira Cloud issue-create payload (REST API v3): one issue per notification, filed under
/// `project`. DENIS never updates or transitions the issue afterwards — closing it is the same
/// manual step as acknowledging any other alert, just done in Jira's own workflow instead.
pub fn jira_payload(n: &Notification, project: &str) -> Value {
    let mut content = vec![adf_paragraph(&cut(&n.summary, 2000))];
    if let Some(d) = n.device() {
        content.push(adf_paragraph(&format!("Device: {d}")));
    }
    if let Some(s) = &n.site {
        content.push(adf_paragraph(&format!("Site: {s}")));
    }
    if !n.reasons.is_empty() {
        content.push(adf_paragraph(&format!("Why: {}", n.reasons.iter().map(|r| short(r, 300)).collect::<Vec<_>>().join("; "))));
    }
    if let Some(a) = &n.advice {
        content.push(adf_paragraph(&format!("What to do: {a}")));
    }
    let mut labels = vec!["denis".to_string()];
    if !n.test {
        labels.push(n.kind.replace(['_', ' '], "-"));
    }
    json!({
        "fields": {
            "project": { "key": project },
            "issuetype": { "name": "Task" },
            "summary": cut(&format!("{} - {}", n.headline(), n.summary), 250),
            "description": { "type": "doc", "version": 1, "content": content },
            "labels": labels,
        },
    })
}

/// HTTP Basic auth header value (`Basic base64(user:pass)`), shared by Jira and ServiceNow.
fn basic_auth(user: &str, pass: &str) -> String {
    format!("Basic {}", crate::report::base64(format!("{user}:{pass}").as_bytes()))
}

/// ServiceNow Table API incident-create payload (`POST .../api/now/table/incident`). The
/// `correlation_id` is ServiceNow's own convention for an external monitoring tool's dedup key —
/// the same idea as PagerDuty's `dedup_key` — so a re-sent alert about the same device correlates
/// in ServiceNow's own UI instead of opening a new incident every time.
pub fn servicenow_payload(n: &Notification) -> Value {
    let (urgency, impact) = match n.severity.as_str() {
        _ if n.test => ("3", "3"),
        "high" => ("1", "2"),
        "medium" => ("2", "2"),
        _ => ("3", "3"),
    };
    let mut description = n.summary.clone();
    if let Some(d) = n.device() {
        description.push_str(&format!("\nDevice: {d}"));
    }
    if let Some(s) = &n.site {
        description.push_str(&format!("\nSite: {s}"));
    }
    if !n.reasons.is_empty() {
        description.push_str(&format!("\nWhy: {}", n.reasons.iter().map(|r| short(r, 300)).collect::<Vec<_>>().join("; ")));
    }
    if let Some(a) = &n.advice {
        description.push_str(&format!("\nWhat to do: {a}"));
    }
    json!({
        "short_description": cut(&format!("{} - {}", n.headline(), n.summary), 160),
        "description": cut(&description, 4000),
        "urgency": urgency,
        "impact": impact,
        "category": "network",
        "correlation_id": match n.asset_id { Some(a) if !n.test => format!("denis-{}-{a}", n.kind), _ => format!("denis-{}", n.kind) },
    })
}

/// Split an ntfy topic address into the server (`https://ntfy.sh`) and the topic (`your-topic`).
pub fn ntfy_target(url: &str) -> Result<(String, String), String> {
    let (scheme, _) = split_url(url)?;
    let rest = &url[scheme.len() + 3..];
    if url.contains(['?', '#']) {
        return Err("the ntfy address is the server and the topic, like https://ntfy.sh/your-topic".into());
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let topic = segments.pop().ok_or("the ntfy address needs a topic at the end, like https://ntfy.sh/your-topic")?;
    if topic.len() > 64 || !topic.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("an ntfy topic is up to 64 letters, digits, - and _".into());
    }
    let prefix = if segments.is_empty() { String::new() } else { format!("/{}", segments.join("/")) };
    Ok((format!("{scheme}://{authority}{prefix}"), topic.to_string()))
}

/// ntfy message, published as JSON to the server (so device names with any characters are safe: no headers involved).
pub fn ntfy_payload(n: &Notification, topic: &str) -> Value {
    let (priority, tag) = match (n.severity.as_str(), n.score) {
        ("high", s) if s >= 90 => (5, "rotating_light"),
        ("high", _) => (4, "rotating_light"),
        ("medium", _) => (3, "warning"),
        _ => (2, "information_source"),
    };
    json!({ "topic": topic, "title": cut(&n.headline(), 250), "message": cut(&n.plain(), 3900), "priority": if n.test { 3 } else { priority }, "tags": [tag] })
}

pub fn webhook_payload(n: &Notification, now: i64) -> Value {
    json!({
        "version": 1,
        "sent_at": now,
        "test": n.test,
        "event": { "id": n.id, "type": n.kind, "severity": n.severity, "score": n.score, "timestamp": n.ts, "summary": n.summary, "reasons": n.reasons, "details": n.details },
        "device": { "id": n.asset_id, "name": n.name, "ip": n.ip, "mac": n.mac, "site": n.site },
        "advice": n.advice,
    })
}

/// HMAC-SHA256 (RFC 2104), hex encoded.
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    let mut k = if key.len() > 64 { Sha256::digest(key).to_vec() } else { key.to_vec() };
    k.resize(64, 0);
    let mut inner = Sha256::new();
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner.finalize());
    outer.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------ sending

fn http_client() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(15))).http_status_as_error(false).build().into()
}

fn post_json(url: &str, body: &Value, extra: &[(&str, String)]) -> Result<()> {
    let text = body.to_string();
    if text.len() > 28 * 1024 {
        bail!("message too large"); // Teams' documented limit; smaller than the others
    }
    let mut req = http_client().post(url).header("Content-Type", "application/json");
    for (k, v) in extra {
        req = req.header(*k, v.as_str());
    }
    let resp = req.send(text.as_bytes()).map_err(|e| anyhow!("{e}"))?;
    let code = resp.status().as_u16();
    if (200..300).contains(&code) {
        return Ok(());
    }
    match code {
        429 => bail!("the service is rate limiting (HTTP 429); will retry"),
        401 | 403 | 404 => bail!("the service refused the request (HTTP {code}): check the URL or key"),
        _ => bail!("the service answered HTTP {code}"),
    }
}

fn send_email(s: &Smtp, n: &Notification) -> Result<()> {
    let subject: String = format!("[DENIS] {}: {}", n.headline(), n.summary).chars().filter(|c| !c.is_control()).take(200).collect();
    send_smtp(s, &s.to, &subject, &n.plain())
}

/// The actual SMTP send, shared by the e-mail notification channel and anything else in DENIS
/// that sends mail (scheduled reports) — `to` is separate from `s.to` so a caller can mail
/// different recipients than the channel's own, using the same server settings.
pub(crate) fn send_smtp(s: &Smtp, to: &[String], subject: &str, body: &str) -> Result<()> {
    use lettre::message::Mailbox;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};
    let mut b = Message::builder().from(s.from.parse::<Mailbox>()?);
    for addr in to {
        b = b.to(addr.parse::<Mailbox>()?);
    }
    let subject: String = subject.chars().filter(|c| !c.is_control()).take(200).collect();
    let msg = b.subject(subject).body(body.to_string())?;
    let builder = match s.security.as_str() {
        "tls" => SmtpTransport::relay(&s.host)?,
        "starttls" => SmtpTransport::starttls_relay(&s.host)?,
        _ => SmtpTransport::builder_dangerous(&s.host),
    };
    let mut builder = builder.port(s.port).timeout(Some(Duration::from_secs(20)));
    if let (Some(u), Some(p)) = (&s.username, &s.password) {
        builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
    }
    builder.build().send(&msg)?;
    Ok(())
}

/// Send one notification through one channel. Errors never contain secrets.
pub fn send(ch: &Channel, n: &Notification, host: &str, now: i64) -> Result<()> {
    let r: Result<()> = match ch.kind.as_str() {
        "slack" => post_json(ch.url.as_deref().unwrap_or(""), &slack_payload(n), &[]),
        "teams" => post_json(ch.url.as_deref().unwrap_or(""), &teams_payload(n), &[]),
        "discord" => post_json(ch.url.as_deref().unwrap_or(""), &discord_payload(n), &[]),
        "pagerduty" => post_json(ch.url.as_deref().unwrap_or(PAGERDUTY_URL), &pagerduty_payload(n, ch.secret.as_deref().unwrap_or(""), host), &[]),
        "pushover" => post_json(ch.url.as_deref().unwrap_or(PUSHOVER_URL), &pushover_payload(n, ch.secret.as_deref().unwrap_or(""), ch.user.as_deref().unwrap_or("")), &[]),
        "ntfy" => {
            let (base, topic) = ntfy_target(ch.url.as_deref().unwrap_or("")).map_err(|e| anyhow!("{e}"))?;
            let extra: Vec<(&str, String)> = ch.secret.iter().map(|t| ("Authorization", format!("Bearer {t}"))).collect();
            post_json(&base, &ntfy_payload(n, &topic), &extra)
        }
        "webhook" => {
            let body = webhook_payload(n, now);
            let mut extra = Vec::new();
            if let Some(secret) = &ch.secret {
                extra.push(("X-Denis-Signature", format!("sha256={}", hmac_sha256_hex(secret.as_bytes(), body.to_string().as_bytes()))));
            }
            post_json(ch.url.as_deref().unwrap_or(""), &body, &extra)
        }
        "email" => send_email(ch.smtp.as_ref().context("no SMTP settings")?, n),
        "jira" => {
            let base = ch.url.as_deref().unwrap_or("").trim_end_matches('/');
            let auth = basic_auth(ch.user.as_deref().unwrap_or(""), ch.secret.as_deref().unwrap_or(""));
            post_json(&format!("{base}/rest/api/3/issue"), &jira_payload(n, ch.project.as_deref().unwrap_or("")), &[("Authorization", auth)])
        }
        "servicenow" => {
            let base = ch.url.as_deref().unwrap_or("").trim_end_matches('/');
            let auth = basic_auth(ch.user.as_deref().unwrap_or(""), ch.secret.as_deref().unwrap_or(""));
            post_json(&format!("{base}/api/now/table/incident"), &servicenow_payload(n), &[("Authorization", auth)])
        }
        other => Err(anyhow!("unknown channel kind {other}")),
    };
    r.map_err(|e| anyhow!(ch.scrub(format!("{e:#}"))))
}

// --------------------------------------------------------------- dispatcher

#[derive(Clone, Debug, Default, Serialize)]
pub struct ChannelStatus {
    pub last_ok: Option<i64>,
    pub last_error: Option<String>,
    /// Messages accepted since start.
    pub sent: u64,
}

pub type StatusMap = Arc<Mutex<HashMap<String, ChannelStatus>>>;

pub struct Dispatcher {
    pub status: StatusMap,
    host: String,
    /// Pause between individual messages (Slack allows about one per second per channel).
    spacing: Duration,
    /// channel id -> (consecutive failures, do not retry before)
    backoff: Mutex<HashMap<String, (u32, i64)>>,
}

fn cursor_key(id: &str) -> String {
    format!("channel.{id}.cursor")
}

impl Dispatcher {
    pub fn new(status: StatusMap, host: String, spacing: Duration) -> Self {
        Dispatcher { status, host, spacing, backoff: Mutex::new(HashMap::new()) }
    }

    /// One pass over every enabled channel.
    pub fn cycle(&self, store: &dyn Store, now: i64) {
        let Ok(channels) = load(store) else { return };
        let maintenance = load_maintenance(store).unwrap_or_default();
        let (assets, metas) = (store.load_assets().unwrap_or_default(), store.load_all_meta().unwrap_or_default());
        for ch in channels.iter().filter(|c| c.enabled) {
            if self.backoff.lock().unwrap_or_else(|e| e.into_inner()).get(&ch.id).is_some_and(|(_, until)| now < *until) {
                continue;
            }
            match self.deliver(ch, store, &assets, &metas, maintenance.active(now), now) {
                Ok(sent) => {
                    self.backoff.lock().unwrap_or_else(|e| e.into_inner()).remove(&ch.id);
                    let mut st = self.status.lock().unwrap_or_else(|e| e.into_inner());
                    let s = st.entry(ch.id.clone()).or_default();
                    s.sent += sent;
                    s.last_error = None;
                    if sent > 0 {
                        s.last_ok = Some(now);
                    }
                }
                Err(e) => {
                    let mut b = self.backoff.lock().unwrap_or_else(|e| e.into_inner());
                    let fails = b.get(&ch.id).map_or(0, |(f, _)| *f) + 1;
                    b.insert(ch.id.clone(), (fails, now + (15i64 << fails.min(6)).min(900)));
                    self.status.lock().unwrap_or_else(|e| e.into_inner()).entry(ch.id.clone()).or_default().last_error = Some(format!("{e:#}"));
                }
            }
        }
    }

    /// Send what is new for one channel. Returns how many messages were accepted.
    fn deliver(&self, ch: &Channel, store: &dyn Store, assets: &[Asset], metas: &HashMap<i64, AssetMeta>, silenced: bool, now: i64) -> Result<u64> {
        let key = cursor_key(&ch.id);
        let cursor: i64 = match store.get_setting(&key)? {
            Some(b) => String::from_utf8_lossy(&b).parse().unwrap_or(0),
            None => {
                // a new channel starts from now: it must not replay the whole history
                let newest = store.list_events(&crate::store::EventQuery { limit: 1, ..Default::default() })?.first().map_or(0, |e| e.id);
                store.set_setting(&key, newest.to_string().as_bytes(), now)?;
                return Ok(0);
            }
        };
        let batch = store.events_after(cursor, 500)?;
        let Some(last_id) = batch.last().map(|e| e.id) else { return Ok(0) };
        if silenced {
            store.set_setting(&key, last_id.to_string().as_bytes(), now)?;
            return Ok(0);
        }
        let today = now.div_euclid(86_400);
        let due: Vec<(i64, Notification)> = batch
            .iter()
            .filter(|e| e.severity != "info" && e.score >= ch.min_score && now - e.timestamp <= MAX_AGE_SECS)
            .filter(|e| {
                // "muted until <date>" runs to the end of that day
                !metas.get(&e.asset_id).and_then(|m| m.muted_until.as_deref()).and_then(crate::tracking::days_from_date).is_some_and(|d| today <= d)
            })
            .map(|e| (e.id, from_event(e, assets, metas)))
            .collect();
        if due.is_empty() {
            store.set_setting(&key, last_id.to_string().as_bytes(), now)?;
            return Ok(0);
        }
        if due.len() > DIGEST_ABOVE {
            let items: Vec<Notification> = due.into_iter().map(|(_, n)| n).collect();
            send(ch, &Notification::digest(&items), &self.host, now)?;
            store.set_setting(&key, last_id.to_string().as_bytes(), now)?;
            return Ok(1);
        }
        let mut sent = 0;
        for (i, (id, n)) in due.iter().enumerate() {
            if i > 0 {
                std::thread::sleep(self.spacing);
            }
            // on failure the cursor stays just before this alert, so it is retried
            send(ch, n, &self.host, now)?;
            store.set_setting(&key, id.to_string().as_bytes(), now)?;
            sent += 1;
        }
        store.set_setting(&key, last_id.to_string().as_bytes(), now)?;
        Ok(sent)
    }
}

/// Run until aborted: one cycle every few seconds.
pub async fn run(d: Arc<Dispatcher>, store: Arc<dyn Store>) {
    loop {
        let (dd, st) = (d.clone(), store.clone());
        if tokio::task::spawn_blocking(move || dd.cycle(&*st, crate::model::now_ts())).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AssetStore;
    use crate::store::EventStore;
    use crate::store::SettingsStore;
    use crate::model::Mac;
    use crate::store::sqlite::SqliteStore;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU16, Ordering};

    /// (path, lower-cased headers, JSON body) of each request received
    type Seen = Vec<(String, Vec<(String, String)>, Value)>;

    struct Fake {
        url: String,
        seen: Arc<Mutex<Seen>>,
        code: Arc<AtomicU16>,
    }

    fn fake() -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let code = Arc::new(AtomicU16::new(200));
        let (s2, c2) = (seen.clone(), code.clone());
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut c) = conn else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (head_end, len) = loop {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                        let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0usize);
                        break (p + 4, len);
                    }
                };
                while buf.len() < head_end + len {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                let headers: Vec<(String, String)> = head.lines().skip(1).filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())).collect();
                let body: Value = serde_json::from_slice(&buf[head_end..]).unwrap_or(Value::Null);
                let code = c2.load(Ordering::SeqCst);
                if code == 200 {
                    s2.lock().unwrap_or_else(|e| e.into_inner()).push((path, headers, body));
                }
                let _ = write!(c, "HTTP/1.1 {code} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
            }
        });
        Fake { url, seen, code }
    }

    fn chan(kind: &str, url: &str) -> Channel {
        from_body(&json!({"name": "ops", "kind": kind, "url": url, "secret": if kind == "pagerduty" { "R0UTINGKEY12345" } else { "" }, "min_score": 30}), None).unwrap()
    }

    fn world() -> (SqliteStore, i64) {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 1);
        a.hostnames = vec!["<!channel> cam".into()];
        s.save_asset(&mut a).unwrap();
        (s, a.id)
    }

    fn event(s: &SqliteStore, asset: i64, kind: &str, score: i32, ts: i64) -> i64 {
        let mut e = Event {
            id: 0, agent_id: None, asset_id: asset, kind: kind.into(), timestamp: ts, severity: crate::detect::severity_for(score, 30).into(), score, acked: false,
            raw_details: json!({"summary": format!("{kind} happened"), "reasons": ["+40 a", "+30 b"]}),
        };
        s.insert_event(&mut e).unwrap();
        e.id
    }

    #[test]
    fn hmac_matches_the_rfc_4231_test_vectors() {
        assert_eq!(hmac_sha256_hex(&[0x0b; 20], b"Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // a key longer than the block size is hashed first (test case 6)
        assert_eq!(
            hmac_sha256_hex(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First"),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn validation_is_strict_and_secrets_are_never_shown() {
        for bad in [
            json!({"name": "x", "kind": "slack"}),
            json!({"name": "x", "kind": "slack", "url": "ftp://x"}),
            json!({"name": "x", "kind": "slack", "url": "http://hooks.slack.com/services/T/B/X"}),
            json!({"name": "x", "kind": "teams", "url": "https://user:pw@evil.example/x"}),
            json!({"name": "x", "kind": "slack", "url": "https://a.example/x y"}),
            json!({"name": "", "kind": "slack", "url": "https://a.example/x"}),
            json!({"name": "x", "kind": "slack", "url": "https://a.example/x", "min_score": 101}),
            json!({"name": "x", "kind": "pagerduty", "secret": "bad key!"}),
            json!({"name": "x", "kind": "pagerduty"}),
            json!({"name": "x", "kind": "nope", "url": "https://a.example/x"}),
            json!({"name": "x", "kind": "slack", "url": "https://a.example/x", "surprise": 1}),
            json!({"name": "x", "kind": "email", "smtp": {"host": "smtp.example.com", "from": "a@example.com", "to": []}}),
            json!({"name": "x", "kind": "email", "smtp": {"host": "smtp.example.com", "from": "not an address", "to": ["b@example.com"]}}),
            json!({"name": "x", "kind": "email", "smtp": {"host": "smtp.example.com", "security": "none", "username": "u", "password": "p", "from": "a@example.com", "to": ["b@example.com"]}}),
            json!({"name": "x", "kind": "jira", "url": "https://a.atlassian.net"}),
            json!({"name": "x", "kind": "jira", "url": "https://a.atlassian.net", "user": "not-an-email", "secret": "0123456789abcdef", "project": "OPS"}),
            json!({"name": "x", "kind": "jira", "url": "https://a.atlassian.net", "user": "a@example.com", "secret": "short", "project": "OPS"}),
            json!({"name": "x", "kind": "jira", "url": "https://a.atlassian.net", "user": "a@example.com", "secret": "0123456789abcdef", "project": "O"}),
            json!({"name": "x", "kind": "jira", "url": "http://a.atlassian.net", "user": "a@example.com", "secret": "0123456789abcdef", "project": "OPS"}),
            json!({"name": "x", "kind": "servicenow", "user": "bot", "secret": "hunter2hunter2"}),
            json!({"name": "x", "kind": "servicenow", "url": "https://a.service-now.com", "secret": "hunter2hunter2"}),
            json!({"name": "x", "kind": "servicenow", "url": "https://a.service-now.com", "user": "bot", "secret": "abc"}),
            json!({"name": "x", "kind": "servicenow", "url": "http://a.service-now.com", "user": "bot", "secret": "hunter2hunter2"}),
        ] {
            assert!(from_body(&bad, None).is_err(), "{bad}");
        }
        let jira = from_body(&json!({"name": "tix", "kind": "jira", "url": "https://a.atlassian.net", "user": "bot@example.com", "secret": "0123456789abcdefTOKEN", "project": "ops"}), None).unwrap();
        assert_eq!(jira.project.as_deref(), Some("OPS"), "the project key is upper-cased");
        let jshown = jira.masked().to_string();
        assert!(!jshown.contains("TOKEN") && !jshown.contains("bot@example.com") && jshown.contains("\"project\":\"OPS\""), "{jshown}");
        let sn = from_body(&json!({"name": "tix2", "kind": "servicenow", "url": "https://a.service-now.com", "user": "denis-bot", "secret": "hunter2hunter2"}), None).unwrap();
        let sshown = sn.masked().to_string();
        assert!(!sshown.contains("hunter2") && !sshown.contains("denis-bot") && sshown.contains("service-now.com"), "{sshown}");
        assert!(from_body(&json!({"name": "x", "kind": "webhook", "url": "http://10.0.0.5/hook", "secret": "0123456789abcdef"}), None).is_ok(), "plain http is fine for a generic webhook");
        let c = from_body(&json!({"name": "ops", "kind": "slack", "url": "https://hooks.slack.com/services/T000/B000/SECRETSECRET"}), None).unwrap();
        let shown = c.masked().to_string();
        assert!(!shown.contains("SECRET") && !shown.contains("T000") && shown.contains("hooks.slack.com") && shown.contains("\"has_url\":true"), "{shown}");
        let e = from_body(&json!({"name": "m", "kind": "email", "smtp": {"host": "smtp.example.com", "port": 587, "username": "u", "password": "hunter2hunter2", "from": "DENIS <d@example.com>", "to": "a@example.com, b@example.com"}}), None).unwrap();
        assert!(!e.masked().to_string().contains("hunter2") && e.masked()["smtp"]["has_password"] == true);
        assert_eq!(e.smtp.as_ref().unwrap().to.len(), 2);
        // editing keeps stored secrets unless new ones are sent, and the kind is fixed
        let e2 = from_body(&json!({"enabled": false, "smtp": {"to": ["c@example.com"]}}), Some(&e)).unwrap();
        assert_eq!(e2.smtp.as_ref().unwrap().password.as_deref(), Some("hunter2hunter2"));
        assert!(!e2.enabled);
        assert!(from_body(&json!({"kind": "slack"}), Some(&e)).is_err());
        // errors mention neither the URL nor its token
        let msg = c.scrub("could not connect to https://hooks.slack.com/services/T000/B000/SECRETSECRET".into());
        assert!(!msg.contains("SECRET"), "{msg}");
    }

    #[test]
    fn every_format_escapes_hostile_device_names() {
        let (s, id) = world();
        event(&s, id, "new_port", 80, 1000);
        let e = &s.events_after(0, 10).unwrap()[0];
        let n = from_event(e, &s.load_assets().unwrap(), &HashMap::new());
        let slack = slack_payload(&n).to_string();
        assert!(!slack.contains("<!channel>") && slack.contains("&lt;!channel&gt;"), "{slack}");
        assert!(slack.contains("What to do"));
        let d = discord_payload(&n);
        assert_eq!(d["allowed_mentions"]["parse"], json!([]), "mentions are switched off");
        let t = teams_payload(&n);
        assert_eq!(t["attachments"][0]["contentType"], "application/vnd.microsoft.card.adaptive");
        assert_eq!(t["attachments"][0]["content"]["type"], "AdaptiveCard");
        let pd = pagerduty_payload(&n, "KEY", "denis-host");
        assert_eq!((pd["event_action"].as_str(), pd["payload"]["severity"].as_str()), (Some("trigger"), Some("error")));
        assert_eq!(pd["dedup_key"], format!("denis-new_port-{id}"));
        assert!(pd["payload"]["timestamp"].as_str().unwrap().ends_with(".000+0000"));
        assert!(webhook_payload(&n, 5)["event"]["type"] == "new_port");
        // very long text stays inside every service's limits
        let mut big = n.clone();
        big.summary = "x".repeat(50_000);
        big.reasons = vec!["y".repeat(5_000); 10];
        assert!(slack_payload(&big)["blocks"][0]["text"]["text"].as_str().unwrap().chars().count() <= 2800);
        assert!(discord_payload(&big)["embeds"][0]["description"].as_str().unwrap().chars().count() <= 3900);
        assert!(pagerduty_payload(&big, "K", "s")["payload"]["summary"].as_str().unwrap().chars().count() <= 1024);
    }

    #[test]
    fn new_channels_start_from_now_then_send_each_alert_once_with_the_right_shape() {
        let f = fake();
        let (s, id) = world();
        event(&s, id, "old_thing", 90, 100); // history before the channel exists
        let ch = chan("slack", &format!("{}/services/T/B/X", f.url));
        save(&s, std::slice::from_ref(&ch), 1).unwrap();
        let d = Dispatcher::new(Arc::default(), "denis".into(), Duration::ZERO);
        d.cycle(&s, 200);
        assert!(f.seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(), "history is not replayed");
        event(&s, id, "new_port", 80, 190);
        event(&s, id, "volume_anomaly", 20, 195); // below the channel's minimum
        d.cycle(&s, 200);
        {
            let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].0, "/services/T/B/X");
            assert!(seen[0].2["blocks"][0]["text"]["text"].as_str().unwrap().contains("new_port"));
        }
        d.cycle(&s, 210);
        assert_eq!(f.seen.lock().unwrap_or_else(|e| e.into_inner()).len(), 1, "nothing is sent twice");
        assert_eq!(d.status.lock().unwrap_or_else(|e| e.into_inner())[&ch.id].sent, 1);
    }

    #[test]
    fn an_outage_keeps_the_alert_for_later_and_backs_off() {
        let f = fake();
        let (s, id) = world();
        let ch = chan("teams", &format!("{}/hook", f.url));
        save(&s, std::slice::from_ref(&ch), 1).unwrap();
        let d = Dispatcher::new(Arc::default(), "denis".into(), Duration::ZERO);
        d.cycle(&s, 100);
        f.code.store(500, Ordering::SeqCst);
        event(&s, id, "arp_conflict", 85, 150);
        d.cycle(&s, 160);
        let err = d.status.lock().unwrap_or_else(|e| e.into_inner())[&ch.id].last_error.clone().unwrap();
        assert!(err.contains("500") && !err.contains(&f.url), "{err}");
        f.code.store(200, Ordering::SeqCst);
        d.cycle(&s, 161);
        assert!(f.seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(), "still backing off");
        d.cycle(&s, 400);
        let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 1, "delivered after the outage");
        assert_eq!(seen[0].2["type"], "message");
    }

    #[test]
    fn a_storm_becomes_one_digest_and_maintenance_mutes_and_stale_alerts_are_dropped() {
        let f = fake();
        let (s, id) = world();
        let ch = chan("discord", &format!("{}/api/webhooks/1/x", f.url));
        save(&s, std::slice::from_ref(&ch), 1).unwrap();
        let d = Dispatcher::new(Arc::default(), "denis".into(), Duration::ZERO);
        d.cycle(&s, 100);
        for i in 0..8 {
            event(&s, id, "new_destination", 40 + i, 150);
        }
        d.cycle(&s, 200);
        {
            let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(seen.len(), 1, "one digest, not eight messages");
            assert!(seen[0].2["embeds"][0]["description"].as_str().unwrap().contains("8 alerts"));
        }
        // maintenance mode: events are silenced, and stay silenced afterwards
        s.set_setting(MAINTENANCE_KEY, &serde_json::to_vec(&Maintenance { until: 1000, note: "patching".into() }).unwrap(), 1).unwrap();
        event(&s, id, "arp_conflict", 90, 250);
        d.cycle(&s, 260);
        d.cycle(&s, 2000);
        assert_eq!(f.seen.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);
        // yesterday's news is not sent
        event(&s, id, "new_port", 80, 10);
        d.cycle(&s, 10 + MAX_AGE_SECS + 5000);
        assert_eq!(f.seen.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);
    }

    #[test]
    fn a_muted_device_is_silent_until_the_end_of_its_date() {
        let f = fake();
        let (s, id) = world();
        let ch = chan("slack", &format!("{}/x/y/z", f.url));
        save(&s, std::slice::from_ref(&ch), 1).unwrap();
        let d = Dispatcher::new(Arc::default(), "denis".into(), Duration::ZERO);
        let day = 1_790_000_000 - 1_790_000_000 % 86_400; // midnight
        d.cycle(&s, day);
        let date = crate::report::iso(day + 3600)[..10].to_string();
        s.save_meta(id, &AssetMeta { muted_until: Some(date), ..Default::default() }, "t", 1).unwrap();
        event(&s, id, "new_port", 80, day + 100);
        d.cycle(&s, day + 20 * 3600); // still that day
        assert!(f.seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
        event(&s, id, "new_port", 80, day + 90_000);
        d.cycle(&s, day + 90_100); // next day: unmuted
        assert_eq!(f.seen.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);
    }

    #[test]
    fn the_generic_webhook_is_signed_and_pagerduty_carries_its_key() {
        let f = fake();
        let (s, id) = world();
        let wh = from_body(&json!({"name": "siem", "kind": "webhook", "url": format!("{}/in", f.url), "secret": "0123456789abcdef0123", "min_score": 0}), None).unwrap();
        let pd = chan("pagerduty", &format!("{}/v2/enqueue", f.url));
        let (mut wh, mut pd) = (wh, pd);
        wh.id = "cw".into();
        pd.id = "cp".into();
        save(&s, &[wh, pd], 1).unwrap();
        let d = Dispatcher::new(Arc::default(), "denis-host".into(), Duration::ZERO);
        d.cycle(&s, 100);
        event(&s, id, "new_port", 95, 150);
        d.cycle(&s, 160);
        let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 2);
        let w = seen.iter().find(|x| x.0 == "/in").unwrap();
        let sig = w.1.iter().find(|(k, _)| k == "x-denis-signature").map(|(_, v)| v.clone()).unwrap();
        // the receiver recomputes the HMAC over the exact body it got
        assert_eq!(sig, format!("sha256={}", hmac_sha256_hex(b"0123456789abcdef0123", w.2.to_string().as_bytes())));
        let p = seen.iter().find(|x| x.0 == "/v2/enqueue").unwrap();
        assert_eq!((p.2["routing_key"].as_str(), p.2["payload"]["severity"].as_str(), p.2["payload"]["source"].as_str()), (Some("R0UTINGKEY12345"), Some("critical"), Some("denis-host")));
    }

    #[test]
    fn jira_files_one_issue_authenticated_and_the_summary_stays_under_the_field_limit() {
        let f = fake();
        let (s, id) = world();
        let mut ch = from_body(
            &json!({"name": "tix", "kind": "jira", "url": f.url, "user": "bot@example.com", "secret": "s3cr3t-api-token", "project": "OPS", "min_score": 0}),
            None,
        )
        .unwrap();
        ch.id = "cj".into();
        save(&s, std::slice::from_ref(&ch), 1).unwrap();
        let d = Dispatcher::new(Arc::default(), "denis-host".into(), Duration::ZERO);
        d.cycle(&s, 100);
        event(&s, id, "new_port", 80, 150);
        d.cycle(&s, 160);
        let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 1);
        let (path, headers, body) = &seen[0];
        assert_eq!(path, "/rest/api/3/issue");
        let auth = headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(auth, format!("Basic {}", crate::report::base64(b"bot@example.com:s3cr3t-api-token")));
        assert_eq!(body["fields"]["project"]["key"], "OPS");
        assert_eq!(body["fields"]["issuetype"]["name"], "Task");
        assert!(body["fields"]["summary"].as_str().unwrap().contains("new_port"));
        assert_eq!(body["fields"]["description"]["type"], "doc");
        assert!(body["fields"]["labels"].as_array().unwrap().iter().any(|l| l == "denis"));
        // a huge summary/reasons stays inside Jira's ~255-char summary field
        let mut big = notif("high", 95);
        big.summary = "x".repeat(5000);
        assert!(jira_payload(&big, "OPS")["fields"]["summary"].as_str().unwrap().chars().count() <= 255);
    }

    #[test]
    fn servicenow_files_one_incident_authenticated_with_a_correlation_id_for_dedup() {
        let f = fake();
        let (s, id) = world();
        let mut ch = from_body(&json!({"name": "sn", "kind": "servicenow", "url": f.url, "user": "denis-bot", "secret": "hunter2hunter2", "min_score": 0}), None).unwrap();
        ch.id = "csn".into();
        save(&s, std::slice::from_ref(&ch), 1).unwrap();
        let d = Dispatcher::new(Arc::default(), "denis-host".into(), Duration::ZERO);
        d.cycle(&s, 100);
        event(&s, id, "new_port", 95, 150);
        d.cycle(&s, 160);
        let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 1);
        let (path, headers, body) = &seen[0];
        assert_eq!(path, "/api/now/table/incident");
        let auth = headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(auth, format!("Basic {}", crate::report::base64(b"denis-bot:hunter2hunter2")));
        assert_eq!((body["urgency"].as_str(), body["impact"].as_str()), (Some("1"), Some("2")), "score 95 is high urgency");
        assert!(body["short_description"].as_str().unwrap().contains("new_port"));
        assert_eq!(body["correlation_id"], format!("denis-new_port-{id}"), "repeats of the same alert about the same device correlate in ServiceNow");
    }

    #[test]
    fn test_messages_and_email() {
        // e-mail against a tiny SMTP server: greeting, EHLO, MAIL, RCPT, DATA, QUIT
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let got = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut data = String::new();
            let mut r = std::io::BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            let mut in_data = false;
            let _ = c.write_all(b"220 test ESMTP\r\n");
            while std::io::BufRead::read_line(&mut r, &mut line).unwrap_or(0) > 0 {
                let l = line.trim_end().to_string();
                line.clear();
                if in_data {
                    if l == "." {
                        in_data = false;
                        let _ = c.write_all(b"250 queued\r\n");
                    } else {
                        data.push_str(&l);
                        data.push('\n');
                    }
                    continue;
                }
                let up = l.to_uppercase();
                let reply: &[u8] = if up.starts_with("EHLO") || up.starts_with("HELO") { b"250 test\r\n" }
                    else if up.starts_with("MAIL") || up.starts_with("RCPT") || up.starts_with("RSET") { b"250 ok\r\n" }
                    else if up.starts_with("DATA") { in_data = true; b"354 go\r\n" }
                    else if up.starts_with("QUIT") { let _ = c.write_all(b"221 bye\r\n"); break }
                    else { b"250 ok\r\n" };
                let _ = c.write_all(reply);
            }
            data
        });
        let ch = from_body(&json!({"name": "mail", "kind": "email", "smtp": {"host": "127.0.0.1", "port": port, "security": "none", "from": "DENIS <denis@example.com>", "to": ["admin@example.com"]}}), None).unwrap();
        send(&ch, &Notification::test(), "h", 1).unwrap();
        let mail = got.join().unwrap();
        assert!(mail.contains("Subject:") && mail.contains("DENIS test notification") && mail.contains("admin@example.com"), "{mail}");
        // a dead server is an error that names no secret
        let mut dead = ch.clone();
        dead.smtp.as_mut().unwrap().port = 1;
        assert!(send(&dead, &Notification::test(), "h", 1).is_err());
    }

    fn notif(severity: &str, score: i32) -> Notification {
        Notification {
            id: 1, kind: "new_port".into(), severity: severity.into(), score, ts: 1_000, summary: "camera opened port 23".into(), reasons: vec!["+40 new port".into()],
            advice: None, name: Some("cam".into()), ip: Some("10.0.0.5".into()), mac: None, site: None, asset_id: Some(1), test: false, details: json!({}),
        }
    }

    #[test]
    fn pushover_and_ntfy_are_validated_addressed_and_never_show_their_secrets() {
        let tok = "a".repeat(30);
        let usr = "u".repeat(30);
        let po = from_body(&json!({"name": "phone", "kind": "pushover", "secret": tok, "user": usr}), None).unwrap();
        let shown = po.masked().to_string();
        assert!(!shown.contains(&tok) && !shown.contains(&usr) && shown.contains("\"has_user\":true"), "{shown}");
        for bad in [
            json!({"name": "x", "kind": "pushover", "user": usr}),
            json!({"name": "x", "kind": "pushover", "secret": tok}),
            json!({"name": "x", "kind": "pushover", "secret": "short", "user": usr}),
            json!({"name": "x", "kind": "pushover", "secret": tok, "user": "not valid!!!!!!!!!!!!!!!!!!!!"}),
            json!({"name": "x", "kind": "pushover", "secret": tok, "user": usr, "url": "http://example.com/x"}),
            json!({"name": "x", "kind": "ntfy"}),
            json!({"name": "x", "kind": "ntfy", "url": "https://ntfy.sh"}),
            json!({"name": "x", "kind": "ntfy", "url": "https://ntfy.sh/bad topic"}),
            json!({"name": "x", "kind": "ntfy", "url": "https://ntfy.sh/topic?auth=x"}),
            json!({"name": "x", "kind": "ntfy", "url": "https://ntfy.sh/a/b/c d"}),
            json!({"name": "x", "kind": "ntfy", "url": "http://ntfy.lan/topic", "secret": "tk_abcdef"}),
        ] {
            assert!(from_body(&bad, None).is_err(), "{bad}");
        }
        assert!(from_body(&json!({"name": "x", "kind": "ntfy", "url": "http://ntfy.lan/topic"}), None).is_ok(), "a private server on http, without a token, is the owner's call");
        assert_eq!(ntfy_target("https://ntfy.sh/my-topic").unwrap(), ("https://ntfy.sh".to_string(), "my-topic".to_string()));
        assert_eq!(ntfy_target("https://ntfy.example.com:8443/sub/path/alerts_1/").unwrap(), ("https://ntfy.example.com:8443/sub/path".to_string(), "alerts_1".to_string()));
        // an error never contains the topic (it is the secret of a public server) or the keys
        let n = from_body(&json!({"name": "x", "kind": "ntfy", "url": "https://ntfy.sh/SecretTopicName", "secret": "tk_verysecrettoken"}), None).unwrap();
        assert!(!n.scrub("POST https://ntfy.sh/SecretTopicName failed, tk_verysecrettoken".into()).contains("SecretTopicName"));
        assert!(!po.scrub(format!("bad {tok} for {usr}")).contains(&tok));
    }

    #[test]
    fn pushover_and_ntfy_carry_severity_the_device_and_what_to_do() {
        let mut n = notif("high", 95);
        n.name = Some("cam \u{1F4F7} <b>1</b>".into());
        n.advice = Some("Isolate it.".into());
        let p = pushover_payload(&n, "TOKEN", "USER");
        assert_eq!((p["token"].as_str(), p["user"].as_str(), p["priority"].as_i64()), (Some("TOKEN"), Some("USER"), Some(1)));
        assert!(p["message"].as_str().unwrap().contains("Isolate it.") && p["message"].as_str().unwrap().contains("cam"));
        assert_eq!(pushover_payload(&notif("medium", 60), "T", "U")["priority"], 0);
        assert_eq!(pushover_payload(&notif("low", 35), "T", "U")["priority"], -1);
        let mut big = notif("high", 95);
        big.summary = "x".repeat(5000);
        assert!(pushover_payload(&big, "T", "U")["message"].as_str().unwrap().chars().count() <= 1024, "Pushover's limit");
        let t = ntfy_payload(&n, "alerts");
        assert_eq!((t["topic"].as_str(), t["priority"].as_i64(), t["tags"][0].as_str()), (Some("alerts"), Some(5), Some("rotating_light")));
        assert_eq!(ntfy_payload(&notif("medium", 60), "a")["priority"], 3);
        assert_eq!(ntfy_payload(&notif("low", 35), "a")["priority"], 2);
        assert!(ntfy_payload(&big, "a")["message"].as_str().unwrap().chars().count() <= 3900);
    }

    #[test]
    fn pushover_and_ntfy_deliver_to_the_service_and_ntfy_sends_its_token_as_a_bearer() {
        let f = fake();
        let (s, id) = world();
        let mut po = from_body(&json!({"name": "phone", "kind": "pushover", "secret": "a".repeat(30), "user": "u".repeat(30), "url": format!("{}/1/messages.json", f.url), "min_score": 0}), None).unwrap();
        let mut nt = from_body(&json!({"name": "topic", "kind": "ntfy", "url": format!("{}/my-topic", f.url), "min_score": 0}), None).unwrap();
        let mut nt2 = from_body(&json!({"name": "private", "kind": "ntfy", "url": format!("{}/sub/other", f.url), "secret": "tk_abc123", "min_score": 0}), None).unwrap();
        po.id = "cp".into();
        nt.id = "cn".into();
        nt2.id = "c2".into();
        save(&s, &[po, nt, nt2], 1).unwrap();
        let d = Dispatcher::new(Arc::default(), "denis-host".into(), Duration::ZERO);
        d.cycle(&s, 100);
        event(&s, id, "new_port", 95, 150);
        d.cycle(&s, 160);
        let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 3, "{:?}", seen.iter().map(|x| &x.0).collect::<Vec<_>>());
        let p = seen.iter().find(|x| x.0 == "/1/messages.json").unwrap();
        assert_eq!((p.2["priority"].as_i64(), p.2["user"].as_str().map(str::len)), (Some(1), Some(30)));
        let plain = seen.iter().find(|x| x.2["topic"] == "my-topic").unwrap();
        assert_eq!(plain.0, "/", "published as JSON to the server itself, the topic is in the body");
        assert!(!plain.1.iter().any(|(k, _)| k == "authorization"), "no token, no Authorization header");
        let private = seen.iter().find(|x| x.2["topic"] == "other").unwrap();
        assert_eq!(private.0, "/sub", "a server under a path keeps its path");
        assert_eq!(private.1.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.as_str()), Some("Bearer tk_abc123"));
    }
}
