//! Saved reports: made by hand or on a schedule, kept in the database, and viewed or
//! downloaded from the console at any time.
//!
//! A saved report is the same self-contained HTML page as the printable report, plus
//! the compliance overview, frozen at the moment it was made (that is the point: an
//! auditor can ask what the network looked like last quarter).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{ReportMeta, User};
use crate::store::Store;

/// The little slice of the running collector's status a compliance report needs — defined here,
/// not in `engine`, so this module names what it actually uses instead of depending on the whole
/// of `engine::Shared`. `engine::Shared` implements it.
pub trait ReportStatus {
    fn snapshot(&self) -> crate::engine::StatusInfo;
    fn detect_base(&self) -> Option<crate::detect::DetectConfig>;
}

impl<T: ReportStatus> ReportStatus for std::sync::Arc<T> {
    fn snapshot(&self) -> crate::engine::StatusInfo {
        (**self).snapshot()
    }
    fn detect_base(&self) -> Option<crate::detect::DetectConfig> {
        (**self).detect_base()
    }
}

pub const SETTINGS_KEY: &str = "reports";
/// Never keep more than this many scheduled reports, whatever is asked for.
pub const MAX_KEEP: u32 = 200;

/// Never e-mail more than this many recipients for one scheduled report.
const MAX_EMAIL_TO: usize = 20;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// `off`, `weekly` or `monthly`.
    pub schedule: String,
    /// How many scheduled reports to keep (older ones are removed; hand-made ones are never).
    pub keep: u32,
    /// The period each scheduled report covers.
    pub days: i64,
    /// Who to e-mail a share link to when a scheduled report is made. Empty (the default): nobody
    /// — it is only saved in the console, same as before this existed. Sent through whichever
    /// e-mail notification channel is enabled (Settings → Alerting); with none configured, the
    /// report still gets made and kept, just not mailed.
    #[serde(default)]
    pub email_to: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { schedule: "off".into(), keep: 12, days: 7, email_to: Vec::new() }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(self.schedule.as_str(), "off" | "weekly" | "monthly") {
            return Err("schedule must be off, weekly or monthly");
        }
        if !(1..=MAX_KEEP).contains(&self.keep) {
            return Err("keep must be between 1 and 200");
        }
        if !(1..=365).contains(&self.days) {
            return Err("days must be between 1 and 365");
        }
        if self.email_to.len() > MAX_EMAIL_TO {
            return Err("at most 20 e-mail addresses");
        }
        if self.email_to.iter().any(|a| a.parse::<lettre::message::Mailbox>().is_err()) {
            return Err("give only valid e-mail addresses");
        }
        Ok(())
    }

    /// Seconds between two scheduled reports.
    fn interval(&self) -> Option<i64> {
        match self.schedule.as_str() {
            "weekly" => Some(7 * 86_400),
            "monthly" => Some(30 * 86_400),
            _ => None,
        }
    }
}

pub fn load(store: &dyn Store) -> Result<Settings> {
    Ok(match store.get_setting(SETTINGS_KEY)? {
        Some(b) => serde_json::from_slice(&b).ok().filter(|s: &Settings| s.validate().is_ok()).unwrap_or_default(),
        None => Settings::default(),
    })
}

pub fn save(store: &dyn Store, s: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(s)?, now)
}

// --------------------------------------------------------------------------------- sharing

const SHARES_KEY: &str = "report_shares";

/// A saved report is otherwise only reachable by someone who can sign in. Sharing gives out a
/// long random token instead of the report's numeric id, so the link cannot be guessed or
/// enumerated; anyone who has the token can view (never edit or delete) that one report, without
/// an account. Kept in the generic settings store (`report_id -> token`) rather than a new
/// database column: the expected number of shared reports at once is small, and this needs no
/// migration.
pub fn load_shares(store: &dyn Store) -> Result<std::collections::HashMap<i64, String>> {
    Ok(store.get_setting(SHARES_KEY)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default())
}

fn save_shares(store: &dyn Store, shares: &std::collections::HashMap<i64, String>, now: i64) -> Result<()> {
    store.set_setting(SHARES_KEY, &serde_json::to_vec(shares)?, now)
}

/// The token this report is already shared under, if any.
pub fn share_token_of(store: &dyn Store, report_id: i64) -> Result<Option<String>> {
    Ok(load_shares(store)?.get(&report_id).cloned())
}

/// Start sharing a report (or return its existing token, so clicking "Share" twice does not
/// invalidate a link someone already has).
pub fn share(store: &dyn Store, report_id: i64, now: i64) -> Result<String> {
    let mut shares = load_shares(store)?;
    if let Some(t) = shares.get(&report_id) {
        return Ok(t.clone());
    }
    let token = crate::auth::random_token()?;
    shares.insert(report_id, token.clone());
    save_shares(store, &shares, now)?;
    Ok(token)
}

/// Stop sharing a report: the old link stops working immediately.
pub fn unshare(store: &dyn Store, report_id: i64, now: i64) -> Result<()> {
    let mut shares = load_shares(store)?;
    if shares.remove(&report_id).is_some() {
        save_shares(store, &shares, now)?;
    }
    Ok(())
}

/// Which report (if any) a share link's token names.
pub fn report_id_for_token(store: &dyn Store, token: &str) -> Result<Option<i64>> {
    Ok(load_shares(store)?.into_iter().find(|(_, t)| t == token).map(|(id, _)| id))
}

/// The compliance overview as of now (what the Compliance page shows).
pub fn compliance_now(store: &dyn Store, shared: &impl ReportStatus, now: i64) -> Result<crate::compliance::Report> {
    let info = shared.snapshot();
    let base = shared.detect_base().unwrap_or_default();
    let mut assets = store.load_assets()?;
    let metas = store.load_all_meta()?;
    let channels = crate::channels::load(store)?;
    let users = store.list_users()?;
    let overrides = crate::rules::load(store)?;
    let acceptances = store.list_risk_acceptances()?;
    // a second step: a passkey or an authenticator app
    let mut with_passkey = store.totp_enabled_users()?;
    for u in &users {
        if !store.list_passkeys(u.id)?.is_empty() {
            with_passkey.insert(u.id);
        }
    }
    for a in &mut assets {
        if let Some(m) = metas.get(&a.id) {
            crate::tracking::apply_overrides(a, m);
        }
    }
    let (open, accepted) = crate::findings::apply_acceptances(crate::findings::compute(&assets, &metas, now), &acceptances, now);
    let eff = overrides.apply(&base, now);
    let rules_enabled = crate::detect::RULES.iter().filter(|r| eff.weights.get(**r).copied().unwrap_or(1.0) > 0.0).count();
    let admins: Vec<&User> = users.iter().filter(|u| u.role == "admin" && !u.disabled).collect();
    let inputs = crate::compliance::Inputs {
        assets: &assets, metas: &metas, now,
        passive_discovery: true,
        active_discovery: !info.passive_only,
        traffic_analysis: info.flows_enabled,
        learning_finished: info.learning_ends_at.is_none_or(|t| t <= now),
        rules_enabled, rules_total: crate::detect::RULES.len(),
        channels_enabled: channels.iter().filter(|c| c.enabled).count(),
        exports_configured: info.exports.len(),
        users: users.len(), users_with_passkey: users.iter().filter(|u| with_passkey.contains(&u.id)).count(),
        admins: admins.len(), admins_with_mfa: admins.iter().filter(|u| with_passkey.contains(&u.id)).count(),
        high_findings: open.iter().filter(|f| f.severity == "high").count(),
        accepted_risks: accepted.iter().filter(|r| r.still_applies).count(),
    };
    Ok(crate::compliance::assess(&inputs))
}

/// Make a report and keep it. `kind` is `manual` or `scheduled`.
pub fn generate(store: &dyn Store, shared: &impl ReportStatus, kind: &str, days: i64, by: &str, now: i64) -> Result<ReportMeta> {
    let days = days.clamp(1, 365);
    let mut data = crate::report::gather(store, days, now)?;
    data.compliance = Some(compliance_now(store, shared, now)?);
    let html = crate::report::html(&data);
    let mut meta = ReportMeta {
        id: 0,
        kind: kind.into(),
        title: format!("{} report, {} day(s), {}", data.brand.product_name, days, crate::report::day(now)),
        period_days: days,
        created_at: now,
        created_by: by.into(),
        size: html.len() as i64,
    };
    meta.id = store.add_report(&meta, html.as_bytes()).context("saving the report")?;
    if kind == "scheduled" {
        let keep = load(store)?.keep as usize;
        store.prune_reports("scheduled", keep)?;
    }
    Ok(meta)
}

/// True when a scheduled report is due: the last one is older than the interval (or there is none).
pub fn is_due(s: &Settings, last_scheduled: Option<i64>, now: i64) -> bool {
    match s.interval() {
        None => false,
        Some(every) => last_scheduled.is_none_or(|t| now - t >= every),
    }
}

/// A link to a shared report, e-mailed to `settings.email_to` through whichever e-mail channel is
/// enabled — nothing is sent (and nothing is an error) when there are no recipients, no e-mail
/// channel, or no `public_url` to build a working link from.
fn email_report(store: &dyn Store, settings: &Settings, meta: &ReportMeta, public_url: Option<&str>, now: i64) -> Result<()> {
    if settings.email_to.is_empty() {
        return Ok(());
    }
    let Some(base) = public_url else {
        tracing::warn!("scheduled report: {} recipient(s) configured, but no --public-url is set, so no link can be sent", settings.email_to.len());
        return Ok(());
    };
    let Some(smtp) = crate::channels::load(store)?.into_iter().find(|c| c.enabled && c.kind == "email").and_then(|c| c.smtp) else {
        tracing::warn!("scheduled report: {} recipient(s) configured, but no e-mail channel is enabled (Settings → Alerting)", settings.email_to.len());
        return Ok(());
    };
    let token = share(store, meta.id, now)?;
    let link = format!("{}/api/reports/shared/{token}", base.trim_end_matches('/'));
    let subject = format!("[DENIS] {}", meta.title);
    let body = format!("Your scheduled DENIS report is ready:\n\n{link}\n\nThis link needs no sign-in. Settings → Reports turns scheduled e-mail off.");
    crate::channels::send_smtp(&smtp, &settings.email_to, &subject, &body)
}

/// Background task: once a while, make the scheduled report if one is due.
pub async fn run<S: ReportStatus + Send + Sync + 'static>(store: std::sync::Arc<dyn Store>, shared: std::sync::Arc<S>, public_url: Option<String>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
    // do not start before the collector has had a moment to look around
    tokio::time::sleep(std::time::Duration::from_secs(90)).await;
    loop {
        tick.tick().await;
        let (s, sh, url) = (store.clone(), shared.clone(), public_url.clone());
        let done = tokio::task::spawn_blocking(move || -> Result<Option<ReportMeta>> {
            let settings = load(&*s)?;
            let last = s.list_reports()?.iter().filter(|r| r.kind == "scheduled").map(|r| r.created_at).max();
            let now = crate::model::now_ts();
            if !is_due(&settings, last, now) {
                return Ok(None);
            }
            let meta = generate(&*s, &sh, "scheduled", settings.days, "schedule", now)?;
            if let Err(e) = email_report(&*s, &settings, &meta, url.as_deref(), now) {
                tracing::warn!("scheduled report: could not e-mail it: {e:#}");
            }
            Ok(Some(meta))
        })
        .await;
        match done {
            Ok(Ok(Some(m))) => tracing::info!("scheduled report saved: {}", m.title),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("scheduled report failed: {e:#}"),
            Err(e) => tracing::warn!("scheduled report task failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_gives_a_stable_token_that_resolves_back_and_can_be_revoked() {
        let store = crate::store::sqlite::SqliteStore::open_in_memory().unwrap();
        assert_eq!(share_token_of(&store, 1).unwrap(), None);
        let t1 = share(&store, 1, 1).unwrap();
        assert_eq!(share_token_of(&store, 1).unwrap(), Some(t1.clone()));
        // sharing again returns the same token, not a fresh one -- an existing link keeps working
        assert_eq!(share(&store, 1, 2).unwrap(), t1);
        assert_eq!(report_id_for_token(&store, &t1).unwrap(), Some(1));
        assert_eq!(report_id_for_token(&store, "no-such-token").unwrap(), None);
        // a second report gets its own, different token
        let t2 = share(&store, 2, 3).unwrap();
        assert_ne!(t1, t2);
        unshare(&store, 1, 4).unwrap();
        assert_eq!(share_token_of(&store, 1).unwrap(), None);
        assert_eq!(report_id_for_token(&store, &t1).unwrap(), None, "the old link stops working");
        assert_eq!(share_token_of(&store, 2).unwrap(), Some(t2), "unsharing one report leaves another alone");
    }

    #[test]
    fn schedule_is_due_after_its_interval() {
        let w = Settings { schedule: "weekly".into(), ..Default::default() };
        assert!(is_due(&w, None, 1000));
        assert!(!is_due(&w, Some(1000), 1000 + 6 * 86_400));
        assert!(is_due(&w, Some(1000), 1000 + 7 * 86_400));
        assert!(!is_due(&Settings::default(), None, 1000), "off never runs");
        let m = Settings { schedule: "monthly".into(), ..Default::default() };
        assert!(!is_due(&m, Some(0), 29 * 86_400));
        assert!(is_due(&m, Some(0), 30 * 86_400));
    }

    #[test]
    fn settings_are_validated() {
        assert!(Settings::default().validate().is_ok());
        assert!(Settings { schedule: "daily".into(), ..Default::default() }.validate().is_err());
        assert!(Settings { keep: 0, ..Default::default() }.validate().is_err());
        assert!(Settings { keep: 201, ..Default::default() }.validate().is_err());
        assert!(Settings { days: 0, ..Default::default() }.validate().is_err());
        assert!(Settings { days: 366, ..Default::default() }.validate().is_err());
        assert!(Settings { email_to: vec!["not-an-address".into()], ..Default::default() }.validate().is_err());
        assert!(Settings { email_to: vec!["a@example.com".into(); 21], ..Default::default() }.validate().is_err());
        assert!(Settings { email_to: vec!["ops@example.com".into(), "a@example.com".into()], ..Default::default() }.validate().is_ok());
    }

    fn report_meta(id: i64) -> ReportMeta {
        ReportMeta { id, kind: "scheduled".into(), title: "DENIS report, 7 day(s), 2026-09-25".into(), period_days: 7, created_at: 1, created_by: "schedule".into(), size: 10 }
    }

    #[test]
    fn no_recipients_no_public_url_or_no_email_channel_is_a_quiet_no_op() {
        let store = crate::store::sqlite::SqliteStore::open_in_memory().unwrap();
        // no recipients configured: nothing to do, not even a share
        email_report(&store, &Settings::default(), &report_meta(1), Some("https://denis.example.com"), 1).unwrap();
        assert_eq!(share_token_of(&store, 1).unwrap(), None);

        let with_to = Settings { email_to: vec!["ops@example.com".into()], ..Default::default() };
        // recipients, but no --public-url: warns and returns Ok, no share made (nothing useful to link to)
        email_report(&store, &with_to, &report_meta(2), None, 1).unwrap();
        assert_eq!(share_token_of(&store, 2).unwrap(), None);
        // recipients and a public URL, but no e-mail channel enabled: same, quietly does nothing
        email_report(&store, &with_to, &report_meta(3), Some("https://denis.example.com"), 1).unwrap();
        assert_eq!(share_token_of(&store, 3).unwrap(), None);
    }

    #[test]
    fn a_due_report_is_shared_and_mailed_with_a_working_link() {
        // a tiny SMTP server: greeting, EHLO, MAIL, RCPT, DATA, QUIT (same shape as channels.rs's own test)
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let got = std::thread::spawn(move || {
            use std::io::{BufRead, Write};
            let (mut c, _) = l.accept().unwrap();
            let mut data = String::new();
            let mut r = std::io::BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            let mut in_data = false;
            let _ = c.write_all(b"220 test ESMTP\r\n");
            while r.read_line(&mut line).unwrap_or(0) > 0 {
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

        let store = crate::store::sqlite::SqliteStore::open_in_memory().unwrap();
        let mut channels = crate::channels::load(&store).unwrap();
        let ch = crate::channels::from_body(
            &serde_json::json!({"name": "ops", "kind": "email", "smtp": {"host": "127.0.0.1", "port": port, "security": "none", "from": "DENIS <denis@example.com>", "to": ["fallback@example.com"]}}),
            None,
        )
        .unwrap();
        crate::channels::add(&mut channels, ch).unwrap();
        crate::channels::save(&store, &channels, 1).unwrap();

        let settings = Settings { email_to: vec!["a@example.com".into(), "b@example.com".into()], ..Default::default() };
        email_report(&store, &settings, &report_meta(9), Some("https://denis.example.com/"), 5).unwrap();

        let token = share_token_of(&store, 9).unwrap().expect("the report was shared so the link works");
        // the body is quoted-printable, which soft-wraps a long line with a trailing "=\n": undo just that
        let mail = got.join().unwrap().replace("=\r\n", "").replace("=\n", "");
        assert!(mail.contains(&format!("https://denis.example.com/api/reports/shared/{token}")), "{mail}");
        assert!(mail.contains("a@example.com") && mail.contains("b@example.com"), "mailed to the report's own recipients, not the channel's own To: {mail}");
        assert!(!mail.contains("fallback@example.com"), "{mail}");
        assert!(mail.contains("Subject:") && mail.contains(&report_meta(9).title), "{mail}");
    }
}
