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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// `off`, `weekly` or `monthly`.
    pub schedule: String,
    /// How many scheduled reports to keep (older ones are removed; hand-made ones are never).
    pub keep: u32,
    /// The period each scheduled report covers.
    pub days: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { schedule: "off".into(), keep: 12, days: 7 }
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
    let eff = overrides.apply(&base);
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

/// Background task: once a while, make the scheduled report if one is due.
pub async fn run<S: ReportStatus + Send + Sync + 'static>(store: std::sync::Arc<dyn Store>, shared: std::sync::Arc<S>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
    // do not start before the collector has had a moment to look around
    tokio::time::sleep(std::time::Duration::from_secs(90)).await;
    loop {
        tick.tick().await;
        let (s, sh) = (store.clone(), shared.clone());
        let done = tokio::task::spawn_blocking(move || -> Result<Option<ReportMeta>> {
            let settings = load(&*s)?;
            let last = s.list_reports()?.iter().filter(|r| r.kind == "scheduled").map(|r| r.created_at).max();
            let now = crate::model::now_ts();
            if !is_due(&settings, last, now) {
                return Ok(None);
            }
            generate(&*s, &sh, "scheduled", settings.days, "schedule", now).map(Some)
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
    }
}
