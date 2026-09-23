//! Warns before a commercial license expires, then again once it is in its grace period —
//! delivered as ordinary alerts, attached to this install's own device (the one
//! `Observation::SelfHost` already creates), so they show up in Alerts/Health like anything else.
//!
//! This is not a per-device detection rule (`detect.rs`), so it runs its own small poll loop
//! instead: the license as a whole either is or is not close to expiring, independent of any
//! device. See `license::stage` for the actual 30-day-warning / 7-day-grace state machine.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::license::{self, Stage};
use crate::model::{Event, Mac};
use crate::notify::Alerts;
use crate::store::Store;

pub const RULE_LICENSE_EXPIRING: &str = "license_expiring";
pub const RULE_LICENSE_GRACE: &str = "license_grace_period";

const CHECK_EVERY: Duration = Duration::from_secs(300);

/// The last stage alerted on: re-checked every `CHECK_EVERY`, but only actually raises a new
/// alert when the stage has changed since (never repeats one every 5 minutes for weeks).
const LAST_STAGE_KEY: &str = "license_alerts.last_stage";

pub async fn run(store: Arc<dyn Store>, license_file: Option<PathBuf>, own_mac: Mac, alerts: Arc<Alerts>) {
    let mut tick = tokio::time::interval(CHECK_EVERY);
    loop {
        tick.tick().await;
        check_once(&store, license_file.as_deref(), own_mac, &alerts);
    }
}

fn check_once(store: &Arc<dyn Store>, license_file: Option<&std::path::Path>, own_mac: Mac, alerts: &Alerts) {
    let now = crate::model::now_ts();
    let eff = license::effective(&**store, license_file);
    let stage = license::stage(&eff, now);
    let key = stage_key(&stage);
    let last = store.get_setting(LAST_STAGE_KEY).ok().flatten().map(|b| String::from_utf8_lossy(&b).to_string());
    if last.as_deref() == Some(key) {
        return; // already alerted for this stage; nothing changed
    }
    let _ = store.set_setting(LAST_STAGE_KEY, key.as_bytes(), now);
    if let Some(event) = event_for(store, &stage, own_mac, now) {
        alerts.emit(vec![event]);
    }
}

fn stage_key(stage: &Stage) -> &'static str {
    match stage {
        Stage::Fine => "fine",
        Stage::ExpiringSoon { .. } => "expiring_soon",
        Stage::Grace { .. } => "grace",
        Stage::Expired => "expired",
    }
}

/// `None` for a stage that does not itself raise an alert: "fine" (nothing to say) and "expired"
/// (the console's Community-edition banner already says so continuously; a one-off alert would
/// just be noise once devices start disappearing from the list).
fn event_for(store: &Arc<dyn Store>, stage: &Stage, own_mac: Mac, now: i64) -> Option<Event> {
    let (kind, severity, score, summary) = match stage {
        Stage::ExpiringSoon { days_left } => (
            RULE_LICENSE_EXPIRING,
            "low",
            20,
            format!("the license expires in {days_left} day(s)"),
        ),
        Stage::Grace { days_left } => (
            RULE_LICENSE_GRACE,
            "medium",
            55,
            format!(
                "the license has expired; {days_left} day(s) left in the grace period before the console falls back to the Community edition"
            ),
        ),
        Stage::Fine | Stage::Expired => return None,
    };
    let asset = store.find_asset(None, &own_mac).ok()??;
    Some(Event {
        id: 0,
        agent_id: None,
        asset_id: asset.id,
        kind: kind.into(),
        timestamp: now,
        severity: severity.into(),
        score,
        acked: false,
        raw_details: serde_json::json!({ "summary": summary }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Asset;
    use crate::store::sqlite::SqliteStore;

    fn store_with_self_asset() -> (Arc<dyn Store>, Mac, i64) {
        let store = SqliteStore::open_in_memory().unwrap();
        let mac = Mac([0x02, 0, 0, 0, 0, 1]);
        let mut a = Asset::new(mac, crate::model::now_ts());
        store.save_asset(&mut a).unwrap();
        let id = a.id;
        (Arc::new(store), mac, id)
    }

    #[test]
    fn expiring_soon_raises_one_low_severity_alert_on_the_self_asset() {
        let (store, mac, id) = store_with_self_asset();
        let alerts = Alerts::new(store.clone(), None);
        let ev = event_for(&store, &Stage::ExpiringSoon { days_left: 10 }, mac, crate::model::now_ts()).expect("should alert");
        assert_eq!(ev.kind, RULE_LICENSE_EXPIRING);
        assert_eq!(ev.severity, "low");
        alerts.emit(vec![ev]);
        let stored = store.list_events(&crate::store::EventQuery { limit: 10, ..Default::default() }).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].kind, RULE_LICENSE_EXPIRING);
        assert_eq!(stored[0].asset_id, id);
    }

    #[test]
    fn grace_raises_a_higher_severity_alert_and_fine_or_expired_raise_none() {
        let (store, mac, _id) = store_with_self_asset();
        let now = crate::model::now_ts();
        let grace = event_for(&store, &Stage::Grace { days_left: 3 }, mac, now).expect("should alert");
        assert_eq!(grace.kind, RULE_LICENSE_GRACE);
        assert_eq!(grace.severity, "medium");
        assert!(event_for(&store, &Stage::Fine, mac, now).is_none());
        assert!(event_for(&store, &Stage::Expired, mac, now).is_none());
    }

    #[test]
    fn an_unknown_self_asset_is_skipped_rather_than_alerting_on_nothing() {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mac = Mac([0x02, 0, 0, 0, 0, 9]); // never saved
        assert!(event_for(&store, &Stage::ExpiringSoon { days_left: 1 }, mac, crate::model::now_ts()).is_none());
    }

    #[test]
    fn check_once_does_not_repeat_the_same_stage_but_does_notice_a_change() {
        let (store, mac, _id) = store_with_self_asset();
        let alerts = Alerts::new(store.clone(), None);
        // no license configured at all -> Community -> Stage::Fine, which never alerts
        check_once(&store, None, mac, &alerts);
        assert_eq!(store.get_setting(LAST_STAGE_KEY).unwrap().unwrap(), b"fine");
        assert!(store.list_events(&crate::store::EventQuery { limit: 10, ..Default::default() }).unwrap().is_empty());

        // pretend a previous run already saw "expiring_soon": re-checking now (still no license,
        // so still "fine") notices the change back to fine and updates the marker, quietly
        store.set_setting(LAST_STAGE_KEY, b"expiring_soon", 0).unwrap();
        check_once(&store, None, mac, &alerts);
        assert_eq!(store.get_setting(LAST_STAGE_KEY).unwrap().unwrap(), b"fine");

        // and a second check with nothing changed does nothing further (idempotent)
        check_once(&store, None, mac, &alerts);
        assert_eq!(store.get_setting(LAST_STAGE_KEY).unwrap().unwrap(), b"fine");
        assert!(store.list_events(&crate::store::EventQuery { limit: 10, ..Default::default() }).unwrap().is_empty());
    }
}
