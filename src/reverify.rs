//! Accepted risks do not rot: DENIS keeps looking at them.
//!
//! * A decision that is about to end is announced (14 days and 3 days before), and one that has ended
//!   is announced too: the finding counts again.
//! * Port findings are checked again once a day with a fresh scan of just those devices, so a fix is
//!   noticed without anyone pressing *Verify*.
//! * When the problem has gone away (fixed, switched off, the device left) that is written to the event
//!   log and the audit log, and the decision can be withdrawn. It is never withdrawn by itself: that is
//!   a person's call.
//!
//! The decision of *what to say* is a pure function ([`evaluate`]); the task around it only fetches,
//! scans, stores and sends.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::engine::Shared;
use crate::model::{now_ts, Asset, AssetMeta, Event, RiskAcceptance};
use crate::notify::Alerts;
use crate::store::Store;

pub const KIND_EXPIRING: &str = "risk_expiring";
pub const KIND_EXPIRED: &str = "risk_expired";
pub const KIND_GONE: &str = "risk_gone";

/// How many days before the end of a decision it is announced.
const WARN_DAYS: [i64; 2] = [14, 3];
/// A decision that ended longer ago than this is not announced (after a long stop, or an upgrade).
const EXPIRED_GRACE_SECS: i64 = 3 * 86_400;
/// How often the accepted port findings are scanned again.
const RECHECK_SECS: i64 = 86_400;
const STATE_KEY: &str = "reverify";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Marks {
    /// Which warnings were sent: `14`, `3`.
    pub warned: Vec<i64>,
    pub expired: bool,
    pub gone: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub marks: BTreeMap<i64, Marks>,
    pub last_recheck: i64,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub events: Vec<Event>,
    pub state: State,
    /// Devices to scan again now (`asset id`, address).
    pub rescan: Vec<(i64, Ipv4Addr)>,
}

#[allow(clippy::too_many_arguments)]
fn event(a: &Asset, kind: &str, severity: &str, score: i32, summary: String, acc: &RiskAcceptance, title: &str, now: i64) -> Event {
    Event {
        id: 0,
        agent_id: a.agent_id.clone(),
        asset_id: a.id,
        kind: kind.into(),
        timestamp: now,
        severity: severity.into(),
        score,
        acked: false,
        raw_details: serde_json::json!({
            "summary": summary,
            "finding": acc.finding_id,
            "title": title,
            "acceptance_id": acc.id,
            "accepted_by": acc.accepted_by,
            "reason": acc.reason,
            "expires_at": acc.expires_at,
        }),
    }
}

fn name(a: &Asset) -> String {
    let ip = a.current_ip().map(|i| i.to_string()).unwrap_or_default();
    let label = a.hostnames.first().cloned().or_else(|| a.vendor.clone()).unwrap_or_default();
    match (ip.is_empty(), label.is_empty()) {
        (false, false) => format!("{label} ({ip})"),
        (false, true) => ip,
        (true, false) => label,
        _ => format!("device #{}", a.id),
    }
}

/// What to say and do about the accepted risks, given the register as it is now. `assets` have their
/// manual corrections applied.
pub fn evaluate(assets: &[Asset], metas: &HashMap<i64, AssetMeta>, acceptances: &[RiskAcceptance], mut state: State, now: i64) -> Outcome {
    let open = crate::findings::compute(assets, metas, now);
    let mut events = Vec::new();
    let mut rescan = Vec::new();
    let recheck_due = now - state.last_recheck >= RECHECK_SECS;
    let live: std::collections::HashSet<i64> = acceptances.iter().map(|a| a.id).collect();
    state.marks.retain(|id, _| live.contains(id));
    for acc in acceptances {
        let Some(kind) = crate::findings::title_of(&acc.finding_id) else { continue };
        let Some(asset) = assets.iter().find(|a| a.id == acc.asset_id) else { continue };
        let marks = state.marks.entry(acc.id).or_default();
        let who = name(asset);
        if !acc.is_active(now) {
            // ended by itself: the finding counts again (if it is still true)
            let ended_at = acc.expires_at.unwrap_or(now);
            if !marks.expired && now - ended_at <= EXPIRED_GRACE_SECS {
                marks.expired = true;
                events.push(event(asset, KIND_EXPIRED, "low", 30, format!("The accepted risk \"{kind}\" on {who} has ended. It counts as a finding again: fix it, or accept it again with a new reason."), acc, kind, now));
            }
            continue;
        }
        let still = open.iter().any(|f| f.id == acc.finding_id && f.assets.contains(&acc.asset_id));
        if !still {
            if !marks.gone {
                marks.gone = true;
                events.push(event(asset, KIND_GONE, "info", 0, format!("The problem \"{kind}\" on {who} is gone. The decision to accept it can be withdrawn."), acc, kind, now));
            }
            continue;
        }
        // it came back after having gone: say so again when it goes next time
        marks.gone = false;
        if let Some(end) = acc.expires_at {
            let days_left = (end - now + 86_399) / 86_400;
            // the nearest threshold that has been crossed and not yet announced (the earlier ones count as announced)
            if let Some(&w) = WARN_DAYS.iter().rev().find(|w| days_left <= **w) {
                if !marks.warned.contains(&w) {
                    marks.warned.extend(WARN_DAYS.iter().copied().filter(|x| *x >= w));
                    let left = if days_left <= 1 { "less than a day".to_string() } else { format!("{days_left} days") };
                    events.push(event(asset, KIND_EXPIRING, "low", 30, format!("The accepted risk \"{kind}\" on {who} ends in {left}. Fix the problem, or renew the decision with a new reason."), acc, kind, now));
                }
            }
        }
        if recheck_due && crate::findings::is_scan_finding(&acc.finding_id) && !crate::fingerprint::is_ot_device(asset) {
            if let Some(ip) = asset.current_ip() {
                rescan.push((asset.id, ip));
            }
        }
    }
    if !rescan.is_empty() {
        state.last_recheck = now;
    }
    rescan.truncate(100);
    Outcome { events, state, rescan }
}

fn load_state(store: &dyn Store) -> State {
    store.get_setting(STATE_KEY).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// The register (with manual corrections applied), and the decisions about its findings.
type Register = (Vec<Asset>, HashMap<i64, AssetMeta>, Vec<RiskAcceptance>);

fn snapshot(store: &dyn Store) -> Result<Register> {
    let mut assets = store.load_assets()?;
    let metas = store.load_all_meta()?;
    for a in &mut assets {
        if let Some(m) = metas.get(&a.id) {
            crate::tracking::apply_overrides(a, m);
        }
    }
    Ok((assets, metas, store.list_risk_acceptances()?))
}

fn finish(store: &dyn Store, alerts: &Alerts, out: Outcome, now: i64) -> Result<()> {
    store.set_setting(STATE_KEY, &serde_json::to_vec(&out.state)?, now)?;
    for e in &out.events {
        let action = if e.kind == KIND_GONE { "risk.gone" } else if e.kind == KIND_EXPIRED { "risk.expired" } else { "risk.expiring" };
        let _ = store.add_audit(now, "system", action, Some(e.asset_id), &e.raw_details);
    }
    alerts.emit(out.events);
    Ok(())
}

/// Background task: look at the accepted risks once an hour.
pub async fn run(store: Arc<dyn Store>, shared: Arc<Shared>, alerts: Arc<Alerts>) {
    tokio::time::sleep(Duration::from_secs(180)).await;
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let s = store.clone();
        let first = tokio::task::spawn_blocking(move || -> Result<Outcome> {
            let (assets, metas, acc) = snapshot(&*s)?;
            Ok(evaluate(&assets, &metas, &acc, load_state(&*s), now_ts()))
        })
        .await;
        let mut out = match first {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => { tracing::warn!("re-checking accepted risks failed: {e:#}"); continue }
            Err(e) => { tracing::warn!("re-checking accepted risks failed: {e}"); continue }
        };
        if !out.rescan.is_empty() {
            // remember that we looked (also when this console cannot scan), then scan and let the register catch up
            let ips: Vec<Ipv4Addr> = out.rescan.iter().map(|(_, ip)| *ip).collect();
            let _ = store.set_setting(STATE_KEY, &serde_json::to_vec(&out.state).unwrap_or_default(), now_ts());
            if shared.rescan(ips).await.is_some() {
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            let s = store.clone();
            let carried = out.state.clone();
            let second = tokio::task::spawn_blocking(move || -> Result<Outcome> {
                let (assets, metas, acc) = snapshot(&*s)?;
                Ok(evaluate(&assets, &metas, &acc, carried, now_ts()))
            })
            .await;
            if let Ok(Ok(o)) = second {
                // the first pass's messages stay; the second adds what the fresh scan just proved (its marks carry on from the first)
                out.events.extend(o.events);
                out.state = o.state;
                out.rescan.clear();
            }
        }
        let (s, a) = (store.clone(), alerts.clone());
        let _ = tokio::task::spawn_blocking(move || finish(&*s, &a, out, now_ts())).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mac, OpenPort};

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn dev(id: i64, ty: &str, ports: &[u16]) -> Asset {
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, id as u8]), NOW - 1000);
        a.id = id;
        a.device_type = ty.into();
        a.vendor = Some("Acme".into());
        a.last_seen = NOW - 60;
        a.open_ports = ports.iter().map(|p| OpenPort { port: *p, proto: "tcp".into(), service: None }).collect();
        a.ip_history.push(crate::model::IpRecord { ip: Ipv4Addr::new(192, 168, 1, id as u8), first_seen: NOW - 1000, last_seen: NOW - 60 });
        a
    }

    fn accept(id: i64, asset: i64, finding: &str, expires_in_days: Option<f64>) -> RiskAcceptance {
        RiskAcceptance {
            id, finding_id: finding.into(), asset_id: asset, reason: "isolated VLAN".into(), accepted_by: "adam".into(), accepted_at: NOW - 10 * DAY,
            expires_at: expires_in_days.map(|d| NOW + (d * DAY as f64) as i64), revoked_at: None, revoked_by: None,
        }
    }

    fn kinds(o: &Outcome) -> Vec<&str> {
        o.events.iter().map(|e| e.kind.as_str()).collect()
    }

    #[test]
    fn a_decision_about_to_end_is_announced_twice_and_never_again() {
        let assets = vec![dev(1, "camera", &[23])];
        let none = HashMap::new();
        // 20 days left: nothing yet
        let o = evaluate(&assets, &none, &[accept(1, 1, "telnet_open", Some(20.0))], State { last_recheck: NOW, ..Default::default() }, NOW);
        assert!(o.events.is_empty());
        // 10 days left: the first warning, once
        let acc = [accept(1, 1, "telnet_open", Some(10.0))];
        let o = evaluate(&assets, &none, &acc, o.state, NOW);
        assert_eq!(kinds(&o), vec![KIND_EXPIRING]);
        assert!(o.events[0].raw_details["summary"].as_str().unwrap().contains("10 days"), "{:?}", o.events[0].raw_details);
        assert_eq!(o.events[0].severity, "low");
        let o = evaluate(&assets, &none, &acc, o.state, NOW + DAY);
        assert!(o.events.is_empty(), "the same warning is not repeated");
        // 2 days left: the second one
        let acc = [accept(1, 1, "telnet_open", Some(2.0))];
        let o = evaluate(&assets, &none, &acc, o.state, NOW);
        assert_eq!(kinds(&o), vec![KIND_EXPIRING]);
        let o = evaluate(&assets, &none, &acc, o.state, NOW);
        assert!(o.events.is_empty());
        // a decision that never ends is never announced
        let o = evaluate(&assets, &none, &[accept(2, 1, "telnet_open", None)], State { last_recheck: NOW, ..Default::default() }, NOW);
        assert!(o.events.is_empty());
    }

    #[test]
    fn going_straight_to_two_days_left_sends_one_warning_not_two() {
        let assets = vec![dev(1, "camera", &[23])];
        let o = evaluate(&assets, &HashMap::new(), &[accept(1, 1, "telnet_open", Some(2.0))], State { last_recheck: NOW, ..Default::default() }, NOW);
        assert_eq!(kinds(&o), vec![KIND_EXPIRING]);
        assert_eq!(o.state.marks[&1].warned.len(), 2, "the 14-day warning counts as given");
    }

    #[test]
    fn an_ended_decision_is_announced_once_unless_it_ended_long_ago() {
        let assets = vec![dev(1, "camera", &[23])];
        let none = HashMap::new();
        let recent = [accept(1, 1, "telnet_open", Some(-0.1))];
        let o = evaluate(&assets, &none, &recent, State { last_recheck: NOW, ..Default::default() }, NOW);
        assert_eq!(kinds(&o), vec![KIND_EXPIRED]);
        assert!(evaluate(&assets, &none, &recent, o.state, NOW).events.is_empty());
        let old = [accept(2, 1, "telnet_open", Some(-30.0))];
        assert!(evaluate(&assets, &none, &old, State { last_recheck: NOW, ..Default::default() }, NOW).events.is_empty(), "after a long stop, do not announce the past");
    }

    #[test]
    fn a_problem_that_is_gone_is_noted_once_and_again_if_it_comes_back_and_goes() {
        let none = HashMap::new();
        let acc = [accept(1, 1, "telnet_open", Some(60.0))];
        let base = State { last_recheck: NOW, ..Default::default() };
        let o = evaluate(&[dev(1, "camera", &[])], &none, &acc, base, NOW);
        assert_eq!(kinds(&o), vec![KIND_GONE]);
        assert_eq!(o.events[0].severity, "info", "a log entry, not an alert");
        let o = evaluate(&[dev(1, "camera", &[])], &none, &acc, o.state, NOW);
        assert!(o.events.is_empty());
        // it comes back: nothing to say (the decision still covers it) ...
        let o = evaluate(&[dev(1, "camera", &[23])], &none, &acc, o.state, NOW);
        assert!(o.events.is_empty());
        // ... and when it goes again, it is said again
        let o = evaluate(&[dev(1, "camera", &[])], &none, &acc, o.state, NOW);
        assert_eq!(kinds(&o), vec![KIND_GONE]);
        // a device that left the register entirely says nothing (there is no device to speak about)
        assert!(evaluate(&[], &none, &acc, State::default(), NOW).events.is_empty());
    }

    #[test]
    fn open_ports_are_scanned_again_once_a_day_and_industrial_devices_never() {
        let assets = vec![dev(1, "camera", &[23]), dev(2, "plc", &[23]), dev(3, "camera", &[])];
        let none = HashMap::new();
        let acc = [accept(1, 1, "telnet_open", Some(90.0)), accept(2, 2, "telnet_open", Some(90.0)), accept(3, 3, "unreviewed_device", Some(90.0))];
        let o = evaluate(&assets, &none, &acc, State::default(), NOW);
        assert_eq!(o.rescan, vec![(1, Ipv4Addr::new(192, 168, 1, 1))], "one device; the PLC is never probed, and a register finding needs no scan");
        assert_eq!(o.state.last_recheck, NOW);
        assert!(evaluate(&assets, &none, &acc, o.state.clone(), NOW + DAY - 1).rescan.is_empty(), "not again within a day");
        assert_eq!(evaluate(&assets, &none, &acc, o.state, NOW + DAY).rescan.len(), 1);
    }

    #[test]
    fn marks_of_withdrawn_decisions_are_forgotten() {
        let assets = vec![dev(1, "camera", &[23])];
        let mut st = State { last_recheck: NOW, ..Default::default() };
        st.marks.insert(99, Marks { gone: true, ..Default::default() });
        let o = evaluate(&assets, &HashMap::new(), &[accept(1, 1, "telnet_open", Some(60.0))], st, NOW);
        assert!(!o.state.marks.contains_key(&99));
    }

    #[test]
    fn finishing_stores_the_events_the_state_and_an_audit_line() {
        use crate::store::sqlite::SqliteStore;
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut a = dev(1, "camera", &[]);
        a.id = 0;
        store.save_asset(&mut a).unwrap();
        let alerts = Alerts::new(store.clone(), None);
        let out = evaluate(&[a.clone()], &HashMap::new(), &[accept(7, a.id, "telnet_open", Some(60.0))], State { last_recheck: NOW, ..Default::default() }, NOW);
        assert_eq!(kinds(&out), vec![KIND_GONE]);
        finish(&*store, &alerts, out, NOW).unwrap();
        let events = store.list_events(&crate::store::EventQuery { limit: 10, ..Default::default() }).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!((events[0].kind.as_str(), events[0].severity.as_str()), (KIND_GONE, "info"));
        assert!(store.list_audit(None, 10).unwrap().iter().any(|e| e.action == "risk.gone" && e.user == "system"));
        assert!(load_state(&*store).marks[&7].gone, "the state is kept, so the same thing is not said again");
    }
}
