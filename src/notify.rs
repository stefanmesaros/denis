//! Alert delivery: persist every event, log alerts, and optionally POST them to
//! a webhook. The payload carries `text` (Slack-compatible) and `content`
//! (Discord-compatible) alongside the full event, so a stock incoming-webhook
//! URL works without a translation layer.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;

use crate::model::Event;
use crate::store::Store;

pub struct Alerts {
    store: Arc<dyn Store>,
    webhook: Option<(mpsc::Sender<Event>, i32)>,
}

impl Alerts {
    pub fn new(store: Arc<dyn Store>, webhook: Option<(mpsc::Sender<Event>, i32)>) -> Self {
        Alerts { store, webhook }
    }

    /// Persist, log and forward. Never fails the caller: an alerting problem
    /// must not stop detection.
    pub fn emit(&self, events: Vec<Event>) {
        for mut e in self.without_exceptions(events) {
            if let Err(err) = self.store.insert_event(&mut e) {
                tracing::error!("could not store {} event: {err:#}", e.kind);
                continue;
            }
            if e.severity == "info" {
                tracing::debug!("{}", one_line(&e));
                continue;
            }
            tracing::warn!("ALERT {}", one_line(&e));
            if let Some((tx, min)) = &self.webhook {
                if e.score >= *min && tx.try_send(e).is_err() {
                    tracing::warn!("webhook queue full; dropping an alert notification");
                }
            }
        }
    }
}

impl Alerts {
    /// Drop the alerts an administrator excepted (Rules → exceptions): a device, a device type, a tag
    /// or a network that a rule should stay quiet about. It looks at the device the alert is about and,
    /// for industrial alerts, at the sending device too. An alert that is dropped is not stored at all.
    fn without_exceptions(&self, events: Vec<Event>) -> Vec<Event> {
        if events.is_empty() {
            return events;
        }
        let Ok(o) = crate::rules::load(&*self.store) else { return events };
        if o.exceptions.is_empty() && o.min_scores.is_empty() {
            return events;
        }
        events
            .into_iter()
            .map(|mut e| {
                // a rule with its own minimum score: below it, the event is recorded but not raised
                if o.min_scores.get(&e.kind).is_some_and(|min| e.score < *min) {
                    e.severity = "info".into();
                }
                e
            })
            .filter(|e| {
                if o.exceptions.is_empty() {
                    return true;
                }
                let mut ids = vec![e.asset_id];
                ids.extend(e.raw_details["client_id"].as_i64());
                let people: Vec<(crate::model::Asset, Option<crate::model::AssetMeta>)> = ids
                    .into_iter()
                    .filter_map(|id| Some((self.store.get_asset(id).ok().flatten()?, self.store.get_meta(id).ok().flatten())))
                    .collect();
                let refs: Vec<(&crate::model::Asset, Option<&crate::model::AssetMeta>)> = people.iter().map(|(a, m)| (a, m.as_ref())).collect();
                let dropped = o.excepted(&e.kind, &refs);
                if dropped {
                    tracing::debug!("alert {} dropped by a rule exception", e.kind);
                }
                !dropped
            })
            .collect()
    }
}

pub fn one_line(e: &Event) -> String {
    format!(
        "[{} {}] {}: {}",
        e.severity.to_uppercase(),
        e.score,
        e.kind,
        e.raw_details["summary"].as_str().unwrap_or("")
    )
}

/// Spawn the delivery task. Retries transient failures a few times, then gives
/// up on that alert (it stays in the UI regardless).
pub fn spawn_webhook(url: String) -> mpsc::Sender<Event> {
    let (tx, mut rx) = mpsc::channel::<Event>(256);
    tokio::spawn(async move {
        while let Some(e) = rx.recv().await {
            for (attempt, wait) in [0u64, 2, 8].into_iter().enumerate() {
                tokio::time::sleep(Duration::from_secs(wait)).await;
                let (u, ev) = (url.clone(), e.clone());
                match tokio::task::spawn_blocking(move || deliver(&u, &ev)).await {
                    Ok(Ok(())) => break,
                    Ok(Err(err)) if attempt == 2 => {
                        tracing::warn!("webhook delivery failed for good: {err:#}");
                    }
                    Ok(Err(err)) => tracing::debug!("webhook attempt {} failed: {err:#}", attempt + 1),
                    Err(_) => break,
                }
            }
        }
    });
    tx
}

pub fn payload(e: &Event) -> serde_json::Value {
    let text = format!("denis {}", one_line(e));
    serde_json::json!({ "text": text, "content": text, "event": e })
}

pub fn deliver(url: &str, e: &Event) -> Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    agent
        .post(url)
        .send_json(payload(e))
        .with_context(|| "posting alert to webhook")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn event(score: i32) -> Event {
        Event {
            id: 1, agent_id: None, asset_id: 1, kind: "new_destination".into(), timestamp: 0,
            severity: crate::detect::severity_for(score, 30).into(), score, acked: false,
            raw_details: serde_json::json!({"summary": "First contact with 8.8.4.4"}),
        }
    }

    /// One-shot HTTP server that records the request and answers 200.
    fn capture_server() -> (String, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = s.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(idx) = text.find("\r\n\r\n") {
                    let len = text.to_lowercase().split("content-length: ").nth(1)
                        .and_then(|r| r.split("\r\n").next()).and_then(|n| n.trim().parse::<usize>().ok()).unwrap_or(0);
                    if buf.len() >= idx + 4 + len { break; }
                }
                if n == 0 { break; }
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            String::from_utf8_lossy(&buf).to_string()
        });
        (url, h)
    }

    #[test]
    fn webhook_payload_has_slack_and_discord_text_plus_the_event() {
        let (url, server) = capture_server();
        deliver(&url, &event(85)).unwrap();
        let req = server.join().unwrap();
        assert!(req.starts_with("POST /hook"), "{req}");
        let body: serde_json::Value = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["text"], body["content"]);
        assert!(body["text"].as_str().unwrap().contains("[HIGH 85] new_destination: First contact"));
        assert_eq!(body["event"]["score"], 85);
    }

    #[test]
    fn delivery_failure_is_an_error_not_a_panic() {
        // nothing listens on port 1
        assert!(deliver("http://127.0.0.1:1/x", &event(50)).is_err());
    }

    #[tokio::test]
    async fn emit_persists_everything_but_only_forwards_alerts_above_the_webhook_threshold() {
        let store: Arc<dyn Store> = Arc::new(crate::store::sqlite::SqliteStore::open_in_memory().unwrap());
        let mut a = crate::model::Asset::new(crate::model::Mac([2, 0, 0, 0, 0, 1]), 0);
        store.save_asset(&mut a).unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        let alerts = Alerts::new(store.clone(), Some((tx, 60)));
        let mk = |score| Event { asset_id: a.id, ..event(score) };
        alerts.emit(vec![mk(0), mk(45), mk(85)]);
        assert_eq!(store.list_events(&crate::store::EventQuery::default()).unwrap().len(), 3);
        assert_eq!(store.list_events(&crate::store::EventQuery { alerts_only: true, ..Default::default() }).unwrap().len(), 2);
        assert_eq!(rx.try_recv().unwrap().score, 85);
        assert!(rx.try_recv().is_err(), "45 is an alert but below the webhook threshold");
    }

    #[test]
    fn excepted_devices_types_tags_and_networks_are_not_alerted_but_everything_else_is() {
        use crate::model::{Asset, AssetMeta, IpRecord, Mac};
        use crate::store::sqlite::SqliteStore;
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mk = |n: u8, ty: &str, ip: [u8; 4]| {
            let mut a = Asset::new(Mac([2, 0, 0, 0, 0, n]), 1);
            a.device_type = ty.into();
            a.ip_history.push(IpRecord { ip: std::net::Ipv4Addr::from(ip), first_seen: 1, last_seen: 1 });
            store.save_asset(&mut a).unwrap();
            a
        };
        let (cam, printer, laptop, tagged) = (mk(1, "camera", [10, 0, 1, 5]), mk(2, "printer", [10, 0, 2, 5]), mk(3, "computer", [10, 0, 3, 5]), mk(4, "computer", [10, 0, 4, 5]));
        store.save_meta(tagged.id, &AssetMeta { tags: vec!["Lab".into()], ..Default::default() }, "test", 1).unwrap();
        let o = |v: serde_json::Value| {
            let mut o = crate::rules::Overrides::default();
            o.patch(&serde_json::json!({ "exceptions": v })).unwrap();
            crate::rules::save(&*store, &o, 1).unwrap();
        };
        let kind = "new_destination";
        let ev = |a: &Asset| {
            let mut e = event(50);
            e.asset_id = a.id;
            e.kind = kind.into();
            e
        };
        let alerts = Alerts::new(store.clone(), None);
        let stored = || store.list_events(&crate::store::EventQuery::default()).unwrap().len();
        // no exceptions: all four are stored
        alerts.emit(vec![ev(&cam), ev(&printer), ev(&laptop), ev(&tagged)]);
        assert_eq!(stored(), 4);
        // the camera by id, printers by type, the "lab" tag (any case), and the 10.0.3.0/24 network
        o(serde_json::json!({ kind: [
            {"kind": "device", "value": cam.id.to_string()}, {"kind": "type", "value": "PRINTER"},
            {"kind": "tag", "value": "lab"}, {"kind": "cidr", "value": "10.0.3.0/24"}] }));
        alerts.emit(vec![ev(&cam), ev(&printer), ev(&laptop), ev(&tagged)]);
        assert_eq!(stored(), 4, "all four are excepted, so nothing new is stored");
        // an exception for one rule does not silence another rule
        let mut other = ev(&cam);
        other.kind = "new_port".into();
        alerts.emit(vec![other]);
        assert_eq!(stored(), 5);
        // an OT alert about a server is dropped when its *sender* is excepted
        o(serde_json::json!({ "ot_control_command": [{"kind": "device", "value": laptop.id.to_string()}] }));
        let mut ot = ev(&cam);
        ot.kind = "ot_control_command".into();
        ot.raw_details = serde_json::json!({"summary": "x", "client_id": laptop.id});
        alerts.emit(vec![ot.clone()]);
        assert_eq!(stored(), 5, "the excepted sender's control command is not alerted");
        ot.raw_details = serde_json::json!({"summary": "x", "client_id": printer.id});
        alerts.emit(vec![ot]);
        assert_eq!(stored(), 6, "another sender still is");
    }

    #[test]
    fn a_rule_with_its_own_minimum_score_only_logs_what_falls_below_it() {
        use crate::store::sqlite::SqliteStore;
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut a = crate::model::Asset::new(crate::model::Mac([2, 0, 0, 0, 0, 1]), 1);
        store.save_asset(&mut a).unwrap();
        let mut o = crate::rules::Overrides::default();
        o.patch(&serde_json::json!({"min_scores": {"new_destination": 60}})).unwrap();
        crate::rules::save(&*store, &o, 1).unwrap();
        let alerts = Alerts::new(store.clone(), None);
        let mut low = event(50);
        low.asset_id = a.id;
        low.kind = "new_destination".into();
        let mut high = event(70);
        high.asset_id = a.id;
        high.kind = "new_destination".into();
        let mut other = event(50);
        other.asset_id = a.id;
        other.kind = "new_port".into();
        alerts.emit(vec![low, high, other]);
        let got = store.list_events(&crate::store::EventQuery::default()).unwrap();
        let sev = |kind: &str, score: i32| got.iter().find(|e| e.kind == kind && e.score == score).unwrap().severity.clone();
        assert_eq!(sev("new_destination", 50), "info", "a 50 under this rule's 60 is only logged");
        assert_ne!(sev("new_destination", 70), "info", "a score above the minimum is raised");
        assert_ne!(sev("new_port", 50), "info", "another rule is unaffected");
        // validation
        let mut o = crate::rules::Overrides::default();
        assert!(o.patch(&serde_json::json!({"min_scores": {"nope": 5}})).is_err() && o.patch(&serde_json::json!({"min_scores": {"new_port": 101}})).is_err());
        o.patch(&serde_json::json!({"min_scores": {"new_port": 5}})).unwrap();
        o.patch(&serde_json::json!({"min_scores": {"new_port": null}})).unwrap();
        assert!(o.min_scores.is_empty());
    }
}
