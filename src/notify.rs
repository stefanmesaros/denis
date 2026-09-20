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
        for mut e in events {
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
    let text = format!("netscope {}", one_line(e));
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
}
