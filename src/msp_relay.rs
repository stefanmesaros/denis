//! Relay this install's own devices and alerts to an MSP's master (`denis run --report-to`), so
//! the MSP sees this site the same way they see an agent's — alongside every other customer,
//! each kept apart by site access (`access.rs`).
//!
//! # Design: bandwidth-conscious on purpose
//!
//! This is a *puller*, the same shape as the OpenObserve exporter (`sink.rs`), for the same
//! reasons: a slow or unreachable MSP never slows detection down, and delivery is at least once
//! (cursors live in the `settings` table, so a restart resumes where it stopped).
//!
//! What actually crosses the wire, each cycle:
//! * **Alerts**: only ones with `id` past a stored cursor — a handful at most, even for a large
//!   site, because alerts are inherently rare compared to devices. Already-scored Events, not raw
//!   signals: the MSP stores them as-is and does **not** re-run its own detection on them.
//! * **Devices**: only ones whose content actually changed since they were last sent (a hash
//!   comparison, ignoring volatile fields like `last_seen`) — *not* the whole register every
//!   cycle. A device that never changes is not resent until the periodic full resync. This is
//!   why 1000 devices does not mean 1000 devices' worth of traffic every cycle: in steady state
//!   it is proportional to how much actually changed, which is normally small.
//! * **Findings and compliance are never sent**: the MSP already has everything it needs to
//!   compute them itself, the same way it does for its own local devices, once the register is
//!   mirrored — sending them separately would be redundant.
//!
//! The default interval is 60 seconds, not the console's own 5-10 second UI refresh (which never
//! leaves the browser-to-local-master link) — alerts and device deltas do not need to be nearly
//! as fresh as a page you are looking at, and a longer interval means less WAN chatter.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Asset, AssetMeta, Event};
use crate::store::{Store};

pub const DEFAULT_INTERVAL_SECS: u64 = 60;
/// Devices are re-sent in full at least this often even if nothing changed, so the MSP's copy
/// never drifts silently (a missed delta, a restart between hash update and cursor save).
const FULL_SNAPSHOT_EVERY: i64 = 6 * 3600;
const BATCH: usize = 500;

#[derive(Clone)]
pub struct Upstream {
    /// The MSP's base URL, e.g. `https://msp.example.com:9000`.
    pub url: String,
    /// A token issued there (`denis agent-token issue`), read once from an environment
    /// variable — never on the command line, never logged.
    pub token: String,
    pub interval: Duration,
}

/// One relay payload: what changed since the last cycle (or everything, on a full resync).
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Sync {
    pub devices: Vec<DeviceDoc>,
    pub events: Vec<RelayedEvent>,
    /// True on a periodic full resync: the MSP does not need to infer "missing = deleted".
    pub full: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceDoc {
    pub asset: Asset,
    pub meta: AssetMeta,
}

/// An event, with the MAC of the device it is about: `event.asset_id` is this install's own
/// local numbering, meaningless to the MSP once relayed, so the MAC (the identity every install
/// already agrees on — see `Store::find_asset`) is how the MSP re-resolves it to its own id.
#[derive(Serialize, Deserialize, Clone)]
pub struct RelayedEvent {
    pub event: Event,
    pub mac: crate::model::Mac,
}

pub struct Relay {
    upstream: Upstream,
    agent: ureq::Agent,
    device_hashes: Mutex<HashMap<i64, u64>>,
    last_full_snapshot: Mutex<i64>,
}

impl Relay {
    pub fn new(upstream: Upstream) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(60))).http_status_as_error(false).build().into();
        Relay { upstream, agent, device_hashes: Mutex::new(HashMap::new()), last_full_snapshot: Mutex::new(0) }
    }

    fn cursor(store: &dyn Store) -> Result<i64> {
        Ok(store.get_setting("msp_relay.cursor.events")?.and_then(|b| String::from_utf8(b).ok()?.parse().ok()).unwrap_or(0))
    }

    fn set_cursor(store: &dyn Store, v: i64, now: i64) -> Result<()> {
        store.set_setting("msp_relay.cursor.events", v.to_string().as_bytes(), now)
    }

    fn hash_of(asset: &Asset, meta: &AssetMeta) -> u64 {
        let mut a = asset.clone();
        a.last_seen = 0; // volatile: would defeat the whole point of the hash comparison
        let mut h = DefaultHasher::new();
        (serde_json::to_string(&a).unwrap_or_default(), serde_json::to_string(meta).unwrap_or_default()).hash(&mut h);
        h.finish()
    }

    /// One relay cycle. Returns (devices sent, events sent).
    pub fn sync_once(&self, store: &dyn Store, now: i64) -> Result<(usize, usize)> {
        let assets = store.load_assets()?;
        let metas = store.load_all_meta()?;
        let full = now - *self.last_full_snapshot.lock().unwrap() >= FULL_SNAPSHOT_EVERY;
        let mut devices = Vec::new();
        {
            let hashes = self.device_hashes.lock().unwrap();
            for a in &assets {
                let meta = metas.get(&a.id).cloned().unwrap_or_default();
                let h = Self::hash_of(a, &meta);
                if full || hashes.get(&a.id) != Some(&h) {
                    devices.push((DeviceDoc { asset: a.clone(), meta }, a.id, h));
                }
            }
        }

        let mac_of: HashMap<i64, crate::model::Mac> = assets.iter().map(|a| (a.id, a.mac)).collect();
        let after = Self::cursor(store)?;
        let q = crate::store::EventQuery { limit: 5_000, alerts_only: true, ..Default::default() };
        let mut new_events: Vec<RelayedEvent> = store
            .list_events(&q)?
            .into_iter()
            .filter(|e| e.id > after)
            .filter_map(|e| mac_of.get(&e.asset_id).map(|&mac| RelayedEvent { event: e, mac }))
            .collect();
        new_events.sort_by_key(|r| r.event.id);

        let mut sent_devices = 0;
        let mut sent_events = 0;
        // devices, in bounded batches
        for chunk in devices.chunks(BATCH) {
            let payload = Sync { devices: chunk.iter().map(|(d, ..)| DeviceDoc { asset: d.asset.clone(), meta: d.meta.clone() }).collect(), events: vec![], full };
            self.post(&payload)?;
            let mut hashes = self.device_hashes.lock().unwrap();
            for (_, id, h) in chunk {
                hashes.insert(*id, *h);
            }
            sent_devices += chunk.len();
        }
        if full && !devices.is_empty() {
            *self.last_full_snapshot.lock().unwrap() = now;
        }
        // events, in bounded batches, cursor only moves after a batch is accepted
        for chunk in new_events.chunks(BATCH) {
            let payload = Sync { devices: vec![], events: chunk.to_vec(), full: false };
            self.post(&payload)?;
            if let Some(last) = chunk.last() {
                Self::set_cursor(store, last.event.id, now)?;
            }
            sent_events += chunk.len();
        }
        Ok((sent_devices, sent_events))
    }

    fn post(&self, payload: &Sync) -> Result<()> {
        let endpoint = format!("{}/api/v1/msp-sync", self.upstream.url.trim_end_matches('/'));
        let resp = self
            .agent
            .post(&endpoint)
            .header("Authorization", format!("Bearer {}", self.upstream.token))
            .send_json(payload)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let code = resp.status().as_u16();
        if !(200..300).contains(&code) {
            bail!("the MSP refused the sync (HTTP {code}): check --report-to and the token");
        }
        Ok(())
    }
}

/// Background task: relay devices and alerts to the MSP on a fixed interval.
pub async fn run(store: std::sync::Arc<dyn Store>, upstream: Upstream) {
    let interval = upstream.interval;
    let relay = std::sync::Arc::new(Relay::new(upstream));
    let mut last_err = String::new();
    loop {
        tokio::time::sleep(interval).await;
        let (r, s) = (relay.clone(), store.clone());
        let now = crate::model::now_ts();
        // ureq's blocking I/O belongs off the async executor, same as everywhere else in DENIS
        let result = match tokio::task::spawn_blocking(move || r.sync_once(&*s, now)).await {
            Ok(r) => r,
            Err(_) => return,
        };
        match result {
            Ok((d, e)) => {
                if !last_err.is_empty() {
                    tracing::info!("MSP relay recovered");
                    last_err.clear();
                }
                if d > 0 || e > 0 {
                    tracing::debug!("relayed {d} device(s) and {e} alert(s) to the MSP");
                }
            }
            Err(err) => {
                let msg = format!("{err:#}");
                if msg != last_err {
                    tracing::warn!("MSP relay failed (will retry): {msg}");
                    last_err = msg;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AssetStore;
    use crate::store::EventStore;
    use crate::model::{Mac, OpenPort};
    use crate::store::sqlite::SqliteStore;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A tiny fake MSP ingest endpoint: records every payload it receives.
    struct Fake {
        addr: std::net::SocketAddr,
        seen: std::sync::Arc<Mutex<Vec<(String, Sync)>>>,
    }

    fn fake_server() -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]);
                let auth = text.lines().find(|l| l.to_ascii_lowercase().starts_with("authorization:")).unwrap_or("").trim().to_string();
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("{}");
                if let Ok(payload) = serde_json::from_str::<Sync>(body) {
                    seen2.lock().unwrap().push((auth, payload));
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
            }
        });
        Fake { addr, seen }
    }

    fn asset(mac: Mac, id: i64) -> Asset {
        let mut a = Asset::new(mac, 10);
        a.id = id;
        a.open_ports = vec![OpenPort { port: 80, proto: "tcp".into(), service: None }];
        a
    }

    #[test]
    fn unchanged_devices_are_not_resent_and_new_alerts_go_out_by_cursor() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut a1 = asset(Mac([0x02, 0, 0, 0, 0, 1]), 0);
        store.save_asset(&mut a1).unwrap();
        let f = fake_server();
        let up = Upstream { url: format!("http://{}", f.addr), token: "tok123".into(), interval: Duration::from_secs(60) };
        let relay = Relay::new(up);

        let (d, e) = relay.sync_once(&store, 100).unwrap();
        assert_eq!((d, e), (1, 0), "first cycle sends the one device, no alerts yet");

        let (d, e) = relay.sync_once(&store, 200).unwrap();
        assert_eq!((d, e), (0, 0), "nothing changed: nothing resent");

        // a real change is sent again; an unrelated field like last_seen alone is not
        a1.last_seen = 999;
        store.save_asset(&mut a1).unwrap();
        let (d, _) = relay.sync_once(&store, 300).unwrap();
        assert_eq!(d, 0, "last_seen alone is not a real change");

        let mut a1_changed = a1.clone();
        a1_changed.device_type = "printer".into();
        store.save_asset(&mut a1_changed).unwrap();
        let (d, _) = relay.sync_once(&store, 400).unwrap();
        assert_eq!(d, 1, "a real change is sent");

        // an alert: sent once, not again on the next cycle (cursor moved)
        let mut ev = Event { id: 0, agent_id: None, asset_id: a1.id, kind: "new_device".into(), timestamp: 400, severity: "high".into(), score: 80, acked: false, raw_details: serde_json::json!({}) };
        store.insert_event(&mut ev).unwrap();
        let (_, e) = relay.sync_once(&store, 500).unwrap();
        assert_eq!(e, 1);
        let (_, e) = relay.sync_once(&store, 600).unwrap();
        assert_eq!(e, 0, "the alert is not resent once its cursor has moved past it");

        let all: Vec<_> = f.seen.lock().unwrap().clone();
        assert!(all.iter().all(|(auth, _)| auth == "authorization: Bearer tok123"));
    }

    #[test]
    fn a_failed_post_does_not_move_the_cursor_or_the_hash() {
        // port 9 (discard) refuses connections on virtually every system without needing a real fake server
        let up = Upstream { url: "http://127.0.0.1:9".into(), token: "x".into(), interval: Duration::from_secs(60) };
        let relay = Relay::new(up);
        let store = SqliteStore::open_in_memory().unwrap();
        let mut a1 = asset(Mac([0x02, 0, 0, 0, 0, 2]), 0);
        store.save_asset(&mut a1).unwrap();
        assert!(relay.sync_once(&store, 100).is_err());
        // nothing was recorded as sent, so a later successful cycle still sends it
        assert!(relay.device_hashes.lock().unwrap().is_empty());
    }
}
