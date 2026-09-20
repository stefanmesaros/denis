//! Rule-based anomaly detection over per-device baselines.
//!
//! Deliberately not ML: three rules whose reasoning can be shown to a
//! non-security reader. Each produces a 0-100 *score* with the list of factors
//! that built it; a per-rule weight scales it, so a noisy rule can be turned
//! down without being disabled, and `min_score` decides what becomes an alert.
//!
//! Time is always passed in, never read, so behaviour is fully testable.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::Result;
use serde_json::json;

use crate::model::{
    proto_name, Asset, Baseline, DestStat, Event, FlowRecord, Mac, PROTO_ICMP,
};
use crate::store::Store;

pub const RULE_NEW_DEVICE: &str = "new_device";
pub const RULE_NEW_DESTINATION: &str = "new_destination";
pub const RULE_VOLUME: &str = "volume_anomaly";

/// Ports that carry so much ordinary traffic that "first time on 443" says nothing.
const COMMON_PORTS: &[u16] = &[53, 80, 123, 443, 465, 587, 853, 993, 5228];

/// Volume statistics forget after roughly this many buckets (~1 day at 5 min).
const VOLUME_WINDOW: u32 = 288;

#[derive(Clone, Debug)]
pub struct DetectConfig {
    /// A device (or a whole newly enrolled site) is only judged once it has been
    /// observed this long; until then everything it does is simply learned.
    pub learning_secs: i64,
    pub bucket_secs: i64,
    /// Wait this long after a bucket ends for late flow reports.
    pub grace_secs: i64,
    /// A new device is scored after this delay, once fingerprinting had a chance.
    pub settle_secs: i64,
    /// Scores below this are logged as `info`, not raised as alerts.
    pub min_score: i32,
    /// Per-rule multiplier on the score (default 1.0; 0 disables the rule).
    pub weights: HashMap<String, f64>,
    /// Minimum gap between two volume alerts for the same device.
    pub cooldown_secs: i64,
    pub z_threshold: f64,
    /// Buckets smaller than this are never anomalous, however unusual.
    pub min_volume_bytes: u64,
    /// Samples needed before a device's volume baseline is trusted.
    pub min_samples: u32,
    pub max_destinations: usize,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            learning_secs: 24 * 3600,
            bucket_secs: 300,
            grace_secs: 30,
            settle_secs: 60,
            min_score: 30,
            weights: HashMap::new(),
            cooldown_secs: 3600,
            z_threshold: 3.0,
            min_volume_bytes: 5_000_000,
            min_samples: 12,
            max_destinations: 2000,
        }
    }
}

impl DetectConfig {
    fn weighted(&self, rule: &str, raw: i32) -> i32 {
        let w = self.weights.get(rule).copied().unwrap_or(1.0);
        (raw as f64 * w).round().clamp(0.0, 100.0) as i32
    }
}

pub fn severity_for(score: i32, min_score: i32) -> &'static str {
    match score {
        s if s < min_score || s <= 0 => "info",
        s if s >= 70 => "high",
        s if s >= 50 => "medium",
        _ => "low",
    }
}

struct PendingNew {
    asset_id: i64,
    queued_at: i64,
}

pub struct Detector {
    cfg: DetectConfig,
    baselines: HashMap<i64, Baseline>,
    dirty: HashSet<i64>,
    /// remote address -> assets that have contacted it (for "nobody else has").
    global_dests: HashMap<Ipv4Addr, HashSet<i64>>,
    /// (asset, bucket start) -> outbound bytes so far.
    buckets: HashMap<(i64, i64), u64>,
    cooldown: HashMap<(i64, &'static str), i64>,
    learning_start: HashMap<Option<String>, i64>,
    default_learning_start: i64,
    pending_new: Vec<PendingNew>,
    ids: HashMap<(Option<String>, Mac), i64>,
}

impl Detector {
    pub fn new(cfg: DetectConfig, baselines: Vec<Baseline>, now: i64) -> Self {
        let mut d = Detector {
            cfg,
            baselines: HashMap::new(),
            dirty: HashSet::new(),
            global_dests: HashMap::new(),
            buckets: HashMap::new(),
            cooldown: HashMap::new(),
            learning_start: HashMap::new(),
            default_learning_start: now,
            pending_new: Vec::new(),
            ids: HashMap::new(),
        };
        for b in baselines {
            for k in b.typical_destinations.keys() {
                if let Ok(ip) = k.parse() {
                    d.global_dests.entry(ip).or_default().insert(b.asset_id);
                }
            }
            d.baselines.insert(b.asset_id, b);
        }
        d
    }

    pub fn config(&self) -> &DetectConfig {
        &self.cfg
    }

    pub fn baseline(&self, asset_id: i64) -> Option<&Baseline> {
        self.baselines.get(&asset_id)
    }

    /// When observation of this collector began. Only ever moves earlier, so
    /// restarts don't reopen the learning period.
    pub fn set_learning_start(&mut self, agent: Option<&str>, ts: i64) {
        let e = self
            .learning_start
            .entry(agent.map(str::to_string))
            .or_insert(ts);
        *e = (*e).min(ts);
    }

    fn learning_start(&self, agent: Option<&str>) -> i64 {
        self.learning_start
            .get(&agent.map(str::to_string))
            .copied()
            .unwrap_or(self.default_learning_start)
    }

    // ------------------------------------------------------------ new device

    /// Called once when an asset is first stored. During the learning period it
    /// only logs; afterwards it queues the device for scoring in `tick`.
    pub fn on_new_asset(&mut self, a: &Asset, now: i64) -> Vec<Event> {
        let start = self.learning_start(a.agent_id.as_deref());
        if a.first_seen - start < self.cfg.learning_secs {
            let details = new_device_details(a, &["joined during the initial learning period".into()]);
            return vec![make_event(a, RULE_NEW_DEVICE, 0, "info", details, now)];
        }
        self.pending_new.push(PendingNew {
            asset_id: a.id,
            queued_at: now,
        });
        Vec::new()
    }

    fn score_new_device(&self, a: &Asset) -> (i32, Vec<String>) {
        let mut score = 50;
        let mut why = vec!["+50 a device not seen before joined the network".to_string()];
        if a.device_type == "unknown" {
            score += 15;
            why.push("+15 device type could not be identified".into());
        }
        if a.randomized_mac {
            score -= 15;
            why.push("-15 private MAC address (typical of phones/laptops rejoining)".into());
        } else if a.vendor.is_none() {
            score += 10;
            why.push("+10 manufacturer not in the IEEE registry".into());
        }
        (self.cfg.weighted(RULE_NEW_DEVICE, score.clamp(0, 100)), why)
    }

    // --------------------------------------------------------------- flows

    fn asset_id(&mut self, agent: Option<&str>, mac: &Mac, store: &dyn Store) -> Option<i64> {
        let key = (agent.map(str::to_string), *mac);
        if let Some(id) = self.ids.get(&key) {
            return Some(*id);
        }
        let id = store.find_asset(agent, mac).ok()??.id;
        self.ids.insert(key, id);
        Some(id)
    }

    /// Fold a batch of flow windows into baselines; returns alerts for
    /// destinations the device has never contacted before.
    pub fn ingest_flows(
        &mut self,
        agent: Option<&str>,
        flows: &[FlowRecord],
        store: &dyn Store,
        now: i64,
    ) -> Vec<Event> {
        let mut by_mac: BTreeMap<Mac, Vec<&FlowRecord>> = BTreeMap::new();
        for f in flows {
            by_mac.entry(f.mac).or_default().push(f);
        }
        let mut events = Vec::new();
        for (mac, recs) in by_mac {
            // Traffic from a device we have not (yet) stored is dropped: it
            // will be recorded as soon as discovery has created the asset.
            let Some(asset_id) = self.asset_id(agent, &mac, store) else {
                continue;
            };
            if let Some((score, details)) = self.ingest_asset(asset_id, &recs, now) {
                if let Ok(Some(asset)) = store.get_asset(asset_id) {
                    let sev = severity_for(score, self.cfg.min_score);
                    events.push(make_event(&asset, RULE_NEW_DESTINATION, score, sev, details, now));
                }
            }
        }
        if self.global_dests.len() > 200_000 {
            self.global_dests.clear(); // only weakens a scoring bonus
        }
        events
    }

    fn ingest_asset(
        &mut self,
        asset_id: i64,
        recs: &[&FlowRecord],
        now: i64,
    ) -> Option<(i32, serde_json::Value)> {
        let first_ts = recs.iter().map(|r| r.window_start).min()?;
        let b = self
            .baselines
            .entry(asset_id)
            .or_insert_with(|| Baseline::new(asset_id, first_ts));
        b.observed_since = b.observed_since.min(first_ts);

        let mut fresh: Vec<(i32, Vec<String>, &FlowRecord)> = Vec::new();
        for r in recs {
            let key = r.remote.to_string();
            let mature = r.window_start - b.observed_since >= self.cfg.learning_secs;
            if mature && !b.typical_destinations.contains_key(&key) {
                let (raw, why) = score_new_destination(b, &self.global_dests, asset_id, r);
                fresh.push((raw, why, r));
            }
            let e = b.typical_destinations.entry(key).or_insert(DestStat {
                first_seen: r.window_start,
                last_seen: r.window_start,
                bytes: 0,
            });
            e.last_seen = e.last_seen.max(r.window_start);
            e.bytes += r.bytes_out + r.bytes_in;
            *b.typical_ports
                .entry(format!("{}/{}", proto_name(r.proto), r.port))
                .or_default() += 1;
            self.global_dests.entry(r.remote).or_default().insert(asset_id);

            let start = r.window_start / self.cfg.bucket_secs * self.cfg.bucket_secs;
            *self.buckets.entry((asset_id, start)).or_default() += r.bytes_out;
        }
        b.updated_at = now;
        // Bound memory: forget the least recently used destinations.
        while b.typical_destinations.len() > self.cfg.max_destinations {
            let oldest = b
                .typical_destinations
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())?;
            b.typical_destinations.remove(&oldest);
        }
        self.dirty.insert(asset_id);

        if fresh.is_empty() {
            return None;
        }
        fresh.sort_by_key(|(s, _, _)| -s);
        let count = fresh.len() as i32;
        let (top, top_why, _) = &fresh[0];
        let mut reasons = top_why.clone();
        let extra = (count - 1).min(10);
        if extra > 0 {
            reasons.push(format!("+{extra} {} other new destinations in the same window", count - 1));
        }
        let score = self.cfg.weighted(RULE_NEW_DESTINATION, (top + extra).clamp(0, 100));
        if score < self.cfg.min_score {
            return None;
        }
        let dests: Vec<_> = fresh
            .iter()
            .take(10)
            .map(|(s, why, r)| {
                json!({
                    "ip": r.remote, "proto": proto_name(r.proto), "port": r.port,
                    "bytes_out": r.bytes_out, "bytes_in": r.bytes_in, "score": s, "reasons": why,
                })
            })
            .collect();
        let first = fresh[0].2;
        Some((
            score,
            json!({
                "summary": format!(
                    "First contact with {} ({}/{}){}",
                    first.remote,
                    proto_name(first.proto),
                    first.port,
                    if count > 1 { format!(" and {} more", count - 1) } else { String::new() }
                ),
                "count": count,
                "destinations": dests,
                "reasons": reasons,
            }),
        ))
    }

    // ----------------------------------------------------------------- tick

    /// Periodic work: score settled new devices and close finished volume buckets.
    pub fn tick(&mut self, store: &dyn Store, now: i64) -> Vec<Event> {
        let mut events = Vec::new();

        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_new)
            .into_iter()
            .partition(|p| now - p.queued_at >= self.cfg.settle_secs);
        self.pending_new = later;
        for p in due {
            // Re-read: fingerprinting has usually filled in more by now.
            if let Ok(Some(a)) = store.get_asset(p.asset_id) {
                let (score, why) = self.score_new_device(&a);
                let sev = severity_for(score, self.cfg.min_score);
                events.push(make_event(&a, RULE_NEW_DEVICE, score, sev, new_device_details(&a, &why), now));
            }
        }

        let mut closing: Vec<(i64, i64)> = self
            .buckets
            .keys()
            .filter(|(_, start)| now >= start + self.cfg.bucket_secs + self.cfg.grace_secs)
            .copied()
            .collect();
        closing.sort_by_key(|(id, start)| (*start, *id));
        for key in closing {
            let bytes = self.buckets.remove(&key).unwrap_or(0);
            if let Some((score, details)) = self.close_bucket(key.0, key.1, bytes, now) {
                if let Ok(Some(a)) = store.get_asset(key.0) {
                    let sev = severity_for(score, self.cfg.min_score);
                    events.push(make_event(&a, RULE_VOLUME, score, sev, details, now));
                }
            }
        }
        self.cooldown.retain(|_, t| now - *t < self.cfg.cooldown_secs);
        events
    }

    fn close_bucket(
        &mut self,
        asset_id: i64,
        start: i64,
        bytes: u64,
        now: i64,
    ) -> Option<(i32, serde_json::Value)> {
        let cfg = &self.cfg;
        let b = self
            .baselines
            .entry(asset_id)
            .or_insert_with(|| Baseline::new(asset_id, start));
        let mature = start - b.observed_since >= cfg.learning_secs;
        let x = bytes as f64;
        let v = &b.volume;
        let mut alert = None;
        let mut learn_x = x;

        if mature && v.n >= cfg.min_samples && bytes >= cfg.min_volume_bytes {
            // Std-dev floors stop a very regular device (variance ~ 0) from
            // alerting on trivial changes.
            let floor = v.var.sqrt().max(0.25 * v.mean).max(1_000_000.0);
            let z = (x - v.mean) / floor;
            if z >= cfg.z_threshold {
                // An incident must not become the new normal.
                learn_x = v.mean + cfg.z_threshold * floor;
                let in_cooldown = self
                    .cooldown
                    .get(&(asset_id, RULE_VOLUME))
                    .is_some_and(|t| now - *t < cfg.cooldown_secs);
                let raw = (40.0 + (z - cfg.z_threshold) * 10.0).clamp(0.0, 100.0) as i32;
                let score = cfg.weighted(RULE_VOLUME, raw);
                if !in_cooldown && score >= cfg.min_score {
                    let mb = |v: f64| v / 1e6;
                    alert = Some((
                        score,
                        json!({
                            "summary": format!(
                                "{:.1} MB sent outside in {}; typical is {:.1} MB",
                                mb(x), duration(cfg.bucket_secs), mb(v.mean)
                            ),
                            "bytes_out": bytes, "bucket_start": start, "bucket_secs": cfg.bucket_secs,
                            "mean": v.mean, "std": v.var.sqrt(), "z": z,
                            "reasons": [format!(
                                "z-score {z:.1} against this device's own baseline (mean {:.1} MB, floor {:.1} MB, {} samples)",
                                mb(v.mean), mb(floor), v.n
                            )],
                        }),
                    ));
                    self.cooldown.insert((asset_id, RULE_VOLUME), now);
                }
            }
        }

        let v = &mut b.volume;
        v.n = (v.n + 1).min(VOLUME_WINDOW);
        let n = v.n as f64;
        let d = learn_x - v.mean;
        v.mean += d / n;
        v.var = (1.0 - 1.0 / n) * (v.var + d * d / n);
        b.buckets += 1;
        b.active_hours[(start / 3600 % 24) as usize] += 1;
        b.updated_at = now;
        self.dirty.insert(asset_id);
        alert
    }

    // ---------------------------------------------------------- persistence

    pub fn flush(&mut self, store: &dyn Store) -> Result<()> {
        let ids: Vec<i64> = self.dirty.iter().copied().collect();
        for id in ids {
            if let Some(b) = self.baselines.get(&id) {
                store.save_baseline(b)?;
            }
            self.dirty.remove(&id);
        }
        Ok(())
    }
}

fn duration(secs: i64) -> String {
    if secs >= 60 && secs % 60 == 0 {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

/// Base 35, adjusted by how unusual this particular contact is.
fn score_new_destination(
    b: &Baseline,
    global: &HashMap<Ipv4Addr, HashSet<i64>>,
    asset_id: i64,
    r: &FlowRecord,
) -> (i32, Vec<String>) {
    let mut score = 35;
    let mut why = vec![format!("+35 first contact with {} by this device", r.remote)];

    let others = global
        .get(&r.remote)
        .is_some_and(|s| s.iter().any(|id| *id != asset_id));
    if !others {
        score += 15;
        why.push("+15 no other device on the network has contacted it".into());
    }
    let o = r.remote.octets();
    let same_24 = b.typical_destinations.keys().any(|k| {
        k.parse::<Ipv4Addr>()
            .is_ok_and(|ip| ip.octets()[..3] == o[..3])
    });
    if same_24 {
        score -= 10;
        why.push("-10 same /24 as an address this device already uses (likely a CDN/cloud neighbour)".into());
    }
    if r.proto != PROTO_ICMP {
        let key = format!("{}/{}", proto_name(r.proto), r.port);
        if !b.typical_ports.contains_key(&key) && !COMMON_PORTS.contains(&r.port) {
            score += 15;
            why.push(format!("+15 unusual port {key} for this device"));
        }
    }
    // A device that routinely talks to hundreds of different hosts (a laptop, a
    // phone) contacts something new all day; that is the main source of
    // false-positive fatigue, so it is judged less harshly than a NAS that talks
    // to three servers.
    let known = b.typical_destinations.len();
    if known >= 500 {
        score -= 20;
        why.push(format!("-20 device already talks to {known} different hosts (high churn is normal for it)"));
    } else if known >= 100 {
        score -= 10;
        why.push(format!("-10 device already talks to {known} different hosts (high churn is normal for it)"));
    }
    if r.bytes_out >= 50_000_000 {
        score += 20;
        why.push(format!("+20 {:.0} MB sent in the first window", r.bytes_out as f64 / 1e6));
    } else if r.bytes_out >= 1_000_000 {
        score += 10;
        why.push(format!("+10 {:.1} MB sent in the first window", r.bytes_out as f64 / 1e6));
    }
    (score.clamp(0, 100), why)
}

fn new_device_details(a: &Asset, reasons: &[String]) -> serde_json::Value {
    let ip = a.current_ip();
    json!({
        "summary": format!(
            "New device {}{}",
            ip.map(|i| i.to_string()).unwrap_or_else(|| a.mac.to_string()),
            a.vendor.as_ref().map(|v| format!(" ({v})")).unwrap_or_default()
        ),
        "mac": a.mac, "ip": ip, "vendor": a.vendor, "hostnames": a.hostnames,
        "device_type": a.device_type, "randomized_mac": a.randomized_mac,
        "reasons": reasons,
    })
}

fn make_event(
    a: &Asset,
    kind: &str,
    score: i32,
    severity: &str,
    details: serde_json::Value,
    now: i64,
) -> Event {
    Event {
        id: 0,
        agent_id: a.agent_id.clone(),
        asset_id: a.id,
        kind: kind.into(),
        timestamp: now,
        severity: severity.into(),
        score,
        acked: false,
        raw_details: details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    const MAC: Mac = Mac([0x3c, 0x22, 0xfb, 1, 2, 3]);
    const MAC2: Mac = Mac([0x00, 0x1b, 0x63, 4, 5, 6]);

    fn cfg() -> DetectConfig {
        DetectConfig {
            learning_secs: 1000,
            min_samples: 3,
            min_volume_bytes: 1_000_000,
            ..Default::default()
        }
    }

    fn asset(store: &SqliteStore, mac: Mac, first_seen: i64) -> Asset {
        let mut a = Asset::new(mac, first_seen);
        a.vendor = Some("Acme".into());
        a.device_type = "computer".into();
        a.ip_history.push(crate::model::IpRecord { ip: Ipv4Addr::new(192, 168, 1, 5), first_seen, last_seen: first_seen });
        store.save_asset(&mut a).unwrap();
        a
    }

    fn flow(mac: Mac, remote: [u8; 4], port: u16, out: u64, ts: i64) -> FlowRecord {
        FlowRecord {
            mac,
            remote: Ipv4Addr::from(remote),
            proto: 6,
            port,
            bytes_out: out,
            bytes_in: 100,
            packets: 3,
            window_start: ts,
            window_secs: 10,
        }
    }

    fn kinds(ev: &[Event]) -> Vec<(&str, i32)> {
        ev.iter().map(|e| (e.kind.as_str(), e.score)).collect()
    }

    #[test]
    fn destinations_are_learned_silently_then_a_new_one_alerts_once() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        asset(&s, MAC, 0);
        // learning period: nothing alerts, everything is remembered
        assert!(d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 500, 0)], &s, 10).is_empty());
        assert!(d.ingest_flows(None, &[flow(MAC, [9, 9, 9, 9], 443, 500, 500)], &s, 510).is_empty());
        // mature: known destination is silent, unknown one alerts
        assert!(d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 500, 2000)], &s, 2010).is_empty());
        let ev = d.ingest_flows(None, &[flow(MAC, [8, 8, 4, 4], 443, 500, 2010)], &s, 2020);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, RULE_NEW_DESTINATION);
        assert_eq!(ev[0].raw_details["count"], 1);
        assert_eq!(ev[0].raw_details["destinations"][0]["ip"], "8.8.4.4");
        assert!(ev[0].score >= 30 && ev[0].severity != "info");
        // now it's part of the baseline
        assert!(d.ingest_flows(None, &[flow(MAC, [8, 8, 4, 4], 443, 500, 2030)], &s, 2040).is_empty());
    }

    #[test]
    fn score_reflects_neighbourhood_port_size_and_other_devices() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        asset(&s, MAC, 0);
        asset(&s, MAC2, 0);
        d.ingest_flows(None, &[flow(MAC, [5, 5, 5, 5], 443, 100, 0)], &s, 10);
        // same /24, ordinary port, tiny: 35 + 15 (nobody else) - 10 (/24)
        let a = d.ingest_flows(None, &[flow(MAC, [5, 5, 5, 9], 443, 100, 2000)], &s, 2010);
        assert_eq!(a[0].score, 40);
        // new /24, unusual port, 60 MB: 35 + 15 + 15 + 20
        let b = d.ingest_flows(None, &[flow(MAC, [9, 9, 9, 9], 4444, 60_000_000, 2020)], &s, 2030);
        assert_eq!(b[0].score, 85);
        assert_eq!(b[0].severity, "high");
        // when another device already talks to it: the +15 disappears
        d.ingest_flows(None, &[flow(MAC2, [7, 7, 7, 7], 443, 100, 0)], &s, 10);
        let c = d.ingest_flows(None, &[flow(MAC, [7, 7, 7, 7], 443, 100, 2040)], &s, 2050);
        assert_eq!(c[0].score, 35);
        assert_eq!(c[0].severity, "low");
        assert!(c[0].raw_details["reasons"].as_array().unwrap().iter().all(|r| !r.as_str().unwrap().contains("no other device")));
    }

    #[test]
    fn chatty_devices_are_judged_less_harshly_than_quiet_ones() {
        let quiet = |known: u32| {
            let s = SqliteStore::open_in_memory().unwrap();
            let mut d = Detector::new(cfg(), vec![], 0);
            asset(&s, MAC, 0);
            let seed: Vec<_> = (0..known).map(|i| flow(MAC, [60 + (i / 250) as u8, (i % 250) as u8, 1, 1], 443, 1, 0)).collect();
            d.ingest_flows(None, &seed, &s, 10);
            // 200.x.x.x: not in the seed's /24s, so only the churn factor differs
            d.ingest_flows(None, &[flow(MAC, [200, 1, 1, 1], 443, 1, 2000)], &s, 2010)
                .first().map(|e| e.score)
        };
        assert_eq!(quiet(5), Some(50));
        assert_eq!(quiet(150), Some(40));
        assert_eq!(quiet(600), Some(30));
    }

    #[test]
    fn many_new_destinations_in_one_window_become_one_alert() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        asset(&s, MAC, 0);
        d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 1, 0)], &s, 10);
        let flows: Vec<_> = (0..5u8).map(|i| flow(MAC, [20 + i, 0, 0, 1], 443, 1, 2000)).collect();
        let ev = d.ingest_flows(None, &flows, &s, 2010);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].raw_details["count"], 5);
        assert_eq!(ev[0].score, 50 + 4); // 35 + 15, +1 per extra destination
    }

    #[test]
    fn weights_scale_zero_disables_and_min_score_suppresses() {
        let run = |weight: f64, min_score: i32| {
            let s = SqliteStore::open_in_memory().unwrap();
            let mut c = cfg();
            c.min_score = min_score;
            c.weights.insert(RULE_NEW_DESTINATION.into(), weight);
            let mut d = Detector::new(c, vec![], 0);
            asset(&s, MAC, 0);
            d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 1, 0)], &s, 10);
            d.ingest_flows(None, &[flow(MAC, [2, 2, 2, 2], 443, 1, 2000)], &s, 2010)
        };
        assert_eq!(run(1.0, 30)[0].score, 50);
        assert_eq!(run(0.5, 20)[0].score, 25); // tuned down, still visible
        assert!(run(0.5, 30).is_empty()); // ...but below the alert threshold
        assert!(run(0.0, 30).is_empty(), "weight 0 disables the rule");
    }

    /// Feed `n` steady buckets of `bytes` (starting at t=0), each closed by a tick.
    fn steady(d: &mut Detector, s: &SqliteStore, n: i64, bytes: u64) {
        for i in 0..n {
            let t = i * 300;
            d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, bytes, t)], s, t + 10);
            assert!(d.tick(s, t + 400).is_empty(), "steady traffic must not alert (bucket {i})");
        }
    }

    #[test]
    fn volume_spike_alerts_and_does_not_poison_the_baseline() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        let a = asset(&s, MAC, 0);
        steady(&mut d, &s, 6, 10_000_000);
        let b = d.baseline(a.id).unwrap();
        assert_eq!((b.volume.n, b.volume.mean, b.volume.var), (6, 10_000_000.0, 0.0));

        // 30 MB: floor = 0.25 * mean = 2.5 MB, z = 8 -> 40 + (8-3)*10
        d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 30_000_000, 1800)], &s, 1810);
        let ev = d.tick(&s, 1800 + 400);
        assert_eq!(kinds(&ev), [(RULE_VOLUME, 90)]);
        assert_eq!(ev[0].severity, "high");
        let summary = ev[0].raw_details["summary"].as_str().unwrap();
        assert_eq!(summary, "30.0 MB sent outside in 5 min; typical is 10.0 MB");
        // The incident is clamped when learned: mean moved a little, not to 30 MB.
        let mean = d.baseline(a.id).unwrap().volume.mean;
        assert!(mean > 10_000_000.0 && mean < 12_000_000.0, "{mean}");
    }

    #[test]
    fn volume_needs_maturity_samples_and_an_absolute_floor() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        asset(&s, MAC, 0);
        // only 2 samples and inside learning: a huge bucket is just learned
        steady(&mut d, &s, 2, 10_000_000);
        d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 500_000_000, 600)], &s, 610);
        assert!(d.tick(&s, 1000).is_empty());

        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        asset(&s, MAC, 0);
        steady(&mut d, &s, 6, 10_000);
        // 50x the mean, but under the 1 MB absolute floor: not an incident
        d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 500_000, 1800)], &s, 1810);
        assert!(d.tick(&s, 2200).is_empty());
    }

    #[test]
    fn volume_alerts_respect_cooldown() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        asset(&s, MAC, 0);
        steady(&mut d, &s, 6, 10_000_000);
        d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 40_000_000, 1800)], &s, 1810);
        assert_eq!(d.tick(&s, 2200).len(), 1);
        d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 40_000_000, 2100)], &s, 2110);
        assert!(d.tick(&s, 2500).is_empty(), "second spike within the cooldown");
        d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 40_000_000, 6000)], &s, 6010);
        assert_eq!(d.tick(&s, 6400).len(), 1, "cooldown expired");
    }

    #[test]
    fn new_device_is_logged_while_learning_then_scored_after_settling() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);

        // inside the learning window: an info log entry, immediately
        let early = asset(&s, MAC, 500);
        let ev = d.on_new_asset(&early, 500);
        assert_eq!((ev.len(), ev[0].severity.as_str(), ev[0].score), (1, "info", 0));

        // after learning: nothing until the device has settled
        let mut late = Asset::new(Mac([0x00, 0x11, 0x22, 9, 9, 9]), 5000);
        s.save_asset(&mut late).unwrap();
        assert!(d.on_new_asset(&late, 5000).is_empty());
        assert!(d.tick(&s, 5030).is_empty());
        let ev = d.tick(&s, 5061);
        // 50 + 15 (unknown type) + 10 (vendor not registered)
        assert_eq!(kinds(&ev), [(RULE_NEW_DEVICE, 75)]);
        assert_eq!(ev[0].severity, "high");
        assert!(d.tick(&s, 6000).is_empty(), "scored exactly once");

        // fingerprinting during the settle period lowers the score
        let mut phone = Asset::new(Mac([0x3a, 0x11, 0x22, 8, 8, 8]), 5000);
        s.save_asset(&mut phone).unwrap();
        d.on_new_asset(&phone, 5000);
        phone.device_type = "phone".into();
        s.save_asset(&mut phone).unwrap();
        let ev = d.tick(&s, 5061);
        assert_eq!(ev[0].score, 35, "50 - 15 for a private MAC");
        assert_eq!(ev[0].severity, "low");
    }

    #[test]
    fn learning_start_is_per_agent_and_only_moves_earlier() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 10_000);
        d.set_learning_start(Some("site-b"), 4000);
        d.set_learning_start(Some("site-b"), 9000); // ignored
        let mut a = Asset::new(MAC, 4500);
        a.agent_id = Some("site-b".into());
        s.save_asset(&mut a).unwrap();
        assert_eq!(d.on_new_asset(&a, 4500)[0].severity, "info", "site-b is still learning");
        let mut b = Asset::new(MAC2, 4500);
        s.save_asset(&mut b).unwrap();
        // the local collector's learning began at 10_000, so 4500 is "before" it: learning
        assert_eq!(d.on_new_asset(&b, 4500)[0].severity, "info");
        let mut c = Asset::new(Mac([1, 2, 3, 4, 5, 6].map(|x| x & 0xfe)), 5200);
        c.agent_id = Some("site-b".into());
        s.save_asset(&mut c).unwrap();
        assert!(d.on_new_asset(&c, 5200).is_empty(), "site-b's learning ended at 5000");
    }

    #[test]
    fn traffic_from_unknown_devices_is_ignored_and_agents_are_isolated() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        assert!(d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 1, 0)], &s, 10).is_empty());
        assert!(d.baselines.is_empty());
        // same MAC on another agent is a different asset
        asset(&s, MAC, 0);
        assert!(d.ingest_flows(Some("site-b"), &[flow(MAC, [1, 1, 1, 1], 443, 1, 0)], &s, 10).is_empty());
        assert!(d.baselines.is_empty());
    }

    #[test]
    fn baselines_persist_and_restore_including_cross_device_knowledge() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        let a = asset(&s, MAC, 0);
        steady(&mut d, &s, 4, 2_000_000);
        d.flush(&s).unwrap();
        let mut d2 = Detector::new(cfg(), s.load_baselines().unwrap(), 9999);
        let b = d2.baseline(a.id).unwrap();
        assert_eq!(b.volume.n, 4);
        assert!(b.typical_destinations.contains_key("1.1.1.1"));
        assert_eq!(b.typical_ports["tcp/443"], 4);
        assert_eq!(b.active_hours.iter().sum::<u32>(), 4);
        assert!(d2.global_dests[&Ipv4Addr::new(1, 1, 1, 1)].contains(&a.id));
        assert!(d2.dirty.is_empty());
        d2.flush(&s).unwrap();
    }

    #[test]
    fn destination_memory_is_bounded() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut c = cfg();
        c.max_destinations = 5;
        let mut d = Detector::new(c, vec![], 0);
        let a = asset(&s, MAC, 0);
        for i in 0..20u8 {
            d.ingest_flows(None, &[flow(MAC, [30, i, 0, 1], 443, 1, i as i64)], &s, 10);
        }
        let b = d.baseline(a.id).unwrap();
        assert_eq!(b.typical_destinations.len(), 5);
        assert!(b.typical_destinations.contains_key("30.19.0.1"), "most recent are kept");
    }

    #[test]
    fn severity_bands() {
        assert_eq!(severity_for(29, 30), "info");
        assert_eq!(severity_for(30, 30), "low");
        assert_eq!(severity_for(50, 30), "medium");
        assert_eq!(severity_for(70, 30), "high");
        assert_eq!(severity_for(0, 0), "info");
    }
}
