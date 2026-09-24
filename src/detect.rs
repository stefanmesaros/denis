//! Rule-based anomaly detection over per-device baselines.
//!
//! Deliberately not ML: three rules whose reasoning can be shown to a
//! non-security reader. Each produces a 0-100 *score* with the list of factors
//! that built it; a per-rule weight scales it, so a noisy rule can be turned
//! down without being disabled, and `min_score` decides what becomes an alert.
//!
//! Time is always passed in, never read, so behaviour is fully testable.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

use anyhow::Result;
use serde_json::json;

use crate::model::{
    proto_name, Asset, Baseline, ConvRecord, Conversation, DestStat, Event, FlowRecord, Mac, Presence, Signal,
    PROTO_ICMP, PROTO_TCP, PROTO_UDP,
};
use crate::ot::ot_proto_for_port;
use crate::store::{Store};

pub const RULE_NEW_DEVICE: &str = "new_device";
pub const RULE_NEW_DESTINATION: &str = "new_destination";
pub const RULE_VOLUME: &str = "volume_anomaly";
pub const RULE_NEW_PORT: &str = "new_port";
pub const RULE_HOURS: &str = "unusual_hours";
pub const RULE_ARP: &str = "arp_conflict";
pub const RULE_SILENT: &str = "device_silent";
pub const RULE_OT_NEW_CONV: &str = "ot_new_conversation";
pub const RULE_OT_CONTROL: &str = "ot_control_command";
pub const RULE_OT_EXPOSURE: &str = "ot_internet_exposure";
pub const RULE_DHCP: &str = "rogue_dhcp";
pub const RULE_BURST: &str = "new_device_burst";
pub const RULE_OT_PURDUE: &str = "ot_purdue_skip";
pub const RULE_OT_WRITER: &str = "ot_unexpected_writer";
pub const RULE_THREAT: &str = "threat_list_match";
pub const RULE_OT_WATCH: &str = "ot_command_watch";
pub const RULE_OT_ESCALATION: &str = "ot_write_escalation";
pub const RULE_IT_WATCH: &str = "it_watch";

/// Every rule name accepted by `--rule-weight`.
pub const RULES: &[&str] = &[
    RULE_NEW_DEVICE, RULE_NEW_DESTINATION, RULE_VOLUME, RULE_NEW_PORT, RULE_HOURS, RULE_ARP, RULE_SILENT,
    RULE_OT_NEW_CONV, RULE_OT_CONTROL, RULE_OT_EXPOSURE, RULE_DHCP, RULE_BURST, RULE_OT_PURDUE, RULE_OT_WRITER, RULE_THREAT,
    RULE_OT_WATCH, RULE_OT_ESCALATION, RULE_IT_WATCH,
];

/// Every event kind that can be raised as an alert, with what the person who
/// receives it should do next. Shown in the UI beside the alert. Kept next to
/// the rules so a new rule cannot be added without saying what to do about it
/// (a test enforces that).
pub const ADVICE: &[(&str, &str)] = &[
    (RULE_NEW_DEVICE, "Check that you recognise the device: compare its MAC address and manufacturer with your purchase records and ask the likely owner. If it is legitimate, give it a name and owner in the asset register. If not, find its switch port or access point (the switch's MAC table shows it) and disconnect it; if it joined over Wi-Fi, change the Wi-Fi password."),
    (RULE_NEW_DESTINATION, "Look up the address (reverse DNS, whois) and decide whether this device has a reason to talk to it (software updates and cloud services are common). If it is unexpected, check what is running on the device and consider isolating it until you know."),
    (RULE_VOLUME, "Find out what moved the data: a backup, an update or a large upload. If nobody started it, treat it as possible data theft or a compromised device: check the device and the destinations in its recent alerts, and consider isolating it."),
    (RULE_NEW_PORT, "The device used a service it has never used before. Confirm that a person or an update started it; otherwise check on the device which program is using that port."),
    (RULE_HOURS, "Ask the owner whether the activity was expected (maintenance, travel, a scheduled job). If the device should be idle at that time, look for remote access or malware."),
    (RULE_ARP, "Two devices claim the same IP address, or something is claiming the gateway's. It can be a plain address clash, but it is also how a man-in-the-middle attack starts. Compare both MAC addresses in the alert with your register and disconnect the one you do not know. If the gateway is involved treat it as urgent. On managed switches enable DHCP snooping and dynamic ARP inspection."),
    ("arp_mismatch", "An ARP reply carried a different address than its Ethernet sender. Some devices and bridges do this legitimately (redundant gateways, load balancers, VMs); a single event is usually harmless. If it repeats or involves the gateway, treat it like an ARP conflict."),
    (RULE_SILENT, "Check power, cable or Wi-Fi first. If it is an important device and cannot be reached, treat an unexplained outage as an incident."),
    ("agent_offline", "A remote site has stopped reporting. Check that site's internet connection and the machine running the DENIS agent; until it returns, its devices are not judged."),
    (RULE_OT_NEW_CONV, "A device started talking to a controller it never talked to. Check it against the change log or engineering plan (a new HMI, an engineering laptop, an integration). If nothing planned it, isolate it following your plant procedure. Do not power-cycle controllers without operations' approval."),
    (RULE_OT_CONTROL, "A stop, program-download or restart command was sent to a controller. Confirm with operations that maintenance was under way and the sender is an authorised engineering station. If not, alert the plant's security and operations leads at once."),
    (RULE_DHCP, "A device you have not seen before is handing out network addresses. A rogue DHCP server can send every client a wrong gateway or DNS server and read or redirect their traffic. Find it (its MAC address and switch port are in the alert), and unplug it unless you installed it on purpose. On managed switches turn on DHCP snooping so only trusted ports may answer."),
    (RULE_BURST, "Several new devices joined within minutes. That fits an event (a meeting, a delivery of new equipment), but also a scan, an ARP flood or someone bridging a second network. Look at the new devices in the list; if none of them is expected, check which switch port or access point they share."),
    (RULE_OT_PURDUE, "Two industrial devices talk across more than one Purdue level (for example a controller straight to an office PC). Segmentation models such as IEC 62443 expect traffic to pass through the level in between. Confirm the path is intended; if it is not, block it at the firewall between the zones or fix the wrong Purdue level in the register."),
    (RULE_OT_WRITER, "A device that is not an engineering or operator station (a phone, printer, camera, IoT gadget…) sent write or control commands to an industrial device. Treat as suspicious: identify the sender, and check whether its device type is simply wrong in the register."),
    (RULE_THREAT, "A device contacted an address on your threat list (known botnet, malware or scanner infrastructure). Isolate the device, check what is running on it and what it sent, and change any credentials it holds. If the entry is a false positive for your environment, remove it from the list file."),
    (RULE_IT_WATCH, "One of your own network watches matched: a device you asked to be told about talked to an address or port you did not allow (the alert names the watch, the device and the destination). If that is expected, no action is needed; if not, find out what on the device made the connection, and consider blocking it at the firewall. Once you know it is legitimate, add the destination to the watch's allowed list, or the device to its exceptions."),
    (RULE_OT_WATCH, "One of your own OT command watches matched: a command you asked to be told about was sent to an industrial device. Check who sent it and why (the alert names the watch, the sender and the target). If it was planned, no action is needed; if not, contact the plant's operations and security leads, and consider adding the sender to the watch's allowed senders once you know it is legitimate."),
    (RULE_OT_ESCALATION, "A path that only ever read from an industrial device has started writing to it. That is how a monitoring or reporting connection turns into a controlling one. Confirm with operations that the change was intended (a new function, a commissioning, a maintenance task); if not, treat the sender as compromised or misconfigured and block the path at the firewall between the zones."),
    (RULE_OT_EXPOSURE, "An industrial protocol crossed the network boundary. These protocols have no authentication of their own, so nothing outside should reach them. Find the firewall or NAT rule, or the bridging device, that allows it and close it."),
];

/// What to do about an alert of this kind, if we have advice for it.
pub fn advice(kind: &str) -> Option<&'static str> {
    ADVICE.iter().find(|(k, _)| *k == kind).map(|(_, a)| *a)
}

/// One finding from a rule: (rule, score, details).
type Found = (&'static str, i32, serde_json::Value);

/// Remote-administration, file-sharing and database ports: unremarkable inside
/// a LAN, worth a look when a device starts using them towards the outside.
const RISKY_PORTS: &[u16] = &[
    21, 22, 23, 25, 111, 135, 137, 138, 139, 161, 389, 445, 512, 513, 514, 636, 1433, 1521, 1723,
    2049, 2375, 2376, 3306, 3389, 5432, 5672, 5900, 5985, 5986, 6379, 6443, 9200, 9092, 10000,
    10250, 11211, 15672, 27017,
];

/// Ports at or above this are the ephemeral range: with `min(sport, dport)` as
/// the "service port" they are noise, not services.
const EPHEMERAL_START: u16 = 32768;

/// Distinct addresses one claimant may raise separate ARP alerts for per 10 minutes.
const MAX_ARP_ALERTS_PER_WINDOW: usize = 5;

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
    /// `new_port`: a device needs at least this many known ports before a new one is notable.
    pub port_min_baseline: usize,
    /// `unusual_hours`: observe a device this long before judging its daily pattern.
    pub hours_learning_secs: i64,
    pub hours_min_buckets: u32,
    /// Activity in an hour that holds less than this share of the device's history is unusual.
    pub hours_max_share: f64,
    pub hours_min_bytes: u64,
    pub hours_cooldown_secs: i64,
    /// Seconds east of UTC, so "hour of day" means the owner's hour.
    pub tz_offset_secs: i64,
    /// `arp_conflict`: minimum gap between alerts for the same (device, address).
    pub conflict_cooldown_secs: i64,
    /// `device_silent`: needs the collector to refresh `last_seen` (active sweeps or traffic).
    pub presence_enabled: bool,
    pub presence_window_secs: i64,
    /// A device must have been observed this long to count as "reliably online".
    pub presence_min_secs: i64,
    /// ...and present in at least this share of hours over the last week.
    pub presence_coverage: f64,
    pub silent_secs: i64,
    /// A remote agent that stops reporting for this long is reported once,
    /// instead of every device behind it going "silent".
    pub agent_offline_secs: i64,
    /// `ot_command_watch`: the administrator's own watches for specific industrial commands.
    pub ot_watches: Vec<crate::rules::OtWatch>,
    /// `it_watch`: the administrator's own watches on ordinary traffic.
    pub it_watches: Vec<crate::rules::ItWatch>,
    /// `new_device_burst`: this many new devices within this many seconds.
    pub burst_min: usize,
    pub burst_window_secs: i64,
    /// `ot_control_command`: at most one alert per sender/target/protocol in this time.
    pub ot_control_cooldown_secs: i64,
    /// `ot_purdue_skip`: talking across at least this many Purdue levels.
    pub ot_purdue_gap: f64,
    /// `ot_unexpected_writer` and `ot_write_escalation`: minimum gap between repeats.
    pub ot_writer_cooldown_secs: i64,
    pub ot_escalation_cooldown_secs: i64,
    /// Per-rule minimum score: below it the rule's events are logged as `info` only.
    pub rule_min_scores: HashMap<String, i32>,
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
            port_min_baseline: 3,
            hours_learning_secs: 7 * 24 * 3600,
            hours_min_buckets: 200,
            hours_max_share: 0.02,
            hours_min_bytes: 50_000,
            hours_cooldown_secs: 6 * 3600,
            tz_offset_secs: 0,
            conflict_cooldown_secs: 1800,
            presence_enabled: true,
            presence_window_secs: 900,
            presence_min_secs: 48 * 3600,
            presence_coverage: 0.9,
            silent_secs: 2 * 3600,
            agent_offline_secs: 600,
            ot_watches: Vec::new(),
            it_watches: Vec::new(),
            burst_min: 5,
            burst_window_secs: 600,
            ot_control_cooldown_secs: 600,
            ot_purdue_gap: 2.0,
            ot_writer_cooldown_secs: 3600,
            ot_escalation_cooldown_secs: 6 * 3600,
            rule_min_scores: HashMap::new(),
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
    /// (asset, rule) -> until when further alerts are suppressed.
    cooldown: HashMap<(i64, &'static str), i64>,
    learning_start: HashMap<Option<String>, i64>,
    default_learning_start: i64,
    pending_new: Vec<PendingNew>,
    ids: HashMap<(Option<String>, Mac), i64>,
    presence: HashMap<i64, Presence>,
    presence_dirty: HashSet<i64>,
    offline_agents: HashSet<String>,
    /// (claimant asset, address) -> until when repeats are suppressed.
    arp_cooldown: HashMap<(i64, Ipv4Addr), i64>,
    /// claimant MAC -> (when, address) of its recent ARP conflicts.
    arp_claims: HashMap<Mac, VecDeque<(i64, Ipv4Addr)>>,
    /// bytes (out, in) per collector since the last `take_traffic`.
    traffic: HashMap<String, (u64, u64)>,
    /// The communications matrix: (client asset, server asset, protocol, port).
    convs: HashMap<(i64, i64, String, u16), Conversation>,
    convs_dirty: HashSet<(i64, i64, String, u16)>,
    /// (client, server, protocol) -> until when repeated control alerts are held back.
    conv_cooldown: HashMap<(i64, i64, String), i64>,
    /// One alert per (device, watch, address, port) in a while, for `it_watch`.
    it_cooldown: HashMap<(i64, String, Ipv4Addr, u16), i64>,
    /// DHCP servers seen so far, per collector (`None` = local). Learned silently during
    /// the learning period and kept in the database (`dhcp_servers`).
    dhcp_known: HashMap<Option<String>, HashSet<Mac>>,
    dhcp_loaded: bool,
    /// When recent new devices appeared (for `new_device_burst`).
    new_times: VecDeque<i64>,
    burst_until: i64,
    /// Known-bad addresses (`threat_list_match`); empty unless a list is configured.
    threat: crate::threat::ThreatList,
    threat_cooldown: HashMap<(i64, Ipv4Addr), i64>,
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
            presence: HashMap::new(),
            presence_dirty: HashSet::new(),
            offline_agents: HashSet::new(),
            arp_cooldown: HashMap::new(),
            arp_claims: HashMap::new(),
            traffic: HashMap::new(),
            convs: HashMap::new(),
            convs_dirty: HashSet::new(),
            conv_cooldown: HashMap::new(),
            it_cooldown: HashMap::new(),
            dhcp_known: HashMap::new(),
            dhcp_loaded: false,
            new_times: VecDeque::new(),
            burst_until: 0,
            threat: Default::default(),
            threat_cooldown: HashMap::new(),
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

    /// Start over as if the program had just been installed on an empty network (the stored data
    /// was erased): everything learned is forgotten and a new learning period begins now.
    /// Settings, the threat list and the configuration are kept.
    pub fn reset(&mut self, now: i64) {
        let cfg = std::mem::take(&mut self.cfg);
        let threat = std::mem::take(&mut self.threat);
        *self = Detector::new(cfg, Vec::new(), now);
        self.threat = threat;
    }

    /// Swap in a new configuration while running (rule settings edited in the portal).
    /// Baselines, cooldowns and learned state are kept; only thresholds and weights change.
    pub fn set_config(&mut self, cfg: DetectConfig) {
        self.cfg = cfg;
    }

    /// Install (or replace) the list of known-bad addresses.
    pub fn set_threat_list(&mut self, list: crate::threat::ThreatList) {
        self.threat = list;
    }

    pub fn threat_entries(&self) -> usize {
        self.threat.entries
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
        // Several arrivals in a few minutes are a story of their own (a scan, a flood, a
        // bridged network), told once per half hour instead of once per device.
        self.new_times.push_back(now);
        while self.new_times.front().is_some_and(|t| now - *t > self.cfg.burst_window_secs) {
            self.new_times.pop_front();
        }
        let n = self.new_times.len();
        if n >= self.cfg.burst_min && now >= self.burst_until {
            self.burst_until = now + 1800;
            let raw = (50 + 4 * (n - self.cfg.burst_min) as i32).min(80);
            let score = self.cfg.weighted(RULE_BURST, raw);
            let details = json!({
                "summary": format!("{n} new devices joined within {} minutes", self.cfg.burst_window_secs / 60),
                "count": n, "latest_mac": a.mac,
                "reasons": [format!("+{raw} {n} devices appeared within {} minutes (at least {} is unusual)", self.cfg.burst_window_secs / 60, self.cfg.burst_min)],
            });
            return vec![make_event(a, RULE_BURST, score, severity_for(score, self.cfg.min_score), details, now)];
        }
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
    /// destinations and ports the device has never used before.
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
        let t = self.traffic.entry(agent.unwrap_or("").to_string()).or_default();
        for f in flows {
            t.0 += f.bytes_out;
            t.1 += f.bytes_in;
        }
        let mut events = Vec::new();
        for (mac, recs) in by_mac {
            // Traffic from a device we have not (yet) stored is dropped: it
            // will be recorded as soon as discovery has created the asset.
            let Some(asset_id) = self.asset_id(agent, &mac, store) else {
                continue;
            };
            if !self.threat.is_empty() {
                events.extend(self.threat_hits(asset_id, &recs, store, now));
            }
            if !self.cfg.it_watches.is_empty() {
                events.extend(self.it_watch_hits(asset_id, &recs, store, now));
            }
            let found = self.ingest_asset(asset_id, &recs, now);
            if found.is_empty() {
                continue;
            }
            if let Ok(Some(asset)) = store.get_asset(asset_id) {
                for (rule, score, details) in found {
                    let sev = severity_for(score, self.cfg.min_score);
                    events.push(make_event(&asset, rule, score, sev, details, now));
                }
            }
        }
        if self.global_dests.len() > 200_000 {
            self.global_dests.clear(); // only weakens a scoring bonus
        }
        events
    }

    /// The administrator's own watches on ordinary traffic. Explicit requests, so learning does not apply.
    fn it_watch_hits(&mut self, asset_id: i64, recs: &[&FlowRecord], store: &dyn Store, now: i64) -> Vec<Event> {
        let mut events = Vec::new();
        let watches = self.cfg.it_watches.clone();
        let mut loaded: Option<(Asset, Option<crate::model::AssetMeta>)> = None;
        for w in watches.iter().filter(|w| w.enabled) {
            for r in recs.iter().filter(|r| w.matches_flow(r)) {
                let key = (asset_id, w.id.clone(), r.remote, r.port);
                if self.it_cooldown.get(&key).is_some_and(|u| now < *u) {
                    continue;
                }
                if loaded.is_none() {
                    let Some(asset) = store.get_asset(asset_id).ok().flatten() else { return events };
                    loaded = Some((asset, store.get_meta(asset_id).ok().flatten()));
                }
                let (asset, meta) = loaded.as_ref().expect("loaded above");
                if !w.covers(asset, meta.as_ref()) {
                    break; // the device is not one this watch is about: no flow of it can match
                }
                let score = self.cfg.weighted(RULE_IT_WATCH, w.score);
                if score == 0 {
                    continue; // the rule as a whole is switched off (weight 0)
                }
                self.it_cooldown.insert(key, now + w.cooldown_minutes as i64 * 60);
                let kb = (r.bytes_out + r.bytes_in) / 1000;
                let mut d = json!({
                    "summary": format!("{}: {} talked to {} ({} port {}, {} kB)", w.name, asset_label(asset), r.remote, proto_name(r.proto), r.port, kb),
                    "reasons": [format!("+{} matches your watch \"{}\"", w.score, w.name)],
                    "watch": {"id": w.id, "name": w.name},
                    "remote": r.remote, "port": r.port, "proto": proto_name(r.proto),
                    "bytes_out": r.bytes_out, "bytes_in": r.bytes_in,
                });
                d["mac"] = json!(asset.mac);
                // a watch is an explicit request: it is raised even if its score is under the general minimum
                events.push(make_event(asset, RULE_IT_WATCH, score, severity_for(score.max(self.cfg.min_score), self.cfg.min_score), d, now));
            }
        }
        if self.it_cooldown.len() > 50_000 {
            self.it_cooldown.retain(|_, u| now < *u);
        }
        events
    }

    /// Contacts with addresses on the threat list. Not subject to learning: contacting a known
    /// botnet server is bad on the first day too. One alert per device and address per 6 hours.
    fn threat_hits(&mut self, asset_id: i64, recs: &[&FlowRecord], store: &dyn Store, now: i64) -> Vec<Event> {
        let mut events = Vec::new();
        for r in recs.iter().filter(|r| self.threat.contains(r.remote)) {
            let key = (asset_id, r.remote);
            if self.threat_cooldown.get(&key).is_some_and(|u| now < *u) {
                continue;
            }
            self.threat_cooldown.insert(key, now + 6 * 3600);
            let Some(asset) = store.get_asset(asset_id).ok().flatten() else { continue };
            let mut raw = 85;
            let mut why = vec![format!("+85 {} contacted {}, which is on your threat list", asset_label(&asset), r.remote)];
            if r.bytes_out >= 100_000 {
                raw += 10;
                why.push(format!("+10 it sent {} kB to it in one window", r.bytes_out / 1000));
            }
            let score = self.cfg.weighted(RULE_THREAT, raw.clamp(0, 100));
            let details = json!({
                "summary": format!("{} contacted known-bad address {} ({} port {})", asset_label(&asset), r.remote, proto_name(r.proto), r.port),
                "remote": r.remote, "port": r.port, "proto": proto_name(r.proto),
                "bytes_out": r.bytes_out, "bytes_in": r.bytes_in, "reasons": why,
            });
            events.push(make_event(&asset, RULE_THREAT, score, severity_for(score, self.cfg.min_score), details, now));
        }
        if self.threat_cooldown.len() > 100_000 {
            self.threat_cooldown.retain(|_, u| now < *u);
        }
        events
    }

    /// Bytes (out, in) per collector (`""` = local) since the last call.
    pub fn take_traffic(&mut self) -> HashMap<String, (u64, u64)> {
        std::mem::take(&mut self.traffic)
    }

    fn ingest_asset(&mut self, asset_id: i64, recs: &[&FlowRecord], now: i64) -> Vec<Found> {
        let Some(first_ts) = recs.iter().map(|r| r.window_start).min() else {
            return Vec::new();
        };
        let b = self
            .baselines
            .entry(asset_id)
            .or_insert_with(|| Baseline::new(asset_id, first_ts));
        b.observed_since = b.observed_since.min(first_ts);

        let mut fresh: Vec<(i32, Vec<String>, &FlowRecord)> = Vec::new();
        let mut newport: Vec<(i32, Vec<String>, &FlowRecord)> = Vec::new();
        let mut exposed: Vec<&FlowRecord> = Vec::new();
        for r in recs {
            // Industrial protocols crossing the network boundary are a finding by
            // themselves: no learning period applies.
            if matches!(r.proto, PROTO_TCP | PROTO_UDP) && ot_proto_for_port(r.port).is_some() {
                exposed.push(r);
            }
            let key = r.remote.to_string();
            let port_key = format!("{}/{}", proto_name(r.proto), r.port);
            let mature = r.window_start - b.observed_since >= self.cfg.learning_secs;
            let dest_known = b.typical_destinations.contains_key(&key);
            if mature && !dest_known {
                let (raw, why) = score_new_destination(b, &self.global_dests, asset_id, r);
                fresh.push((raw, why, r));
            } else if mature
                && !b.typical_ports.contains_key(&port_key)
                && b.typical_ports.len() >= self.cfg.port_min_baseline
                && r.port < EPHEMERAL_START
                && !COMMON_PORTS.contains(&r.port)
            {
                // A known destination on a port the device has never used. (A
                // new destination already scores an unusual port itself.)
                let (raw, why) = score_new_port(r);
                newport.push((raw, why, r));
            }
            let e = b.typical_destinations.entry(key).or_insert(DestStat {
                first_seen: r.window_start,
                last_seen: r.window_start,
                bytes: 0,
                bytes_out: 0,
                bytes_in: 0,
            });
            e.last_seen = e.last_seen.max(r.window_start);
            e.bytes += r.bytes_out + r.bytes_in;
            e.bytes_out += r.bytes_out;
            e.bytes_in += r.bytes_in;
            *b.typical_ports.entry(port_key).or_default() += 1;
            self.global_dests.entry(r.remote).or_default().insert(asset_id);

            let start = r.window_start / self.cfg.bucket_secs * self.cfg.bucket_secs;
            *self.buckets.entry((asset_id, start)).or_default() += r.bytes_out;
        }
        b.updated_at = now;
        // Bound memory: forget the least recently used destinations.
        while b.typical_destinations.len() > self.cfg.max_destinations {
            let Some(oldest) = b
                .typical_destinations
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            b.typical_destinations.remove(&oldest);
        }
        self.dirty.insert(asset_id);

        let mut out = Vec::new();
        if let Some(r) = exposed.first() {
            let proto = ot_proto_for_port(r.port).unwrap_or("industrial");
            let held = self.cooldown.get(&(asset_id, RULE_OT_EXPOSURE)).is_some_and(|until| now < *until);
            let score = self.cfg.weighted(RULE_OT_EXPOSURE, 90);
            if !held && score >= self.cfg.min_score {
                self.cooldown.insert((asset_id, RULE_OT_EXPOSURE), now + 6 * 3600);
                out.push((
                    RULE_OT_EXPOSURE,
                    score,
                    json!({
                        "summary": format!("Port {} ({proto}, an industrial control protocol) between this device and {} outside the local network", r.port, r.remote),
                        "protocol": proto, "port": r.port, "remote": r.remote,
                        "bytes_out": r.bytes_out, "bytes_in": r.bytes_in, "peers": exposed.len(),
                        "reasons": [format!(
                            "+90 port {} is normally {proto}, an industrial control protocol with little or no authentication; whatever is really running on it, that port must never cross the network boundary",
                            r.port
                        )],
                    }),
                ));
            }
        }
        if !fresh.is_empty() {
            fresh.sort_by_key(|(s, _, _)| -s);
            let count = fresh.len() as i32;
            let (top, top_why, _) = &fresh[0];
            let mut reasons = top_why.clone();
            let extra = (count - 1).min(10);
            if extra > 0 {
                reasons.push(format!("+{extra} {} other new destinations in the same window", count - 1));
            }
            let score = self.cfg.weighted(RULE_NEW_DESTINATION, (top + extra).clamp(0, 100));
            if score >= self.cfg.min_score {
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
                out.push((
                    RULE_NEW_DESTINATION,
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
                ));
            }
        }
        if !newport.is_empty() {
            newport.sort_by_key(|(s, _, _)| -s);
            let count = newport.len() as i32;
            let (top, top_why, first) = &newport[0];
            let mut reasons = top_why.clone();
            let extra = (count - 1).min(10);
            if extra > 0 {
                reasons.push(format!("+{extra} {} other new ports in the same window", count - 1));
            }
            let score = self.cfg.weighted(RULE_NEW_PORT, (top + extra).clamp(0, 100));
            if score >= self.cfg.min_score {
                out.push((
                    RULE_NEW_PORT,
                    score,
                    json!({
                        "summary": format!(
                            "First use of {}/{} towards {}{}",
                            proto_name(first.proto),
                            first.port,
                            first.remote,
                            if count > 1 { format!(" and {} more ports", count - 1) } else { String::new() }
                        ),
                        "count": count,
                        "ports": newport.iter().take(10).map(|(s, _, r)| json!({
                            "proto": proto_name(r.proto), "port": r.port, "remote": r.remote,
                            "bytes_out": r.bytes_out, "score": s,
                        })).collect::<Vec<_>>(),
                        "reasons": reasons,
                    }),
                ));
            }
        }
        out
    }

    // --------------------------------------------------------- OT conversations

    /// Restore the communications matrix saved by an earlier run.
    pub fn load_conversations(&mut self, v: Vec<Conversation>) {
        for c in v {
            self.convs.insert((c.client_id, c.server_id, c.proto.clone(), c.port), c);
        }
    }

    /// Fold conversation windows into the communications matrix and judge them:
    ///
    /// * `ot_new_conversation`: a client/server/protocol path that did not exist
    ///   during the learning period (the allow-list in OT terms);
    /// * `ot_control_command`: STOP/START, program download, restart, operate.
    ///   These are never suppressed by learning; what changes is the score: the
    ///   first time a source does it to a target is alarming, routine repeats
    ///   (an engineering workstation that always downloads) are not.
    pub fn ingest_conversations(
        &mut self,
        agent: Option<&str>,
        convs: &[ConvRecord],
        store: &dyn Store,
        now: i64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        for c in convs {
            let (Some(cid), Some(sid)) = (
                self.asset_id(agent, &c.client_mac, store),
                self.asset_id(agent, &c.server_mac, store),
            ) else {
                continue; // an endpoint discovery has not stored yet: it will be seen again
            };
            let (Ok(Some(client)), Ok(Some(server))) = (store.get_asset(cid), store.get_asset(sid)) else {
                continue;
            };
            let encrypted = crate::ot::is_encrypted_proto(&c.proto);
            // TLS between two ordinary machines is none of this matrix's business: only paths that involve an industrial device
            if c.proto == "tls" && !crate::fingerprint::is_ot_device(&client) && !crate::fingerprint::is_ot_device(&server) {
                continue;
            }
            let key = (cid, sid, c.proto.clone(), c.port);
            let prior = self.convs.get(&key).cloned();
            let mature = c.window_start - self.learning_start(agent) >= self.cfg.learning_secs;

            let e = self.convs.entry(key.clone()).or_insert_with(|| Conversation {
                client_id: cid, server_id: sid, proto: c.proto.clone(), port: c.port,
                first_seen: c.window_start, last_seen: c.window_start,
                packets: 0, bytes: 0, reads: 0, writes: 0, controls: 0, note: None, commands: Default::default(),
            });
            e.last_seen = e.last_seen.max(c.window_start);
            e.packets += c.packets as i64;
            e.bytes += c.bytes as i64;
            e.reads += c.reads as i64;
            e.writes += c.writes as i64;
            e.controls += c.controls as i64;
            if e.note.is_none() {
                e.note = c.note.clone();
            }
            for (cmd, n) in &c.commands {
                if e.commands.contains_key(cmd) || e.commands.len() < crate::model::MAX_COMMANDS {
                    *e.commands.entry(cmd.clone()).or_insert(0) += *n as i64;
                }
            }
            self.convs_dirty.insert(key);

            let cname = asset_label(&client);
            let sname = asset_label(&server);
            let server_is_ot = crate::fingerprint::is_ot_device(&server);
            let parties = json!({
                "client": {"mac": client.mac, "ip": client.current_ip(), "name": cname},
                "server": {"mac": server.mac, "ip": server.current_ip(), "name": sname},
                "protocol": c.proto, "port": c.port,
                "reads": c.reads, "writes": c.writes, "controls": c.controls,
                "client_id": cid, "server_id": sid,
            });

            if prior.is_none() && mature {
                let mut raw = 50;
                let mut why = vec![format!("+50 {cname} has never talked to {sname} over {} before", c.proto)];
                if c.writes > 0 {
                    raw += 20;
                    why.push("+20 the conversation includes write commands".into());
                }
                if c.controls > 0 {
                    raw += 25;
                    why.push("+25 the conversation includes control commands (stop/start/download)".into());
                }
                if server_is_ot {
                    raw += 10;
                    why.push("+10 the target is an industrial controller/device".into());
                }
                if !client.is_self && now - client.first_seen < 3600 {
                    raw += 10;
                    why.push("+10 the client device itself appeared on the network within the last hour".into());
                }
                if encrypted {
                    why.push("+0 the content is encrypted: DENIS sees who talks to whom, not what is said".into());
                } else if c.reads + c.writes + c.controls == 0 {
                    raw -= 15;
                    why.push("-15 only session set-up / discovery traffic so far".into());
                }
                let score = self.cfg.weighted(RULE_OT_NEW_CONV, raw.clamp(0, 100));
                if score >= self.cfg.min_score {
                    let mut d = parties.clone();
                    d["summary"] = json!(format!("New {} path: {cname} → {sname}", c.proto));
                    d["reasons"] = json!(why);
                    events.push(make_event(&server, RULE_OT_NEW_CONV, score, severity_for(score, self.cfg.min_score), d, now));
                }
            }

            if c.controls > 0 {
                let cd_key = (cid, sid, c.proto.clone());
                let held = self.conv_cooldown.get(&cd_key).is_some_and(|until| now < *until);
                if !held {
                    let before = prior.as_ref().map_or(0, |p| p.controls);
                    let what = c.note.clone().unwrap_or_else(|| "control command".into());
                    let (mut raw, mut why) = if before > 0 {
                        (45, vec![format!("+45 {what}: this source has done this to this target before")])
                    } else if mature {
                        (85, vec![format!("+85 {what}: first time this device has done so to this target")])
                    } else {
                        (60, vec![format!("+60 {what}: first seen during the learning period")])
                    };
                    if server_is_ot {
                        raw += 10;
                        why.push("+10 the target is an industrial controller/device".into());
                    }
                    let score = self.cfg.weighted(RULE_OT_CONTROL, raw.clamp(0, 100));
                    self.conv_cooldown.insert(cd_key, now + self.cfg.ot_control_cooldown_secs);
                    if score >= self.cfg.min_score {
                        let mut d = parties.clone();
                        d["summary"] = json!(format!("{cname} sent {what} to {sname} ({})", c.proto));
                        d["reasons"] = json!(why);
                        d["command"] = json!(what);
                        events.push(make_event(&server, RULE_OT_CONTROL, score, severity_for(score, self.cfg.min_score), d, now));
                    }
                }
            }

            // A path that only read starts writing (never during learning: the baseline is what it read).
            if let Some(p) = prior.as_ref().filter(|p| p.writes == 0 && c.writes > 0 && mature) {
                let key = (cid, sid, format!("escalate:{}", c.proto));
                if !self.conv_cooldown.get(&key).is_some_and(|u| now < *u) {
                    self.conv_cooldown.insert(key, now + self.cfg.ot_escalation_cooldown_secs);
                    let mut raw = 60;
                    let mut why = vec![format!("+60 {cname} only read from {sname} over {} until now ({} reads, no writes), and has now written", c.proto, p.reads)];
                    if server_is_ot {
                        raw += 10;
                        why.push("+10 the target is an industrial controller/device".into());
                    }
                    if c.controls > 0 {
                        raw += 15;
                        why.push("+15 the same window includes control commands (stop/start/download)".into());
                    }
                    let score = self.cfg.weighted(RULE_OT_ESCALATION, raw.clamp(0, 100));
                    if score >= self.cfg.min_score {
                        let mut d = parties.clone();
                        d["summary"] = json!(format!("{cname} started writing to {sname} over {} (it only read before)", c.proto));
                        d["reasons"] = json!(why);
                        events.push(make_event(&server, RULE_OT_ESCALATION, score, severity_for(score, self.cfg.min_score), d, now));
                    }
                }
            }

            // The administrator's own watches: specific commands to specific devices.
            if !self.cfg.ot_watches.is_empty() {
                let cmeta = store.get_meta(cid).ok().flatten();
                let smeta = store.get_meta(sid).ok().flatten();
                let watches = self.cfg.ot_watches.clone();
                for w in watches.iter().filter(|w| w.enabled && (w.proto == "any" || w.proto == c.proto)) {
                    if !w.targets.is_empty() && !w.targets.iter().any(|t| t.matches(&server, smeta.as_ref())) {
                        continue;
                    }
                    if w.allowed_senders.iter().any(|t| t.matches(&client, cmeta.as_ref())) {
                        continue;
                    }
                    // what matched: named functions first, then the coarse classes
                    let mut hits: Vec<String> = c.commands.keys()
                        .filter(|k| { let k = k.to_lowercase(); w.commands.iter().any(|word| k.contains(&word.to_lowercase())) })
                        .cloned().collect();
                    if w.controls && c.controls > 0 && !hits.iter().any(|h| Some(h) == c.note.as_ref()) {
                        hits.push(c.note.clone().unwrap_or_else(|| "control command".into()));
                    }
                    if w.writes && c.writes > 0 && hits.is_empty() {
                        hits.push("write command".into());
                    }
                    // "any communication": the path itself, whatever it carries (also traffic that cannot be read)
                    if w.any_traffic && hits.is_empty() {
                        hits.push(if crate::ot::is_encrypted_proto(&c.proto) { "encrypted communication" } else { "communication" }.into());
                    }
                    if hits.is_empty() {
                        continue;
                    }
                    let score = self.cfg.weighted(RULE_OT_WATCH, w.score);
                    if score == 0 {
                        continue; // the rule as a whole is switched off (weight 0)
                    }
                    let cd_key = (cid, sid, format!("watch:{}:{}", w.id, c.proto));
                    if self.conv_cooldown.get(&cd_key).is_some_and(|until| now < *until) {
                        continue;
                    }
                    self.conv_cooldown.insert(cd_key, now + w.cooldown_minutes as i64 * 60);
                    let what = hits.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
                    let mut d = parties.clone();
                    d["summary"] = json!(format!("{}: {cname} sent {what} to {sname} ({})", w.name, c.proto));
                    d["reasons"] = json!([format!("+{} matches your watch \"{}\": {what}", w.score, w.name)]);
                    d["watch"] = json!({"id": w.id, "name": w.name});
                    d["command"] = json!(what);
                    // a watch is an explicit request: it is raised even if its score is under the general minimum
                    events.push(make_event(&server, RULE_OT_WATCH, score, severity_for(score.max(self.cfg.min_score), self.cfg.min_score), d, now));
                }
            }

            // Segmentation: talking across more than one Purdue level, or writing from a
            // device that has no business writing. Both are about the *pair*, not history,
            // so learning does not apply.
            let active = c.reads + c.writes + c.controls > 0;
            if active {
                if let (Some(cl), Some(sl)) = (purdue_level(store, cid), purdue_level(store, sid)) {
                    let key = (cid, sid, format!("purdue:{}", c.proto));
                    if (cl - sl).abs() >= self.cfg.ot_purdue_gap && !self.conv_cooldown.get(&key).is_some_and(|u| now < *u) {
                        self.conv_cooldown.insert(key, now + 6 * 3600);
                        let mut raw = 50;
                        let mut why = vec![format!("+50 {cname} (Purdue level {cl}) talks directly to {sname} (level {sl}): {} levels apart", (cl - sl).abs())];
                        if c.writes + c.controls > 0 {
                            raw += 15;
                            why.push("+15 the conversation includes write or control commands".into());
                        }
                        let score = self.cfg.weighted(RULE_OT_PURDUE, raw);
                        let mut d = parties.clone();
                        d["summary"] = json!(format!("{cname} (L{cl}) ↔ {sname} (L{sl}) skip a level over {}", c.proto));
                        d["reasons"] = json!(why);
                        events.push(make_event(&server, RULE_OT_PURDUE, score, severity_for(score, self.cfg.min_score), d, now));
                    }
                }
            }
            if c.writes + c.controls > 0 && NOT_AN_OPERATOR.contains(&effective_type(store, &client).as_str()) {
                let key = (cid, sid, format!("writer:{}", c.proto));
                if !self.conv_cooldown.get(&key).is_some_and(|u| now < *u) {
                    self.conv_cooldown.insert(key, now + self.cfg.ot_writer_cooldown_secs);
                    let ty = effective_type(store, &client);
                    let mut raw = 65;
                    let mut why = vec![format!("+65 {cname} is a {ty}, not an engineering or operator station, yet it sent write/control commands")];
                    if c.controls > 0 {
                        raw += 15;
                        why.push("+15 including control commands (stop/start/download)".into());
                    }
                    let score = self.cfg.weighted(RULE_OT_WRITER, raw);
                    let mut d = parties.clone();
                    d["summary"] = json!(format!("{ty} {cname} wrote to {sname} over {}", c.proto));
                    d["reasons"] = json!(why);
                    events.push(make_event(&server, RULE_OT_WRITER, score, severity_for(score, self.cfg.min_score), d, now));
                }
            }
        }
        if self.convs.len() > 50_000 {
            // Bound memory: forget the least recently active paths.
            let mut v: Vec<_> = self.convs.iter().map(|(k, c)| (c.last_seen, k.clone())).collect();
            v.sort();
            for (_, k) in v.into_iter().take(10_000) {
                self.convs.remove(&k);
            }
        }
        self.conv_cooldown.retain(|_, until| now < *until);
        events
    }

    /// The whole communications matrix, for the API.
    pub fn conversations(&self) -> Vec<Conversation> {
        self.convs.values().cloned().collect()
    }

    // -------------------------------------------------------------- signals

    /// Judge raw collector signals (ARP conflicts). Learning periods don't
    /// apply: an address war is suspicious from the first minute.
    pub fn ingest_signals(
        &mut self,
        agent: Option<&str>,
        signals: &[Signal],
        store: &dyn Store,
        now: i64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        for s in signals {
            if s.kind == "dhcp_server" {
                events.extend(self.dhcp_server(agent, s, store, now));
                continue;
            }
            let Some(id) = self.asset_id(agent, &s.mac, store) else {
                continue;
            };
            let claims = self.arp_claims.entry(s.mac).or_default();
            claims.retain(|(t, _)| now - *t < 600);
            claims.push_back((now, s.ip));
            let distinct: HashSet<_> = claims.iter().map(|(_, ip)| *ip).collect();
            // Same claimant, same address, still fighting: counted above, not repeated.
            if self.arp_cooldown.get(&(id, s.ip)).is_some_and(|until| now < *until) {
                continue;
            }
            // A poisoner sweeping a subnet must not bury the alert list: after a
            // handful of addresses it is one story, already told.
            if distinct.len() > MAX_ARP_ALERTS_PER_WINDOW {
                continue;
            }

            let previous = s
                .other_mac
                .and_then(|m| store.find_asset(agent, &m).ok().flatten());
            let prev_desc = match (&previous, s.other_mac) {
                (Some(a), _) => a.hostnames.first().cloned().or_else(|| a.vendor.clone()).unwrap_or_else(|| a.mac.to_string()),
                (None, Some(m)) => m.to_string(),
                (None, None) => "unknown".into(),
            };
            let (mut raw, mut why, summary) = if s.kind == "arp_mismatch" {
                (
                    45,
                    vec!["+45 ARP sender hardware address differs from the Ethernet source address (forged or malformed ARP)".to_string()],
                    format!("Malformed ARP for {} from {}", s.ip, s.mac),
                )
            } else {
                (
                    70,
                    vec![format!("+70 {} claimed {} while {} was still using it", s.mac, s.ip, prev_desc)],
                    format!("{} claimed {} which {} is using", s.mac, s.ip, prev_desc),
                )
            };
            // One router or access point often answers for the same IP from several
            // interfaces (2.4/5 GHz radios, mesh nodes, VLANs) whose hardware addresses
            // differ only in the last byte. That is a housekeeping oddity, not a hijack,
            // so it stays in the log unless the contested address is the gateway.
            if s.kind != "arp_mismatch" && s.other_mac.is_some_and(|o| o.0[..5] == s.mac.0[..5]) {
                raw -= 50;
                why.push("-50 both hardware addresses differ only in the last byte: typical of one router/AP with several radios or interfaces".into());
            }
            if s.gateway {
                raw += 25;
                why.push("+25 the contested address is the default gateway (classic man-in-the-middle position)".into());
            }
            if distinct.len() >= 3 {
                raw += 15;
                why.push(format!("+15 claims {} different addresses within 10 minutes (ARP poisoning pattern)", distinct.len()));
            }
            let score = self.cfg.weighted(RULE_ARP, raw.clamp(0, 100));
            self.arp_cooldown.insert((id, s.ip), now + self.cfg.conflict_cooldown_secs);
            if let Ok(Some(claimant)) = store.get_asset(id) {
                let sev = severity_for(score, self.cfg.min_score);
                let details = json!({
                    "summary": summary, "ip": s.ip, "gateway": s.gateway,
                    "claimant_mac": s.mac, "claimant_vendor": claimant.vendor,
                    "previous_mac": s.other_mac, "previous_vendor": previous.as_ref().and_then(|p| p.vendor.clone()),
                    "addresses_claimed": distinct.len(), "reasons": why,
                });
                events.push(make_event(&claimant, &s.kind, score, sev, details, now));
            }
        }
        if self.arp_claims.len() > 10_000 {
            self.arp_claims.retain(|_, q| q.back().is_some_and(|(t, _)| now - *t < 600));
        }
        events
    }

    /// A DHCP reply (offer or acknowledgement) was seen from `s.mac`. Servers seen during the
    /// learning period are the normal ones; a new one afterwards is reported once.
    fn dhcp_server(&mut self, agent: Option<&str>, s: &Signal, store: &dyn Store, now: i64) -> Option<Event> {
        if !self.dhcp_loaded {
            self.dhcp_loaded = true;
            let saved: Vec<(String, String)> = store.get_setting("dhcp_servers").ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            for (ag, mac) in saved {
                if let Ok(m) = mac.parse::<Mac>() {
                    self.dhcp_known.entry(Some(ag).filter(|a| !a.is_empty())).or_default().insert(m);
                }
            }
        }
        let key = agent.map(str::to_string);
        if self.dhcp_known.get(&key).is_some_and(|k| k.contains(&s.mac)) {
            return None;
        }
        // Not stored yet: it will be seen again, and judged then.
        let id = self.asset_id(agent, &s.mac, store)?;
        self.dhcp_known.entry(key).or_default().insert(s.mac);
        let all: Vec<(String, String)> = self
            .dhcp_known
            .iter()
            .flat_map(|(ag, set)| set.iter().map(move |m| (ag.clone().unwrap_or_default(), m.to_string())))
            .take(1000)
            .collect();
        if let Ok(b) = serde_json::to_vec(&all) {
            let _ = store.set_setting("dhcp_servers", &b, now);
        }
        if now - self.learning_start(agent) < self.cfg.learning_secs {
            return None; // part of the normal picture
        }
        let asset = store.get_asset(id).ok().flatten()?;
        let label = asset_label(&asset);
        let mut raw = 70;
        let mut why = vec![format!("+70 {label} started answering DHCP requests, and was not doing so during the learning period")];
        if s.gateway {
            raw -= 30;
            why.push("-30 it is the default gateway: routers normally serve DHCP, so check whether this is a new setting".into());
        }
        let score = self.cfg.weighted(RULE_DHCP, raw);
        let details = json!({
            "summary": format!("New DHCP server: {label} ({}) is handing out addresses", s.ip),
            "server_mac": s.mac, "server_ip": s.ip, "gateway": s.gateway, "reasons": why,
        });
        Some(make_event(&asset, RULE_DHCP, score, severity_for(score, self.cfg.min_score), details, now))
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
            let found = self.close_bucket(key.0, key.1, bytes, now);
            if found.is_empty() {
                continue;
            }
            if let Ok(Some(a)) = store.get_asset(key.0) {
                for (rule, score, details) in found {
                    let sev = severity_for(score, self.cfg.min_score);
                    events.push(make_event(&a, rule, score, sev, details, now));
                }
            }
        }
        self.cooldown.retain(|_, until| now < *until);
        self.arp_cooldown.retain(|_, until| now < *until);
        events
    }

    /// Local hour of day (0-23) of a timestamp.
    fn hour_of(&self, ts: i64) -> usize {
        ((ts + self.cfg.tz_offset_secs).div_euclid(3600)).rem_euclid(24) as usize
    }

    fn close_bucket(&mut self, asset_id: i64, start: i64, bytes: u64, now: i64) -> Vec<Found> {
        let hour = self.hour_of(start);
        let cfg = &self.cfg;
        let b = self
            .baselines
            .entry(asset_id)
            .or_insert_with(|| Baseline::new(asset_id, start));
        let mature = start - b.observed_since >= cfg.learning_secs;
        let x = bytes as f64;
        let v = &b.volume;
        let mut found: Vec<Found> = Vec::new();
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
                    .is_some_and(|until| now < *until);
                let raw = (40.0 + (z - cfg.z_threshold) * 10.0).clamp(0.0, 100.0) as i32;
                let score = cfg.weighted(RULE_VOLUME, raw);
                if !in_cooldown && score >= cfg.min_score {
                    let mb = |v: f64| v / 1e6;
                    found.push((
                        RULE_VOLUME,
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
                    self.cooldown.insert((asset_id, RULE_VOLUME), now + cfg.cooldown_secs);
                }
            }
        }

        // Unusual hours: judged against the histogram *before* this bucket joins it.
        let total: u32 = b.active_hours.iter().sum();
        if start - b.observed_since >= cfg.hours_learning_secs
            && total >= cfg.hours_min_buckets
            && bytes >= cfg.hours_min_bytes
        {
            let share = b.active_hours[hour] as f64 / total as f64;
            let in_cooldown = self
                .cooldown
                .get(&(asset_id, RULE_HOURS))
                .is_some_and(|until| now < *until);
            if share < cfg.hours_max_share && !in_cooldown {
                let raw = (30.0 + 30.0 * (1.0 - share / cfg.hours_max_share)).round() as i32;
                let score = cfg.weighted(RULE_HOURS, raw);
                if score >= cfg.min_score {
                    found.push((
                        RULE_HOURS,
                        score,
                        json!({
                            "summary": format!(
                                "Activity at {hour:02}:00 (local time); this device is almost never active then"
                            ),
                            "hour": hour, "share": share, "bytes_out": bytes, "buckets_observed": total,
                            "reasons": [format!(
                                "{:.1}% of this device's {total} observed activity buckets fall in that hour (threshold {:.0}%)",
                                share * 100.0, cfg.hours_max_share * 100.0
                            )],
                        }),
                    ));
                    self.cooldown.insert((asset_id, RULE_HOURS), now + cfg.hours_cooldown_secs);
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
        b.active_hours[hour] += 1;
        b.updated_at = now;
        self.dirty.insert(asset_id);
        found
    }

    // ------------------------------------------------------------- presence

    pub fn load_presence(&mut self, v: Vec<Presence>) {
        for p in v {
            self.presence.insert(p.asset_id, p);
        }
    }

    /// Record who is present this hour and raise `device_silent` for a device
    /// that was reliably online and no longer is. Call every few minutes.
    ///
    /// If a remote agent itself stops reporting, one `agent_offline` event is
    /// raised for it and its devices are not judged (they would all look silent).
    pub fn tick_presence(&mut self, store: &dyn Store, now: i64) -> Vec<Event> {
        if !self.cfg.presence_enabled {
            return Vec::new();
        }
        // demo devices and sites are fictional: they are never judged silent or offline
        let (Ok(assets), Ok(agents)) = (crate::store::real_assets(store), store.list_agents()) else {
            return Vec::new();
        };
        let agents: Vec<_> = agents.into_iter().filter(|a| !a.id.starts_with(crate::store::DEMO_SITE_PREFIX)).collect();
        let mut events = Vec::new();
        let hour = now.div_euclid(3600);

        let mut silent_agents: HashSet<String> = HashSet::new();
        for ag in &agents {
            let quiet = now - ag.last_report_at >= self.cfg.agent_offline_secs;
            if quiet {
                silent_agents.insert(ag.id.clone());
                if self.offline_agents.insert(ag.id.clone()) {
                    // Attach the event to the agent's own host if we know it.
                    let host = assets.iter().find(|a| a.agent_id.as_deref() == Some(&ag.id) && a.is_self)
                        .or_else(|| assets.iter().find(|a| a.agent_id.as_deref() == Some(&ag.id)));
                    tracing::warn!("agent {} has stopped reporting", ag.id);
                    if let Some(h) = host {
                        let score = self.cfg.weighted(RULE_SILENT, 60);
                        let details = json!({
                            "summary": format!("Agent {:?} has not reported for {}", ag.name, human_secs(now - ag.last_report_at)),
                            "agent": ag.id, "last_report_at": ag.last_report_at,
                            "reasons": ["+60 a whole site stopped reporting; its devices are not judged individually until it returns"],
                        });
                        events.push(make_event(h, "agent_offline", score, severity_for(score, self.cfg.min_score), details, now));
                    }
                }
            } else {
                self.offline_agents.remove(&ag.id);
            }
        }

        for a in &assets {
            if a.agent_id.as_ref().is_some_and(|id| silent_agents.contains(id)) {
                continue;
            }
            let p = self.presence.entry(a.id).or_insert_with(|| Presence { asset_id: a.id, ..Default::default() });
            let mut changed = false;
            if now - a.last_seen <= self.cfg.presence_window_secs {
                changed |= p.hours.insert(hour);
                if p.silent_alerted {
                    p.silent_alerted = false;
                    changed = true;
                    let details = json!({"summary": "Device is back", "reasons": []});
                    events.push(make_event(a, "device_back", 0, "info", details, now));
                }
            }
            let before = p.hours.len();
            p.hours.retain(|h| *h > hour - 14 * 24);
            changed |= p.hours.len() != before;

            let silent_for = now - a.last_seen;
            if !p.silent_alerted && !a.is_self && silent_for >= self.cfg.silent_secs {
                if let Some(coverage) = reliable_coverage(&p.hours, a.last_seen, now, &self.cfg) {
                    p.silent_alerted = true;
                    changed = true;
                    let mut raw = 45;
                    let mut why = vec![format!("+45 online in {:.0}% of hours over the last week, now silent for {}", coverage * 100.0, human_secs(silent_for))];
                    if a.is_gateway || matches!(a.device_type.as_str(), "router" | "nas" | "server" | "camera" | "network device") {
                        raw += 15;
                        why.push(format!("+15 a {} is normally expected to stay up", if a.is_gateway { "gateway" } else { a.device_type.as_str() }));
                    }
                    if coverage >= 0.99 {
                        raw += 10;
                        why.push("+10 essentially never offline before".into());
                    }
                    if a.randomized_mac {
                        raw -= 10;
                        why.push("-10 private MAC address (phones/laptops leave routinely)".into());
                    }
                    let score = self.cfg.weighted(RULE_SILENT, raw.clamp(0, 100));
                    let name = a.hostnames.first().cloned().or_else(|| a.current_ip().map(|i| i.to_string())).unwrap_or_else(|| a.mac.to_string());
                    let details = json!({
                        "summary": format!("{name} has been silent for {}", human_secs(silent_for)),
                        "last_seen": a.last_seen, "coverage": coverage, "reasons": why,
                    });
                    events.push(make_event(a, RULE_SILENT, score, severity_for(score, self.cfg.min_score), details, now));
                }
            }
            if changed {
                self.presence_dirty.insert(a.id);
            }
        }
        events
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
        let ids: Vec<i64> = self.presence_dirty.iter().copied().collect();
        for id in ids {
            if let Some(p) = self.presence.get(&id) {
                store.save_presence(p)?;
            }
            self.presence_dirty.remove(&id);
        }
        if !self.convs_dirty.is_empty() {
            let batch: Vec<Conversation> = self.convs_dirty.iter().filter_map(|k| self.convs.get(k).cloned()).collect();
            store.save_conversations(&batch)?;
            self.convs_dirty.clear();
        }
        Ok(())
    }
}

/// Share of hours in which the device was present over the last week (up to the
/// hour it was last seen), or `None` if it does not count as reliably online.
fn reliable_coverage(hours: &std::collections::BTreeSet<i64>, last_seen: i64, now: i64, cfg: &DetectConfig) -> Option<f64> {
    let first = *hours.iter().next()?;
    if now - first * 3600 < cfg.presence_min_secs {
        return None;
    }
    let end = last_seen.div_euclid(3600);
    let start = first.max(end - 7 * 24);
    if end < start {
        return None;
    }
    let slots = (end - start + 1) as f64;
    let present = hours.range(start..=end).count() as f64;
    let coverage = present / slots;
    (coverage >= cfg.presence_coverage).then_some(coverage)
}

fn human_secs(s: i64) -> String {
    match s {
        s if s >= 86_400 => format!("{:.1} days", s as f64 / 86_400.0),
        s if s >= 3600 => format!("{:.1} h", s as f64 / 3600.0),
        s => format!("{} min", s / 60),
    }
}

/// Base 40 for a port the device has never used.
fn score_new_port(r: &FlowRecord) -> (i32, Vec<String>) {
    let key = format!("{}/{}", proto_name(r.proto), r.port);
    let mut score = 40;
    let mut why = vec![format!("+40 first use of {key} by this device (it has an established set of ports)")];
    if r.proto == PROTO_ICMP {
        score -= 10;
        why.push("-10 ICMP (ping) is usually benign".into());
    }
    if RISKY_PORTS.contains(&r.port) {
        score += 15;
        why.push(format!("+15 {key} is a remote-administration/file-sharing/database port used towards the outside"));
    }
    if r.bytes_out >= 1_000_000 {
        score += 10;
        why.push(format!("+10 {:.1} MB sent in the first window", r.bytes_out as f64 / 1e6));
    }
    (score.clamp(0, 100), why)
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

/// Name for humans: manual/discovered hostname, else IP, else MAC.
/// Device types that are never an engineering workstation, HMI or controller.
const NOT_AN_OPERATOR: &[&str] = &[
    "phone", "tablet", "printer", "camera", "tv", "media device", "smart speaker", "iot", "nas", "game console",
    "smart plug", "smart light", "smart lock", "doorbell", "wearable", "set-top box", "streaming stick", "3d printer",
    "robot vacuum", "appliance", "access point", "voip phone",
];

/// The device type with the owner's correction applied.
fn effective_type(store: &dyn Store, a: &Asset) -> String {
    store.get_meta(a.id).ok().flatten().and_then(|m| m.type_override).unwrap_or_else(|| a.device_type.clone())
}

/// The Purdue level the owner entered (`0`..`5`, `3.5`), as a number.
fn purdue_level(store: &dyn Store, id: i64) -> Option<f64> {
    store.get_meta(id).ok().flatten()?.purdue_level.as_deref()?.parse().ok()
}

fn asset_label(a: &Asset) -> String {
    a.hostnames
        .first()
        .cloned()
        .or_else(|| a.current_ip().map(|i| i.to_string()))
        .unwrap_or_else(|| a.mac.to_string())
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
    use crate::store::AdminStore;
    use crate::store::AssetStore;
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

    // ------------------------------------------------------- new_port rule

    /// Device with an established port set (443, 53, 993 are common; 8883 and 5060 are
    /// "established" non-common ones), mature, with `1.1.1.1` as a known destination.
    fn established(s: &SqliteStore, d: &mut Detector) -> Asset {
        let a = asset(s, MAC, 0);
        let seed = [
            flow(MAC, [1, 1, 1, 1], 443, 1, 0),
            flow(MAC, [1, 1, 1, 1], 8883, 1, 0),
            flow(MAC, [1, 1, 1, 1], 5060, 1, 0),
        ];
        d.ingest_flows(None, &seed, s, 10);
        a
    }

    #[test]
    fn a_known_destination_on_a_port_never_used_before_alerts_with_risk_context() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        established(&s, &mut d);
        // ssh outbound: 40 + 15 (remote administration port)
        let ev = d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 22, 100, 2000)], &s, 2010);
        assert_eq!(kinds(&ev), [(RULE_NEW_PORT, 55)]);
        assert_eq!(ev[0].raw_details["ports"][0]["port"], 22);
        assert!(ev[0].raw_details["summary"].as_str().unwrap().contains("tcp/22 towards 1.1.1.1"));
        // now it is part of the baseline
        assert!(d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 22, 100, 2100)], &s, 2110).is_empty());
        // an unremarkable service port scores the base 40, +10 for >= 1 MB
        let ev = d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 9000, 2_000_000, 2200)], &s, 2210);
        assert_eq!(kinds(&ev), [(RULE_NEW_PORT, 50)]);
    }

    #[test]
    fn new_port_ignores_ephemeral_common_immature_and_thin_baselines() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        established(&s, &mut d);
        for port in [40_000u16, 65_000, 443, 53, 123] {
            assert!(d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], port, 100, 2000)], &s, 2010).is_empty(), "port {port}");
        }
        // inside the learning period: learned silently
        let s2 = SqliteStore::open_in_memory().unwrap();
        let mut d2 = Detector::new(cfg(), vec![], 0);
        established(&s2, &mut d2);
        assert!(d2.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 22, 100, 500)], &s2, 510).is_empty());
        // a device with only two known ports has no "established set" yet
        let s3 = SqliteStore::open_in_memory().unwrap();
        let mut d3 = Detector::new(cfg(), vec![], 0);
        asset(&s3, MAC, 0);
        d3.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, 1, 0), flow(MAC, [1, 1, 1, 1], 8883, 1, 0)], &s3, 10);
        assert!(d3.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 22, 100, 2000)], &s3, 2010).is_empty());
    }

    #[test]
    fn a_new_destination_on_a_new_port_is_one_alert_not_two() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        established(&s, &mut d);
        let ev = d.ingest_flows(None, &[flow(MAC, [9, 9, 9, 9], 4444, 100, 2000)], &s, 2010);
        assert_eq!(kinds(&ev), [(RULE_NEW_DESTINATION, 65)]); // 35 + 15 nobody else + 15 unusual port
    }

    #[test]
    fn new_port_is_tunable_like_every_rule() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut c = cfg();
        c.weights.insert(RULE_NEW_PORT.into(), 0.0);
        let mut d = Detector::new(c, vec![], 0);
        established(&s, &mut d);
        assert!(d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 22, 100, 2000)], &s, 2010).is_empty());
    }

    // ---------------------------------------------------- unusual_hours rule

    fn hours_cfg() -> DetectConfig {
        DetectConfig {
            hours_learning_secs: 1000,
            hours_min_buckets: 10,
            hours_min_bytes: 50_000,
            tz_offset_secs: 3600, // UTC+1
            min_volume_bytes: 10_000_000_000, // keep the volume rule out of the way
            ..cfg()
        }
    }

    /// One closed bucket of `bytes` starting at `ts`.
    fn bucket(d: &mut Detector, s: &SqliteStore, ts: i64, bytes: u64) -> Vec<Event> {
        d.ingest_flows(None, &[flow(MAC, [1, 1, 1, 1], 443, bytes, ts)], s, ts + 10);
        d.tick(s, ts + 400)
    }

    #[test]
    fn activity_in_an_hour_the_device_is_never_active_in_alerts_in_local_time() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(hours_cfg(), vec![], 0);
        let a = asset(&s, MAC, 0);
        // A daytime device: 12 buckets across local 10:00-11:00 (= 09:00 UTC).
        let day = 86_400 * 3;
        for i in 0..12 {
            assert!(bucket(&mut d, &s, day + 9 * 3600 + i * 300, 100_000).is_empty());
        }
        let b = d.baseline(a.id).unwrap();
        assert_eq!(b.active_hours[10], 12, "histogram is in local hours");
        // Its usual hour again: fine.
        assert!(bucket(&mut d, &s, day + 86_400 + 9 * 3600, 100_000).is_empty());
        // 02:00 UTC = 03:00 local: never active then.
        let ev = bucket(&mut d, &s, day + 86_400 + 2 * 3600, 100_000);
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].kind.as_str(), ev[0].score, ev[0].severity.as_str()), (RULE_HOURS, 60, "medium"));
        assert!(ev[0].raw_details["summary"].as_str().unwrap().contains("03:00"));
        assert_eq!(ev[0].raw_details["hour"], 3);
        // The same odd hour again soon is suppressed (cooldown), tiny traffic never counts.
        assert!(bucket(&mut d, &s, day + 86_400 + 2 * 3600 + 600, 100_000).is_empty());
        assert!(bucket(&mut d, &s, day + 2 * 86_400 + 4 * 3600, 1_000).is_empty(), "under hours_min_bytes");
    }

    #[test]
    fn hours_rule_needs_history_before_it_judges() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut c = hours_cfg();
        c.hours_min_buckets = 50;
        let mut d = Detector::new(c, vec![], 0);
        asset(&s, MAC, 0);
        for i in 0..12 {
            bucket(&mut d, &s, 86_400 + 9 * 3600 + i * 300, 100_000);
        }
        // only 12 of the 50 buckets required: an odd hour is just learned
        assert!(bucket(&mut d, &s, 2 * 86_400 + 2 * 3600, 100_000).is_empty());
        // and inside hours_learning_secs nothing is judged either
        let s2 = SqliteStore::open_in_memory().unwrap();
        let mut d2 = Detector::new(hours_cfg(), vec![], 0);
        asset(&s2, MAC, 0);
        for i in 0..12 {
            bucket(&mut d2, &s2, 9 * 3600 + i * 300, 100_000);
        }
        assert!(bucket(&mut d2, &s2, 9 * 3600 + 12 * 300 - 1000 + 600, 100_000).is_empty());
    }

    // ----------------------------------------------------------- ARP signals

    fn sig(kind: &str, mac: Mac, ip: [u8; 4], other: Option<Mac>, gateway: bool) -> Signal {
        Signal { kind: kind.into(), ts: 0, mac, ip: Ipv4Addr::from(ip), other_mac: other, gateway }
    }

    #[test]
    fn arp_conflicts_score_higher_on_the_gateway_and_name_both_parties() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        let mut victim = asset(&s, MAC2, 0);
        victim.hostnames = vec!["router".into()];
        s.save_asset(&mut victim).unwrap();
        asset(&s, MAC, 0);

        let ev = d.ingest_signals(None, &[sig("arp_conflict", MAC, [192, 168, 1, 50], Some(MAC2), false)], &s, 100);
        assert_eq!((ev[0].kind.as_str(), ev[0].score, ev[0].severity.as_str()), ("arp_conflict", 70, "high"));
        let summary = ev[0].raw_details["summary"].as_str().unwrap();
        assert!(summary.contains("router") && summary.contains("192.168.1.50"), "{summary}");
        assert_eq!(ev[0].raw_details["previous_mac"], "00:1b:63:04:05:06");

        let ev = d.ingest_signals(None, &[sig("arp_conflict", MAC, [192, 168, 1, 1], Some(MAC2), true)], &s, 110);
        assert_eq!(ev[0].score, 95);
        assert!(ev[0].raw_details["reasons"].to_string().contains("default gateway"));
    }

    #[test]
    fn sibling_interfaces_of_one_device_are_only_logged_unless_they_contest_the_gateway() {
        let s = SqliteStore::open_in_memory().unwrap();
        let (a, b) = (Mac([0xc8, 0x7f, 0x54, 0x8f, 0x10, 0x90]), Mac([0xc8, 0x7f, 0x54, 0x8f, 0x10, 0xa0]));
        let mut d = Detector::new(cfg(), vec![], 0);
        for m in [a, b] {
            asset(&s, m, 0);
        }
        let ev = d.ingest_signals(None, &[sig("arp_conflict", a, [10, 0, 0, 154], Some(b), false)], &s, 1000);
        assert_eq!(ev[0].severity, "info", "{ev:?}");
        assert!(ev[0].raw_details["reasons"].to_string().contains("differ only in the last byte"));
        // the same pair fighting over the gateway address is still an alert
        let ev = d.ingest_signals(None, &[sig("arp_conflict", b, [10, 0, 0, 1], Some(a), true)], &s, 2000);
        assert!(ev[0].score >= 30 && ev[0].severity != "info", "{ev:?}");
        // unrelated hardware addresses keep the full score
        let c = Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        asset(&s, c, 0);
        let ev = d.ingest_signals(None, &[sig("arp_conflict", c, [10, 0, 0, 155], Some(a), false)], &s, 3000);
        assert_eq!(ev[0].score, 70);
    }

    #[test]
    fn the_same_fight_is_reported_once_and_a_subnet_sweep_does_not_flood() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        asset(&s, MAC, 0);
        let one = sig("arp_conflict", MAC, [192, 168, 1, 50], Some(MAC2), false);
        assert_eq!(d.ingest_signals(None, std::slice::from_ref(&one), &s, 100).len(), 1);
        assert!(d.ingest_signals(None, std::slice::from_ref(&one), &s, 200).is_empty(), "same claimant+address: cooldown");
        // ...until the cooldown passes
        assert_eq!(d.ingest_signals(None, std::slice::from_ref(&one), &s, 100 + 1800).len(), 1);

        // Claiming three or more addresses is the poisoning pattern: +15.
        let many: Vec<_> = (60..70u8).map(|i| sig("arp_conflict", MAC, [192, 168, 1, i], Some(MAC2), false)).collect();
        let ev = d.ingest_signals(None, &many, &s, 5000);
        assert_eq!(ev.len(), MAX_ARP_ALERTS_PER_WINDOW, "capped, not one alert per victim");
        let scores: Vec<i32> = ev.iter().map(|e| e.score).collect();
        assert_eq!(scores, [70, 70, 85, 85, 85], "the pattern bonus applies from the third address");
    }

    #[test]
    fn arp_mismatch_is_scored_lower_and_weights_apply() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut c = cfg();
        c.weights.insert(RULE_ARP.into(), 0.5);
        let mut d = Detector::new(c, vec![], 0);
        asset(&s, MAC, 0);
        let ev = d.ingest_signals(None, &[sig("arp_mismatch", MAC, [192, 168, 1, 7], Some(MAC2), false)], &s, 100);
        assert_eq!((ev[0].kind.as_str(), ev[0].score), ("arp_mismatch", 23)); // round(45 * 0.5)
        // a claimant we have no asset for cannot be attributed: ignored
        assert!(d.ingest_signals(None, &[sig("arp_conflict", Mac([0x00, 9, 9, 9, 9, 9]), [1, 1, 1, 1], None, false)], &s, 100).is_empty());
        // and signals are scoped to their agent like everything else
        assert!(d.ingest_signals(Some("site-b"), &[sig("arp_conflict", MAC, [1, 1, 1, 1], None, false)], &s, 100).is_empty());
    }

    // -------------------------------------------------------- device_silent

    const T0: i64 = 1_000_000_000 / 3600 * 3600;

    fn presence_cfg() -> DetectConfig {
        DetectConfig { presence_min_secs: 48 * 3600, silent_secs: 7200, ..cfg() }
    }

    /// Mark the asset as seen at `ts` and run a presence tick.
    fn seen(d: &mut Detector, s: &SqliteStore, a: &mut Asset, ts: i64) -> Vec<Event> {
        a.last_seen = ts;
        s.save_asset(a).unwrap();
        d.tick_presence(s, ts)
    }

    /// A NAS seen every hour for `hours` hours.
    fn reliable_nas(d: &mut Detector, s: &SqliteStore, hours: i64) -> Asset {
        let mut a = asset(s, MAC, T0);
        a.device_type = "nas".into();
        for h in 0..hours {
            assert!(seen(d, s, &mut a, T0 + h * 3600).is_empty());
        }
        a
    }

    #[test]
    fn a_reliably_online_device_that_goes_silent_alerts_once_and_recovers() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(presence_cfg(), vec![], T0);
        let mut a = reliable_nas(&mut d, &s, 72);
        let last = T0 + 71 * 3600;
        assert!(d.tick_presence(&s, last + 3600).is_empty(), "1 h of silence is not enough");
        let ev = d.tick_presence(&s, last + 7200);
        assert_eq!(ev.len(), 1);
        // 45 + 15 (a NAS should stay up) + 10 (never offline before)
        assert_eq!((ev[0].kind.as_str(), ev[0].score, ev[0].severity.as_str()), (RULE_SILENT, 70, "high"));
        assert!(ev[0].raw_details["summary"].as_str().unwrap().contains("silent for 2.0 h"));
        assert!(d.tick_presence(&s, last + 4 * 3600).is_empty(), "reported once per outage");

        // it comes back: an info event, and the next outage can alert again
        let back = seen(&mut d, &s, &mut a, last + 5 * 3600);
        assert_eq!((back[0].kind.as_str(), back[0].severity.as_str()), ("device_back", "info"));
        assert!(seen(&mut d, &s, &mut a, last + 6 * 3600).is_empty());
        let again = d.tick_presence(&s, last + 6 * 3600 + 7200);
        assert_eq!(again.len(), 1);
    }

    #[test]
    fn flaky_new_or_self_devices_never_count_as_reliably_online() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(presence_cfg(), vec![], T0);
        // seen only 24 of 72 hours (33% coverage)
        let mut flaky = asset(&s, MAC, T0);
        for h in (0..72).filter(|h| h % 3 == 0) {
            seen(&mut d, &s, &mut flaky, T0 + h * 3600);
        }
        assert!(d.tick_presence(&s, T0 + 71 * 3600 + 20_000).is_empty());
        // only 10 h of history (< 48 h): too young to judge
        let s2 = SqliteStore::open_in_memory().unwrap();
        let mut d2 = Detector::new(presence_cfg(), vec![], T0);
        let mut young = asset(&s2, MAC, T0);
        for h in 0..10 {
            seen(&mut d2, &s2, &mut young, T0 + h * 3600);
        }
        assert!(d2.tick_presence(&s2, T0 + 30 * 3600).is_empty());
        // the collector's own host is never "silent"
        let s3 = SqliteStore::open_in_memory().unwrap();
        let mut d3 = Detector::new(presence_cfg(), vec![], T0);
        let mut me = asset(&s3, MAC, T0);
        me.is_self = true;
        for h in 0..72 {
            seen(&mut d3, &s3, &mut me, T0 + h * 3600);
        }
        assert!(d3.tick_presence(&s3, T0 + 71 * 3600 + 20_000).is_empty());
    }

    #[test]
    fn a_silent_phone_scores_lower_than_a_silent_server_and_the_rule_can_be_disabled() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(presence_cfg(), vec![], T0);
        let mut a = asset(&s, Mac([0x3a, 1, 2, 3, 4, 5]), T0); // private MAC
        a.device_type = "phone".into();
        for h in 0..72 {
            seen(&mut d, &s, &mut a, T0 + h * 3600);
        }
        let ev = d.tick_presence(&s, T0 + 71 * 3600 + 7200);
        assert_eq!(ev[0].score, 45 + 10 - 10);

        let s2 = SqliteStore::open_in_memory().unwrap();
        let mut c = presence_cfg();
        c.presence_enabled = false;
        let mut d2 = Detector::new(c, vec![], T0);
        let mut a2 = asset(&s2, MAC, T0);
        for h in 0..72 {
            seen(&mut d2, &s2, &mut a2, T0 + h * 3600);
        }
        assert!(d2.tick_presence(&s2, T0 + 71 * 3600 + 7200).is_empty());
    }

    #[test]
    fn a_silent_agent_is_one_alert_not_a_hundred_silent_devices() {
        use crate::model::AgentInfo;
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(presence_cfg(), vec![], T0);
        let ag = |last_report_at| AgentInfo { id: "site-b".into(), name: "Branch".into(), site: None, version: "t".into(), subnet: "10.9.0.0/24".into(), first_seen: T0, last_report_at, last_run_id: "r".into(), last_seq: 1 };
        // three devices at the branch, reliably online for 3 days
        let mut devs: Vec<Asset> = (1..=3u8)
            .map(|i| {
                let mut a = Asset::new(Mac([0x00, 0x1b, 0x63, 0, 0, i]), T0);
                a.agent_id = Some("site-b".into());
                a.is_self = i == 1;
                s.save_asset(&mut a).unwrap();
                a
            })
            .collect();
        for h in 0..72 {
            let ts = T0 + h * 3600;
            s.upsert_agent(&ag(ts)).unwrap();
            for a in devs.iter_mut() {
                a.last_seen = ts;
                s.save_asset(a).unwrap();
            }
            assert!(d.tick_presence(&s, ts).is_empty());
        }
        // the agent (and so every device behind it) stops at the same moment
        let ev = d.tick_presence(&s, T0 + 71 * 3600 + 3 * 3600);
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].kind, "agent_offline");
        assert!(ev[0].raw_details["summary"].as_str().unwrap().contains("Branch"));
        assert!(d.tick_presence(&s, T0 + 71 * 3600 + 4 * 3600).is_empty(), "once per outage");
        // when the agent returns, judging resumes without a false alarm
        s.upsert_agent(&ag(T0 + 71 * 3600 + 5 * 3600)).unwrap();
        for a in devs.iter_mut() {
            a.last_seen = T0 + 71 * 3600 + 5 * 3600;
            s.save_asset(a).unwrap();
        }
        assert!(d.tick_presence(&s, T0 + 71 * 3600 + 5 * 3600).is_empty());
    }

    #[test]
    fn presence_survives_a_restart() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(presence_cfg(), vec![], T0);
        reliable_nas(&mut d, &s, 72);
        d.flush(&s).unwrap();
        let mut d2 = Detector::new(presence_cfg(), vec![], T0);
        d2.load_presence(s.load_presence().unwrap());
        // the fresh process still knows this device was reliable
        let ev = d2.tick_presence(&s, T0 + 71 * 3600 + 7200);
        assert_eq!(kinds(&ev), [(RULE_SILENT, 70)]);
    }

    // ------------------------------------------------------------ OT rules

    const HMI: Mac = Mac([0x3c, 0x22, 0xfb, 1, 1, 1]);
    const PLC: Mac = Mac([0x00, 0x1b, 0x1b, 2, 2, 2]);
    const PLC2: Mac = Mac([0x00, 0x1b, 0x1b, 3, 3, 3]);

    /// An HMI and two PLCs (Siemens => recognised as industrial devices).
    fn ot_world(s: &SqliteStore) {
        // The HMI has been on the network for a long time (the "client appeared
        // recently" factor must not apply to it).
        asset(s, HMI, -1_000_000);
        for m in [PLC, PLC2] {
            let mut a = asset(s, m, 0);
            a.vendor = Some("Siemens AG".into());
            s.save_asset(&mut a).unwrap();
        }
    }

    fn conv(client: Mac, server: Mac, reads: u64, writes: u64, controls: u64, ts: i64) -> ConvRecord {
        ConvRecord {
            client_mac: client, server_mac: server, client_ip: Ipv4Addr::new(10, 0, 0, 1), server_ip: Ipv4Addr::new(10, 0, 0, 2),
            proto: "s7".into(), port: 102, packets: reads + writes + controls, bytes: 100, reads, writes, controls,
            note: (controls > 0).then(|| "PLC stop (0x29)".to_string()), commands: Default::default(), window_start: ts, window_secs: 10,
        }
    }

    fn tls_conv(client: Mac, server: Mac, proto: &str, port: u16, ts: i64) -> ConvRecord {
        ConvRecord { proto: proto.into(), port, packets: 12, bytes: 4000, ..conv(client, server, 0, 0, 0, ts) }
    }

    #[test]
    fn encrypted_paths_to_an_industrial_device_are_seen_and_judged_by_who_talks_to_whom_and_others_are_ignored() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let laptop = Mac([0x3c, 0x22, 0xfb, 9, 9, 9]);
        let printer = Mac([0x3c, 0x22, 0xfb, 8, 8, 8]);
        asset(&s, laptop, -1_000_000);
        asset(&s, printer, -1_000_000);
        let mut d = Detector::new(cfg(), vec![], 0);
        // learning: the HMI talks TLS to PLC #1 (secured OPC UA); nothing alerts
        assert!(d.ingest_conversations(None, &[tls_conv(HMI, PLC, "opcua-tls", 4843, 10)], &s, 20).is_empty());
        // routine afterwards; another secured path to the same PLC is a new path even though nothing can be read
        assert!(d.ingest_conversations(None, &[tls_conv(HMI, PLC, "opcua-tls", 4843, 2000)], &s, 2010).is_empty());
        let ev = d.ingest_conversations(None, &[tls_conv(laptop, PLC, "opcua-tls", 4843, 2100)], &s, 2110);
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].kind, RULE_OT_NEW_CONV);
        let why = ev[0].raw_details["reasons"].to_string();
        assert!(why.contains("encrypted") && !why.contains("-15"), "an unreadable path is not marked down as 'set-up only': {why}");
        assert_eq!(ev[0].raw_details["protocol"], "opcua-tls");
        assert!(ev[0].score >= 50, "{}", ev[0].score);
        // TLS between two ordinary machines is not recorded at all; TLS involving an industrial device is
        assert!(d.ingest_conversations(None, &[tls_conv(laptop, printer, "tls", 443, 2200)], &s, 2210).is_empty());
        assert!(!d.convs.keys().any(|k| k.2 == "tls"), "an ordinary TLS path is not kept");
        let ev = d.ingest_conversations(None, &[tls_conv(laptop, PLC2, "tls", 8443, 2300)], &s, 2310);
        assert_eq!((ev.len(), ev[0].kind.as_str()), (1, RULE_OT_NEW_CONV));
        assert!(d.convs.keys().any(|k| k.2 == "tls" && k.3 == 8443));
    }

    #[test]
    fn an_allow_list_watch_alerts_on_any_communication_from_a_sender_that_is_not_allowed_also_when_it_is_encrypted() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let laptop = Mac([0x3c, 0x22, 0xfb, 9, 9, 9]);
        let laptop_asset = asset(&s, laptop, -1_000_000);
        let hmi_asset = s.find_asset(None, &HMI).unwrap().unwrap();
        let plc = s.find_asset(None, &PLC).unwrap().unwrap();
        let mut w = watch("allow", "Only the HMI may talk to PLC 1");
        w.proto = "any".into();
        w.any_traffic = true;
        w.targets = vec![crate::rules::Scope { kind: "device".into(), value: plc.id.to_string(), note: None }];
        w.allowed_senders = vec![crate::rules::Scope { kind: "device".into(), value: hmi_asset.id.to_string(), note: None }];
        let mut c = cfg();
        c.ot_watches = vec![w];
        let mut d = Detector::new(c, vec![], 0);
        // the watch fires from the first minute (you asked for it), also while everything else is still learning
        let ev = d.ingest_conversations(None, &[tls_conv(laptop, PLC, "opcua-tls", 4843, 10)], &s, 20);
        let hit = ev.iter().find(|e| e.kind == RULE_OT_WATCH).expect("the allow-list fires for an encrypted path");
        assert!(hit.raw_details["summary"].as_str().unwrap().contains("Only the HMI may talk to PLC 1"));
        assert_eq!(hit.raw_details["command"], "encrypted communication");
        assert_eq!(hit.asset_id, plc.id);
        // the allowed sender, in the clear or not, is silent; another device as target is not covered
        assert!(d.ingest_conversations(None, &[tls_conv(HMI, PLC, "opcua-tls", 4843, 30), conv(HMI, PLC, 3, 0, 0, 30)], &s, 40).iter().all(|e| e.kind != RULE_OT_WATCH));
        assert!(d.ingest_conversations(None, &[tls_conv(laptop, PLC2, "opcua-tls", 4843, 50)], &s, 60).iter().all(|e| e.kind != RULE_OT_WATCH));
        // in the clear it says "communication"; the same watch works for a protocol that is decoded
        let ev = d.ingest_conversations(None, &[conv(laptop, PLC, 2, 0, 0, 5000)], &s, 5010);
        assert_eq!(ev.iter().find(|e| e.kind == RULE_OT_WATCH).map(|e| e.raw_details["command"].clone()), Some(json!("communication")));
        let _ = laptop_asset;
    }

    #[test]
    fn a_new_communication_path_after_learning_is_an_alert_with_context() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let mut d = Detector::new(cfg(), vec![], 0);
        // learning period: the HMI polls PLC #1; nothing alerts
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 5, 0, 0, 10)], &s, 20).is_empty());
        // later, the same path is routine
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 5, 0, 0, 2000)], &s, 2010).is_empty());
        // a path that never existed: read-only = 50 + 10 (target is an industrial device)
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC2, 3, 0, 0, 2000)], &s, 2010);
        assert_eq!(kinds(&ev), [(RULE_OT_NEW_CONV, 60)]);
        assert_eq!(ev[0].raw_details["protocol"], "s7");
        assert_eq!(ev[0].asset_id, s.find_asset(None, &PLC2).unwrap().unwrap().id, "attached to the target");
        assert!(ev[0].raw_details["summary"].as_str().unwrap().contains("New s7 path"));
        // ...and it is now part of the matrix
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC2, 3, 0, 0, 2100)], &s, 2110).is_empty());
        assert_eq!(d.conversations().len(), 2);
    }

    /// A conversation window that also says which functions were used.
    fn conv_with(client: Mac, server: Mac, reads: u64, writes: u64, controls: u64, ts: i64, commands: &[(&str, u32)]) -> ConvRecord {
        let mut c = conv(client, server, reads, writes, controls, ts);
        c.commands = commands.iter().map(|(k, n)| (k.to_string(), *n)).collect();
        c
    }

    fn watch(id: &str, name: &str) -> crate::rules::OtWatch {
        crate::rules::OtWatch {
            id: id.into(), name: name.into(), enabled: true, proto: "s7".into(), writes: false, controls: false, any_traffic: false, commands: vec![],
            targets: vec![], allowed_senders: vec![], score: 80, cooldown_minutes: 10,
        }
    }

    #[test]
    fn a_watch_names_the_command_the_sender_and_the_target_and_respects_its_limits() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let ews = Mac([0x3c, 0x22, 0xfb, 9, 9, 9]);
        let ews_asset = asset(&s, ews, -1_000_000);
        let plc = s.find_asset(None, &PLC).unwrap().unwrap();
        let plc2 = s.find_asset(None, &PLC2).unwrap().unwrap();
        let mut c = cfg();
        let mut w = watch("w1", "Setpoint changes");
        w.commands = vec!["write variable".into()];
        w.targets = vec![crate::rules::Scope { kind: "device".into(), value: plc.id.to_string(), note: None }];
        w.allowed_senders = vec![crate::rules::Scope { kind: "device".into(), value: ews_asset.id.to_string(), note: None }];
        c.ot_watches = vec![w];
        let mut d = Detector::new(c, vec![], 0);
        // learn the paths first, so only the watch can speak
        for (cl, sv) in [(HMI, PLC), (HMI, PLC2), (ews, PLC)] {
            d.ingest_conversations(None, &[conv(cl, sv, 5, 0, 0, 10)], &s, 20);
        }
        let cmd = [("write variable (0x05)", 3)];
        // the HMI wrote a variable to the watched PLC: the alert names the watch, the command, the sender and the target
        let ev = d.ingest_conversations(None, &[conv_with(HMI, PLC, 0, 3, 0, 2000, &cmd)], &s, 2010);
        let w: Vec<_> = ev.iter().filter(|e| e.kind == RULE_OT_WATCH).collect();
        assert_eq!(w.len(), 1, "{ev:?}");
        assert_eq!(w[0].score, 80);
        assert_eq!(w[0].asset_id, plc.id);
        let sum = w[0].raw_details["summary"].as_str().unwrap();
        assert!(sum.contains("Setpoint changes") && sum.contains("write variable (0x05)") && sum.contains("s7"), "{sum}");
        assert_eq!(w[0].raw_details["watch"]["id"], "w1");
        // the cooldown holds repeats back...
        assert!(d.ingest_conversations(None, &[conv_with(HMI, PLC, 0, 3, 0, 2100, &cmd)], &s, 2110).iter().all(|e| e.kind != RULE_OT_WATCH));
        // ...an allowed sender never triggers it, another target is not watched, another command does not match
        assert!(d.ingest_conversations(None, &[conv_with(ews, PLC, 0, 3, 0, 2200, &cmd)], &s, 2210).iter().all(|e| e.kind != RULE_OT_WATCH));
        assert!(d.ingest_conversations(None, &[conv_with(HMI, PLC2, 0, 3, 0, 2300, &cmd)], &s, 2310).iter().all(|e| e.kind != RULE_OT_WATCH));
        let mut d2 = Detector::new(d.config().clone(), vec![], 0);
        assert!(d2.ingest_conversations(None, &[conv_with(HMI, PLC, 3, 0, 0, 2400, &[("read variable (0x04)", 3)])], &s, 2410).iter().all(|e| e.kind != RULE_OT_WATCH));
        let _ = plc2;
    }

    #[test]
    fn a_watch_can_match_any_write_or_any_control_command_even_while_learning_and_can_be_switched_off() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let mut c = cfg();
        let mut w = watch("w2", "Any stop or download");
        w.controls = true;
        w.score = 20; // below the general minimum: still raised, because it is an explicit request
        c.ot_watches = vec![w];
        let mut d = Detector::new(c.clone(), vec![], 0);
        // during the learning period (window at t=10)
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC, 1, 0, 1, 10)], &s, 20);
        let hit = ev.iter().find(|e| e.kind == RULE_OT_WATCH).expect("watch fires while learning");
        assert!(hit.raw_details["summary"].as_str().unwrap().contains("PLC stop (0x29)"));
        assert_ne!(hit.severity, "info", "a watch is shown even below the minimum score");
        // a different protocol is not covered by an s7 watch
        let mut other = conv(HMI, PLC2, 1, 0, 1, 10);
        other.proto = "modbus".into();
        assert!(d.ingest_conversations(None, &[other], &s, 30).iter().all(|e| e.kind != RULE_OT_WATCH));
        // the whole rule off (weight 0) or the watch disabled: silence
        for tweak in [0, 1] {
            let mut c2 = c.clone();
            if tweak == 0 {
                c2.weights.insert(RULE_OT_WATCH.into(), 0.0);
            } else {
                c2.ot_watches[0].enabled = false;
            }
            let mut d = Detector::new(c2, vec![], 0);
            assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 1, 0, 1, 10)], &s, 20).iter().all(|e| e.kind != RULE_OT_WATCH), "{tweak}");
        }
    }

    #[test]
    fn a_path_that_only_read_and_starts_writing_is_flagged_once_but_not_while_learning() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let mut d = Detector::new(cfg(), vec![], 0);
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 5, 0, 0, 10)], &s, 20).is_empty());
        // writes while still learning are learned
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 5, 2, 0, 500)], &s, 510).iter().all(|e| e.kind != RULE_OT_ESCALATION));
        // a path that read for a long time, then writes
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC2, 5, 0, 0, 900)], &s, 910).is_empty());
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC2, 5, 1, 0, 2000)], &s, 2010);
        let e = ev.iter().find(|e| e.kind == RULE_OT_ESCALATION).expect("escalation");
        assert_eq!(e.score, 70, "60 + 10 for an industrial target");
        assert!(e.raw_details["summary"].as_str().unwrap().contains("it only read before"));
        // once per six hours
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC2, 5, 1, 0, 2100)], &s, 2110).iter().all(|e| e.kind != RULE_OT_ESCALATION));
    }

    #[test]
    fn writes_and_only_discovery_traffic_move_the_new_path_score() {
        let score = |reads, writes, ctrl| {
            let s = SqliteStore::open_in_memory().unwrap();
            ot_world(&s);
            let mut d = Detector::new(cfg(), vec![], 0);
            d.ingest_conversations(None, &[conv(HMI, PLC, 1, 0, 0, 10)], &s, 20); // something else learned
            d.ingest_conversations(None, &[conv(HMI, PLC2, reads, writes, ctrl, 2000)], &s, 2010)
                .iter().find(|e| e.kind == RULE_OT_NEW_CONV).map(|e| e.score)
        };
        assert_eq!(score(3, 0, 0), Some(60));
        assert_eq!(score(3, 2, 0), Some(80)); // +20 writes
        assert_eq!(score(0, 0, 0), Some(45)); // -15 nothing but session set-up
        assert_eq!(score(0, 0, 1), Some(85)); // +25 control commands
    }

    #[test]
    fn a_first_stop_or_download_is_alarming_repeats_are_routine_and_cooldown_applies() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let mut d = Detector::new(cfg(), vec![], 0);
        // first ever, after learning: 85 + 10
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC, 0, 0, 1, 2000)], &s, 2010);
        let control: Vec<_> = ev.iter().filter(|e| e.kind == RULE_OT_CONTROL).collect();
        assert_eq!((control.len(), control[0].score, control[0].severity.as_str()), (1, 95, "high"));
        assert!(control[0].raw_details["summary"].as_str().unwrap().contains("PLC stop (0x29)"));
        assert_eq!(control[0].raw_details["command"], "PLC stop (0x29)");
        // an immediate repeat is held back
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 0, 0, 1, 2020)], &s, 2030).iter().all(|e| e.kind != RULE_OT_CONTROL));
        // after the cooldown, the same pair doing it again is routine: 45 + 10
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC, 0, 0, 1, 3000)], &s, 3010);
        let c = ev.iter().find(|e| e.kind == RULE_OT_CONTROL).unwrap();
        assert_eq!((c.score, c.severity.as_str()), (55, "medium"));
        // a different target is a first time again
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC2, 0, 0, 1, 3000)], &s, 3010);
        assert_eq!(ev.iter().find(|e| e.kind == RULE_OT_CONTROL).unwrap().score, 95);
    }

    #[test]
    fn control_commands_alert_even_during_learning_but_less_urgently() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let mut d = Detector::new(cfg(), vec![], 0);
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC, 0, 0, 1, 100)], &s, 110);
        // 60 + 10; and no "new path" alert because paths are being learned
        assert_eq!(kinds(&ev), [(RULE_OT_CONTROL, 70)]);
    }

    #[test]
    fn ot_rules_can_be_tuned_or_disabled_and_unknown_endpoints_are_skipped() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let mut c = cfg();
        c.weights.insert(RULE_OT_CONTROL.into(), 0.0);
        let mut d = Detector::new(c, vec![], 0);
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 0, 0, 1, 2000)], &s, 2010).iter().all(|e| e.kind != RULE_OT_CONTROL));
        // an endpoint discovery never stored is skipped, not a crash
        let ghost = Mac([0x02, 9, 9, 9, 9, 9]);
        assert!(d.ingest_conversations(None, &[conv(ghost, PLC, 1, 0, 0, 2000), conv(HMI, ghost, 1, 0, 0, 2000)], &s, 2010).is_empty());
        // agents are isolated: the same MACs on another agent are different assets
        assert!(d.ingest_conversations(Some("site-b"), &[conv(HMI, PLC, 1, 0, 0, 2000)], &s, 2010).is_empty());
    }

    #[test]
    fn the_communications_matrix_survives_a_restart() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let mut d = Detector::new(cfg(), vec![], 0);
        d.ingest_conversations(None, &[conv(HMI, PLC, 4, 1, 1, 10)], &s, 20);
        d.flush(&s).unwrap();
        let mut d2 = Detector::new(cfg(), vec![], 0);
        d2.load_conversations(s.list_conversations().unwrap());
        assert_eq!(d2.conversations().len(), 1);
        // the known path is still known: no "new conversation" after restart...
        let ev = d2.ingest_conversations(None, &[conv(HMI, PLC, 1, 0, 0, 5000)], &s, 5010);
        assert!(ev.is_empty(), "{ev:?}");
        // ...and the recorded history makes a later STOP "routine" rather than "first time"
        let ev = d2.ingest_conversations(None, &[conv(HMI, PLC, 0, 0, 1, 6000)], &s, 6010);
        assert_eq!(ev.iter().find(|e| e.kind == RULE_OT_CONTROL).unwrap().score, 55);
    }

    #[test]
    fn industrial_protocols_crossing_the_network_boundary_are_always_an_alert() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        asset(&s, MAC, 0);
        // no learning period applies: this is the very first traffic the device has ever shown
        let ev = d.ingest_flows(None, &[flow(MAC, [203, 0, 113, 5], 502, 100, 0)], &s, 10);
        assert_eq!(kinds(&ev), [(RULE_OT_EXPOSURE, 90)]);
        assert_eq!((ev[0].severity.as_str(), ev[0].raw_details["protocol"].as_str()), ("high", Some("modbus")));
        // held back for hours, then reported again
        assert!(d.ingest_flows(None, &[flow(MAC, [203, 0, 113, 6], 102, 100, 100)], &s, 110).is_empty());
        assert_eq!(d.ingest_flows(None, &[flow(MAC, [203, 0, 113, 6], 102, 100, 100_000)], &s, 100_010).len(), 1);
        // ordinary ports are not affected
        let s2 = SqliteStore::open_in_memory().unwrap();
        let mut d2 = Detector::new(cfg(), vec![], 0);
        asset(&s2, MAC, 0);
        assert!(d2.ingest_flows(None, &[flow(MAC, [203, 0, 113, 5], 443, 100, 0), flow(MAC, [203, 0, 113, 5], 8080, 100, 0)], &s2, 10).is_empty());
    }

    #[test]
    fn every_alertable_kind_comes_with_advice() {
        for r in RULES.iter().chain(["arp_mismatch", "agent_offline"].iter()) {
            let a = advice(r).unwrap_or_else(|| panic!("no advice for {r}"));
            assert!(a.len() > 40, "{r}: advice too thin");
        }
        assert!(advice("device_back").is_none(), "info-only kinds need none");
    }

    // ------------------------------------------------------------ more rules

    #[test]
    fn a_dhcp_server_that_appears_after_learning_is_reported_once_and_remembered_across_restarts() {
        let s = SqliteStore::open_in_memory().unwrap();
        let (a, b) = (Mac([0x00, 0x1b, 0x63, 0, 0, 1]), Mac([0x00, 0x1b, 0x63, 0, 0, 2]));
        asset(&s, a, 0);
        asset(&s, b, 0);
        let mut d = Detector::new(cfg(), vec![], 0);
        // during learning the existing server is simply the normal one
        assert!(d.ingest_signals(None, &[sig("dhcp_server", a, [192, 168, 1, 1], None, true)], &s, 20).is_empty());
        assert!(d.ingest_signals(None, &[sig("dhcp_server", a, [192, 168, 1, 1], None, true)], &s, 3000).is_empty(), "still normal later");
        // a second one after learning: 70, once
        let ev = d.ingest_signals(None, &[sig("dhcp_server", b, [192, 168, 1, 99], None, false)], &s, 3000);
        assert_eq!(kinds(&ev), [(RULE_DHCP, 70)]);
        assert!(ev[0].raw_details["summary"].as_str().unwrap().contains("192.168.1.99"));
        assert!(d.ingest_signals(None, &[sig("dhcp_server", b, [192, 168, 1, 99], None, false)], &s, 3100).is_empty(), "told once");
        // a restarted detector still knows both
        let mut d2 = Detector::new(cfg(), vec![], 0);
        assert!(d2.ingest_signals(None, &[sig("dhcp_server", a, [192, 168, 1, 1], None, true), sig("dhcp_server", b, [192, 168, 1, 99], None, false)], &s, 9000).is_empty());
        // the gateway itself starting to serve DHCP is a milder event; weights apply
        let c = Mac([0x00, 0x1b, 0x63, 0, 0, 3]);
        asset(&s, c, 0);
        let ev = d2.ingest_signals(None, &[sig("dhcp_server", c, [192, 168, 1, 1], None, true)], &s, 9000);
        assert_eq!(kinds(&ev), [(RULE_DHCP, 40)]);
        // an unstored sender is skipped (seen again later), not remembered
        assert!(d2.ingest_signals(None, &[sig("dhcp_server", Mac([9, 9, 9, 9, 9, 9]), [192, 168, 1, 50], None, false)], &s, 9100).is_empty());
        // and the rule can be switched off
        let mut off = Detector::new(DetectConfig { weights: [(RULE_DHCP.to_string(), 0.0)].into(), ..cfg() }, vec![], 0);
        let ev = off.ingest_signals(None, &[sig("dhcp_server", b, [192, 168, 1, 99], None, false)], &SqliteStore::open_in_memory().unwrap(), 9000);
        assert!(ev.is_empty());
    }

    #[test]
    fn several_new_devices_in_a_few_minutes_are_one_burst_alert_per_half_hour() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        let mk = |n: u8, t: i64| {
            let mut a = Asset::new(Mac([0x00, 0x11, 0x22, 5, 5, n]), t);
            s.save_asset(&mut a).unwrap();
            a
        };
        let mut burst = Vec::new();
        for n in 0..4u8 {
            assert!(d.on_new_asset(&mk(n, 5000 + n as i64 * 10), 5000 + n as i64 * 10).is_empty(), "four is normal");
        }
        burst.extend(d.on_new_asset(&mk(4, 5050), 5050));
        assert_eq!(kinds(&burst), [(RULE_BURST, 50)]);
        assert!(burst[0].raw_details["summary"].as_str().unwrap().contains("5 new devices"));
        assert!(d.on_new_asset(&mk(5, 5060), 5060).is_empty(), "one alert for the burst");
        // arrivals spread over hours never add up
        let mut d = Detector::new(cfg(), vec![], 0);
        for n in 0..10u8 {
            assert!(d.on_new_asset(&mk(n, 5000 + n as i64 * 3600), 5000 + n as i64 * 3600).is_empty());
        }
    }

    #[test]
    fn contact_with_a_listed_address_alerts_immediately_once_per_six_hours_and_only_for_listed_addresses() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = asset(&s, MAC, 0);
        let mut d = Detector::new(cfg(), vec![], 0);
        // no list, no rule
        assert!(d.ingest_flows(None, &[flow(MAC, [203, 0, 113, 9], 443, 10, 100)], &s, 100).is_empty());
        d.set_threat_list(crate::threat::ThreatList::parse("203.0.113.9\n198.51.100.0/24\n").unwrap());
        assert_eq!(d.threat_entries(), 2);
        // during the learning period too: a known-bad address is bad on day one
        let ev = d.ingest_flows(None, &[flow(MAC, [203, 0, 113, 9], 443, 10, 100)], &s, 100);
        assert_eq!(kinds(&ev), [(RULE_THREAT, 85)]);
        assert_eq!(ev[0].asset_id, a.id);
        assert_eq!(ev[0].raw_details["remote"], "203.0.113.9");
        assert!(d.ingest_flows(None, &[flow(MAC, [203, 0, 113, 9], 443, 10, 200)], &s, 200).is_empty(), "held back");
        // a different listed address, with a lot of data sent
        let ev = d.ingest_flows(None, &[flow(MAC, [198, 51, 100, 77], 8080, 500_000, 300)], &s, 300);
        assert_eq!(kinds(&ev), [(RULE_THREAT, 95)]);
        // unlisted neighbours are quiet, and it repeats after six hours
        assert!(d.ingest_flows(None, &[flow(MAC, [203, 0, 113, 10], 443, 10, 400)], &s, 400).is_empty());
        assert_eq!(d.ingest_flows(None, &[flow(MAC, [203, 0, 113, 9], 443, 10, 30_000)], &s, 30_000).len(), 1);
    }

    fn it_watch(id: &str) -> crate::rules::ItWatch {
        crate::rules::ItWatch {
            id: id.into(), name: "Cameras to the internet".into(), enabled: true, sources: vec![], except_sources: vec![], proto: "any".into(),
            ports_mode: "any".into(), ports: vec![], remotes_mode: "only".into(), remotes: vec!["public".into()], min_kb: 0, score: 75, cooldown_minutes: 30,
        }
    }

    #[test]
    fn an_it_watch_names_the_device_and_destination_only_for_the_devices_and_traffic_it_is_about() {
        let s = SqliteStore::open_in_memory().unwrap();
        let cam = asset(&s, MAC, 0);
        let other = asset(&s, MAC2, 0);
        let mut c = cfg();
        let mut w = it_watch("w1");
        w.sources = vec![crate::rules::Scope { kind: "device".into(), value: cam.id.to_string(), note: None }];
        c.it_watches = vec![w];
        let mut d = Detector::new(c, vec![], 0);
        // watches fire during the learning period too
        assert!(d.ingest_flows(None, &[flow(MAC, [192, 168, 1, 77], 443, 500, 0)], &s, 10).is_empty(), "the local network is not the internet");
        let ev = d.ingest_flows(None, &[flow(MAC, [8, 8, 4, 4], 443, 500, 0)], &s, 10);
        assert_eq!(kinds(&ev), [(RULE_IT_WATCH, 75)]);
        assert_eq!(ev[0].asset_id, cam.id);
        assert_eq!((ev[0].raw_details["remote"].as_str(), ev[0].raw_details["port"].as_u64()), (Some("8.8.4.4"), Some(443)));
        assert!(ev[0].raw_details["summary"].as_str().unwrap().starts_with("Cameras to the internet: "));
        // held back for the cooldown, per destination and port; another destination speaks up
        assert!(d.ingest_flows(None, &[flow(MAC, [8, 8, 4, 4], 443, 500, 100)], &s, 100).is_empty());
        assert_eq!(d.ingest_flows(None, &[flow(MAC, [8, 8, 8, 8], 443, 500, 100)], &s, 100).len(), 1);
        assert_eq!(d.ingest_flows(None, &[flow(MAC, [8, 8, 4, 4], 443, 500, 2000)], &s, 2000).len(), 1, "and again after the cooldown");
        // another device is not what the watch is about
        assert!(d.ingest_flows(None, &[flow(MAC2, [1, 1, 1, 1], 443, 500, 3000)], &s, 3000).is_empty());
        let _ = other;
    }

    #[test]
    fn an_it_watch_can_be_an_allow_list_and_stays_quiet_for_excepted_devices_or_when_switched_off() {
        let s = SqliteStore::open_in_memory().unwrap();
        let cam = asset(&s, MAC, 0);
        let run = |tweak: &dyn Fn(&mut crate::rules::ItWatch, &mut DetectConfig)| {
            let mut c = cfg();
            let mut w = it_watch("w1");
            // "may talk only to the recorder and to DNS": anything else is alerted
            w.remotes_mode = "except".into();
            w.remotes = vec!["192.168.1.10".into()];
            w.ports_mode = "except".into();
            w.ports = vec![53];
            tweak(&mut w, &mut c);
            c.it_watches = vec![w];
            let mut d = Detector::new(c, vec![], 0);
            let mut out = Vec::new();
            for (remote, port) in [([192, 168, 1, 10], 554u16), ([192, 168, 1, 10], 53), ([192, 168, 1, 99], 554), ([8, 8, 8, 8], 53)] {
                out.extend(d.ingest_flows(None, &[flow(MAC, remote, port, 500, 0)], &s, 10).into_iter().map(|e| (e.raw_details["remote"].as_str().unwrap().to_string(), e.raw_details["port"].as_u64().unwrap())));
            }
            out
        };
        // both conditions must hold: not the recorder AND not port 53
        assert_eq!(run(&|_, _| {}), vec![("192.168.1.99".to_string(), 554)], "only the flow outside both allow-lists");
        assert!(run(&|w, _| w.except_sources = vec![crate::rules::Scope { kind: "device".into(), value: cam.id.to_string(), note: None }]).is_empty());
        assert!(run(&|w, _| w.enabled = false).is_empty());
        assert!(run(&|_, c| { c.weights.insert(RULE_IT_WATCH.into(), 0.0); }).is_empty(), "the rule as a whole can be switched off");
        // an amount of data, and a protocol
        assert!(run(&|w, _| w.min_kb = 10).is_empty(), "600 bytes is not 10 kB");
        assert!(run(&|w, _| w.proto = "udp".into()).is_empty(), "the flows are TCP");
    }

    #[test]
    fn talking_across_purdue_levels_is_flagged_but_adjacent_levels_and_unset_levels_are_not() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let level = |mac: Mac, l: &str| {
            let id = s.find_asset(None, &mac).unwrap().unwrap().id;
            s.save_meta(id, &crate::model::AssetMeta { purdue_level: Some(l.into()), ..Default::default() }, "t", 1).unwrap();
        };
        let mut d = Detector::new(cfg(), vec![], 0);
        // no levels entered: nothing to judge
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 5, 0, 0, 10)], &s, 20).is_empty());
        level(HMI, "4");
        level(PLC, "1");
        level(PLC2, "3");
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC, 5, 0, 0, 30)], &s, 40);
        assert_eq!(kinds(&ev), [(RULE_OT_PURDUE, 50)], "{ev:?}");
        assert!(ev[0].raw_details["summary"].as_str().unwrap().contains("skip a level"));
        assert!(d.ingest_conversations(None, &[conv(HMI, PLC, 5, 0, 0, 50)], &s, 60).is_empty(), "held back for six hours");
        // writes across the gap weigh more (another pair, so no cooldown)
        level(PLC2, "1");
        let ev = d.ingest_conversations(None, &[conv(HMI, PLC2, 0, 2, 0, 70)], &s, 80);
        assert_eq!(kinds(&ev), [(RULE_OT_PURDUE, 65)], "{ev:?}");
        // adjacent levels are fine (4 <-> 3), and so is the DMZ (3.5) next to 3 or 4
        let s2 = SqliteStore::open_in_memory().unwrap();
        ot_world(&s2);
        for (m, l) in [(HMI, "4"), (PLC, "3"), (PLC2, "3.5")] {
            let id = s2.find_asset(None, &m).unwrap().unwrap().id;
            s2.save_meta(id, &crate::model::AssetMeta { purdue_level: Some(l.into()), ..Default::default() }, "t", 1).unwrap();
        }
        let mut d2 = Detector::new(cfg(), vec![], 0);
        assert!(d2.ingest_conversations(None, &[conv(HMI, PLC, 5, 0, 0, 30), conv(HMI, PLC2, 5, 0, 0, 30), conv(PLC2, PLC, 5, 0, 0, 30)], &s2, 40).is_empty());
    }

    #[test]
    fn a_camera_or_phone_writing_to_a_plc_is_flagged_but_an_engineering_laptop_is_not() {
        let s = SqliteStore::open_in_memory().unwrap();
        ot_world(&s);
        let cam = Mac([0x00, 0x1b, 0x63, 7, 7, 7]);
        let mut a = asset(&s, cam, -1_000_000);
        a.device_type = "camera".into();
        s.save_asset(&mut a).unwrap();
        let mut d = Detector::new(cfg(), vec![], 0);
        // reads are harmless
        assert!(d.ingest_conversations(None, &[conv(cam, PLC, 5, 0, 0, 10)], &s, 20).is_empty());
        let ev = d.ingest_conversations(None, &[conv(cam, PLC, 0, 3, 0, 30)], &s, 40);
        assert_eq!(kinds(&ev).iter().filter(|(k, _)| *k == RULE_OT_WRITER).count(), 1, "{ev:?}");
        assert_eq!(ev.iter().find(|e| e.kind == RULE_OT_WRITER).unwrap().score, 65);
        // the owner says it is really an engineering workstation: no more alerts
        s.save_meta(a.id, &crate::model::AssetMeta { type_override: Some("engineering workstation".into()), ..Default::default() }, "t", 1).unwrap();
        let mut d2 = Detector::new(cfg(), vec![], 0);
        assert!(d2.ingest_conversations(None, &[conv(cam, PLC2, 0, 3, 0, 30)], &s, 40).iter().all(|e| e.kind != RULE_OT_WRITER));
        // an ordinary computer writing (the usual engineering laptop) is not judged by this rule
        let mut d3 = Detector::new(cfg(), vec![], 0);
        assert!(d3.ingest_conversations(None, &[conv(HMI, PLC, 0, 3, 0, 30)], &s, 40).iter().all(|e| e.kind != RULE_OT_WRITER));
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
