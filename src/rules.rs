//! The detection rules as the portal shows and edits them.
//!
//! Three layers combine into the settings actually in force:
//!
//! 1. the built-in defaults (`DetectConfig::default()`),
//! 2. what the command line said (`--min-score`, `--rule-weight`, …): the **base**,
//! 3. **overrides** an administrator saved in the portal, kept in the database
//!    (setting `rules`) so they survive restarts.
//!
//! The running detector re-reads the overrides every few seconds, so a change takes
//! effect without a restart. Removing an override falls back to the base value.
//!
//! Every editable value has hard limits (below), enforced here on the server: the
//! UI is only a convenience. Rules cannot be *created* or given code from the portal;
//! it only turns existing, reviewed rules up, down or off, and tunes their thresholds.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::detect::{DetectConfig, RULES};
use crate::store::Store;

/// Settings key holding the saved overrides (JSON).
pub const KEY: &str = "rules";

/// One editable threshold.
pub struct Param {
    pub key: &'static str,
    pub label: &'static str,
    pub unit: &'static str,
    pub help: &'static str,
    pub min: f64,
    pub max: f64,
    pub step: f64,
    get: fn(&DetectConfig) -> f64,
    set: fn(&mut DetectConfig, f64),
}

#[allow(clippy::too_many_arguments)]
const fn param(
    key: &'static str, label: &'static str, unit: &'static str, help: &'static str, min: f64, max: f64, step: f64,
    get: fn(&DetectConfig) -> f64, set: fn(&mut DetectConfig, f64),
) -> Param {
    Param { key, label, unit, help, min, max, step, get, set }
}

/// Every editable threshold, and how it maps onto `DetectConfig`.
pub static PARAMS: &[Param] = &[
    param("volume_z_threshold", "Deviations above normal", "×σ", "How many standard deviations above a device's own average a 5-minute transfer must be.", 1.0, 10.0, 0.5,
        |c| c.z_threshold, |c, v| c.z_threshold = v),
    param("volume_min_mb", "Ignore transfers smaller than", "MB", "Windows that send less than this are never anomalous, however unusual.", 0.1, 1000.0, 0.1,
        |c| c.min_volume_bytes as f64 / 1e6, |c, v| c.min_volume_bytes = (v * 1e6) as u64),
    param("volume_min_samples", "Samples before judging", "windows", "A device needs this many 5-minute windows of history before its volume is judged.", 3.0, 288.0, 1.0,
        |c| c.min_samples as f64, |c, v| c.min_samples = v as u32),
    param("volume_cooldown_min", "Minimum gap between alerts", "min", "Per device.", 1.0, 1440.0, 1.0,
        |c| c.cooldown_secs as f64 / 60.0, |c, v| c.cooldown_secs = (v * 60.0) as i64),
    param("new_port_min_known", "Known ports before a new one counts", "ports", "A device with fewer known service ports is still being learned.", 1.0, 50.0, 1.0,
        |c| c.port_min_baseline as f64, |c, v| c.port_min_baseline = v as usize),
    param("hours_max_share_pct", "Unusual if the hour holds less than", "% of history", "Activity in an hour of the day with less than this share of the device's past is unusual.", 0.1, 20.0, 0.1,
        |c| c.hours_max_share * 100.0, |c, v| c.hours_max_share = v / 100.0),
    param("hours_learning_days", "Days of history before judging", "days", "How long a device is observed before its daily pattern is trusted.", 1.0, 30.0, 1.0,
        |c| c.hours_learning_secs as f64 / 86_400.0, |c, v| c.hours_learning_secs = (v * 86_400.0) as i64),
    param("hours_cooldown_h", "Minimum gap between alerts", "hours", "Per device.", 1.0, 72.0, 1.0,
        |c| c.hours_cooldown_secs as f64 / 3600.0, |c, v| c.hours_cooldown_secs = (v * 3600.0) as i64),
    param("arp_cooldown_min", "Minimum gap between repeats", "min", "The same claimant fighting over the same address is reported once per this time.", 1.0, 1440.0, 1.0,
        |c| c.conflict_cooldown_secs as f64 / 60.0, |c, v| c.conflict_cooldown_secs = (v * 60.0) as i64),
    param("silent_minutes", "Silent for", "min", "How long a reliably-online device must be unseen before it is reported.", 10.0, 1440.0, 5.0,
        |c| c.silent_secs as f64 / 60.0, |c, v| c.silent_secs = (v * 60.0) as i64),
    param("presence_coverage_pct", "Counts as reliable if online", "% of hours", "Share of hours in the last week a device must have been present.", 50.0, 100.0, 1.0,
        |c| c.presence_coverage * 100.0, |c, v| c.presence_coverage = v / 100.0),
    param("burst_min_devices", "New devices that count as a burst", "devices", "How many new devices must appear within the window below.", 2.0, 100.0, 1.0,
        |c| c.burst_min as f64, |c, v| c.burst_min = v as usize),
    param("burst_window_min", "Burst window", "min", "The time within which they must appear.", 1.0, 120.0, 1.0,
        |c| c.burst_window_secs as f64 / 60.0, |c, v| c.burst_window_secs = (v * 60.0) as i64),
    param("ot_control_cooldown_min", "Minimum gap between alerts", "min", "Per sender, target and protocol: a repeated stop or download is reported once per this time.", 1.0, 1440.0, 1.0,
        |c| c.ot_control_cooldown_secs as f64 / 60.0, |c, v| c.ot_control_cooldown_secs = (v * 60.0) as i64),
    param("ot_purdue_gap", "Levels apart that count as skipping", "levels", "Two industrial devices talking across at least this many Purdue levels are reported (2 = one level in between is skipped).", 1.0, 5.0, 0.5,
        |c| c.ot_purdue_gap, |c, v| c.ot_purdue_gap = v),
    param("ot_writer_cooldown_min", "Minimum gap between alerts", "min", "Per sender, target and protocol.", 1.0, 1440.0, 1.0,
        |c| c.ot_writer_cooldown_secs as f64 / 60.0, |c, v| c.ot_writer_cooldown_secs = (v * 60.0) as i64),
    param("ot_escalation_cooldown_h", "Minimum gap between alerts", "hours", "Per sender, target and protocol.", 1.0, 168.0, 1.0,
        |c| c.ot_escalation_cooldown_secs as f64 / 3600.0, |c, v| c.ot_escalation_cooldown_secs = (v * 3600.0) as i64),
    param("agent_offline_minutes", "Site silent for", "min", "How long a remote site may stop reporting before one alert is raised.", 1.0, 120.0, 1.0,
        |c| c.agent_offline_secs as f64 / 60.0, |c, v| c.agent_offline_secs = (v * 60.0) as i64),
];

/// What a rule is, in plain words, for the portal.
pub struct RuleInfo {
    pub id: &'static str,
    pub title: &'static str,
    /// `network` or `ot`
    pub group: &'static str,
    pub summary: &'static str,
    pub needs: &'static str,
    /// Keys of `PARAMS` that tune this rule.
    pub params: &'static [&'static str],
}

pub static RULE_INFO: &[RuleInfo] = &[
    RuleInfo { id: "new_device", title: "New device", group: "network",
        summary: "A device appears on the network after the learning period. Scored higher when it is unidentified or has an unknown manufacturer, lower for private (randomised) MAC addresses.",
        needs: "nothing extra", params: &[] },
    RuleInfo { id: "new_destination", title: "New destination", group: "network",
        summary: "A device contacts an outside address it has never used. Best for NAS, cameras, printers and servers; noisy for laptops and phones.",
        needs: "traffic analysis (--flows)", params: &[] },
    RuleInfo { id: "new_port", title: "New service port", group: "network",
        summary: "A device with an established set of ports starts using a new service port, especially remote-administration, file-sharing or database ports.",
        needs: "traffic analysis (--flows)", params: &["new_port_min_known"] },
    RuleInfo { id: "volume_anomaly", title: "Unusual outbound volume", group: "network",
        summary: "A device sends far more data outside than its own history suggests. An incident is not learned as the new normal.",
        needs: "traffic analysis (--flows)", params: &["volume_z_threshold", "volume_min_mb", "volume_min_samples", "volume_cooldown_min"] },
    RuleInfo { id: "unusual_hours", title: "Activity at an unusual hour", group: "network",
        summary: "A device is active in an hour of the day when it is almost never active, judged in local time after about a week of history.",
        needs: "traffic analysis (--flows)", params: &["hours_max_share_pct", "hours_learning_days", "hours_cooldown_h"] },
    RuleInfo { id: "arp_conflict", title: "Address hijacking (ARP)", group: "network",
        summary: "Two devices claim one IP address, or an ARP message is inconsistent: how a man-in-the-middle attack starts. Scored higher when the address is the default gateway.",
        needs: "nothing extra", params: &["arp_cooldown_min"] },
    RuleInfo { id: "device_silent", title: "Device went silent", group: "network",
        summary: "A device that is almost always online has not been seen for a while. Also raised once when a whole remote site stops reporting.",
        needs: "active sweeps (not --passive-only)", params: &["silent_minutes", "presence_coverage_pct", "agent_offline_minutes"] },
    RuleInfo { id: "rogue_dhcp", title: "New DHCP server", group: "network",
        summary: "A device you have not seen before starts handing out network addresses: a rogue DHCP server can redirect every client's traffic. Servers seen during the learning period are the normal ones.",
        needs: "nothing extra", params: &[] },
    RuleInfo { id: "new_device_burst", title: "Burst of new devices", group: "network",
        summary: "Several new devices join within a few minutes (five in ten by default): a scan, an ARP flood, a bridged network, or simply an event. Reported once per half hour.",
        needs: "nothing extra", params: &["burst_min_devices", "burst_window_min"] },
    RuleInfo { id: "threat_list_match", title: "Contact with a known-bad address", group: "network",
        summary: "A device contacts an address on your threat list (a blocklist file you supply, for example from abuse.ch or Spamhaus). Not subject to learning.",
        needs: "traffic analysis (--flows) and --threat-list <file>", params: &[] },
    RuleInfo { id: "ot_new_conversation", title: "OT: new communication path", group: "ot",
        summary: "An industrial device starts talking to a controller it never talked to. Writes and control messages weigh more than reads.",
        needs: "traffic analysis on a mirror port", params: &[] },
    RuleInfo { id: "ot_control_command", title: "OT: control command", group: "ot",
        summary: "A stop, program-download or restart command is sent to a controller. The first one is alarming, repeats are routine.",
        needs: "traffic analysis on a mirror port", params: &["ot_control_cooldown_min"] },
    RuleInfo { id: "ot_purdue_skip", title: "OT: skipping a Purdue level", group: "ot",
        summary: "Two industrial devices talk across more than one Purdue level (for example a controller straight to an office PC), against the usual segmentation model. Needs the Purdue level on both devices in the register.",
        needs: "traffic analysis on a mirror port; Purdue levels entered", params: &["ot_purdue_gap"] },
    RuleInfo { id: "ot_unexpected_writer", title: "OT: write from an unexpected device", group: "ot",
        summary: "A phone, printer, camera, IoT gadget or similar sends write or control commands to an industrial device. Engineering laptops typed as computers are not flagged.",
        needs: "traffic analysis on a mirror port", params: &["ot_writer_cooldown_min"] },
    RuleInfo { id: "ot_command_watch", title: "OT: your command watches", group: "ot",
        summary: "Your own watches: be told when specific industrial commands (a Modbus write, an S7 CPU stop, a DNP3 restart…) are sent to specific devices, optionally except from senders you allow. Add them below.",
        needs: "traffic analysis on a mirror port", params: &[] },
    RuleInfo { id: "ot_write_escalation", title: "OT: read-only path starts writing", group: "ot",
        summary: "A path that only ever read from an industrial device starts sending write commands: how a monitoring connection turns into a controlling one.",
        needs: "traffic analysis on a mirror port", params: &["ot_escalation_cooldown_h"] },
    RuleInfo { id: "ot_internet_exposure", title: "OT: industrial protocol crossing the boundary", group: "ot",
        summary: "An industrial protocol is seen between a local device and an address outside the network.",
        needs: "traffic analysis on a mirror port", params: &[] },
];

/// Administrator changes on top of the base configuration.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Overrides {
    #[serde(default)]
    pub min_score: Option<i32>,
    #[serde(default)]
    pub weights: BTreeMap<String, f64>,
    #[serde(default)]
    pub params: BTreeMap<String, f64>,
    /// Per-rule minimum score: below it that rule's events are only logged.
    #[serde(default)]
    pub min_scores: BTreeMap<String, i32>,
    /// Devices a rule should never alert about (per rule id).
    #[serde(default)]
    pub exceptions: BTreeMap<String, Vec<Scope>>,
    /// The administrator's own industrial-command watches.
    #[serde(default)]
    pub ot_watches: Vec<OtWatch>,
}

/// Who or what a rule setting applies to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    /// `device` (an asset id), `type` (a device type), `tag` or `cidr` (an IPv4 range like `10.0.5.0/24`).
    pub kind: String,
    pub value: String,
}

/// Limits: a rule setting is small, and a request must not be able to make it big.
pub const MAX_SCOPES: usize = 50;
pub const MAX_WATCHES: usize = 30;
pub const WATCH_PROTOS: &[&str] = &["any", "modbus", "s7", "enip", "dnp3", "bacnet", "opcua", "iec104"];

impl Scope {
    /// Validate and normalise what came in.
    pub fn check(&self) -> Result<Scope, String> {
        let value = self.value.trim().to_string();
        if value.is_empty() || value.chars().count() > 60 || value.chars().any(char::is_control) {
            return Err("an exception needs a value of at most 60 characters".into());
        }
        match self.kind.as_str() {
            "device" => {
                value.parse::<i64>().map_err(|_| "a device exception refers to a device by its id")?;
            }
            "type" | "tag" => {}
            "cidr" => {
                parse_cidr(&value).ok_or("a network must look like 10.0.5.0/24")?;
            }
            other => return Err(format!("unknown exception kind {other:?} (device, type, tag or cidr)")),
        }
        Ok(Scope { kind: self.kind.clone(), value })
    }

    /// Does this device fall under the scope?
    pub fn matches(&self, a: &crate::model::Asset, meta: Option<&crate::model::AssetMeta>) -> bool {
        match self.kind.as_str() {
            "device" => self.value.parse::<i64>().is_ok_and(|id| id == a.id),
            "type" => {
                let t = meta.and_then(|m| m.type_override.as_deref()).unwrap_or(&a.device_type);
                t.eq_ignore_ascii_case(&self.value)
            }
            "tag" => meta.is_some_and(|m| m.tags.iter().any(|t| t.eq_ignore_ascii_case(&self.value))),
            "cidr" => match (parse_cidr(&self.value), a.current_ip()) {
                (Some((net, bits)), Some(ip)) => {
                    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                    u32::from(ip) & mask == u32::from(net) & mask
                }
                _ => false,
            },
            _ => false,
        }
    }
}

fn parse_cidr(s: &str) -> Option<(std::net::Ipv4Addr, u32)> {
    let (ip, bits) = s.split_once('/')?;
    let bits: u32 = bits.parse().ok().filter(|b| *b <= 32)?;
    Some((ip.parse().ok()?, bits))
}

/// "Tell me when this command goes to that device": one watch on industrial traffic.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OtWatch {
    /// Chosen by the console; lower-case letters and digits.
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// One of [`WATCH_PROTOS`]; `any` covers every industrial protocol.
    pub proto: String,
    /// Match any write command (registers, coils, tags, setpoints).
    #[serde(default)]
    pub writes: bool,
    /// Match any control command (stop/start, program download, restart, operate).
    #[serde(default)]
    pub controls: bool,
    /// Match functions whose name contains one of these words (`write single register`, `0x29`, `restart`).
    #[serde(default)]
    pub commands: Vec<String>,
    /// Only when the target is one of these (empty: any device).
    #[serde(default)]
    pub targets: Vec<Scope>,
    /// Never for these senders (your engineering workstation, for instance).
    #[serde(default)]
    pub allowed_senders: Vec<Scope>,
    /// The score the alert gets (1-100).
    pub score: i32,
    /// At most one alert per sender/target/protocol in this many minutes.
    pub cooldown_minutes: u32,
}

impl OtWatch {
    pub fn check(&self) -> Result<OtWatch, String> {
        let id = self.id.trim().to_string();
        if id.is_empty() || id.len() > 16 || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            return Err("a watch needs an id of up to 16 lower-case letters and digits".into());
        }
        let name = self.name.trim().to_string();
        if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
            return Err("a watch needs a name of at most 60 characters".into());
        }
        if !WATCH_PROTOS.contains(&self.proto.as_str()) {
            return Err(format!("protocol must be one of {}", WATCH_PROTOS.join(", ")));
        }
        let commands: Vec<String> = self.commands.iter().map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
        if commands.len() > 10 || commands.iter().any(|c| c.chars().count() > 40 || c.chars().any(char::is_control)) {
            return Err("at most 10 command words of up to 40 characters".into());
        }
        if !self.writes && !self.controls && commands.is_empty() {
            return Err("a watch must match something: any write, any control command, or a command word".into());
        }
        if !(1..=100).contains(&self.score) {
            return Err("the score of a watch must be between 1 and 100".into());
        }
        if !(1..=1440).contains(&self.cooldown_minutes) {
            return Err("the gap between alerts must be between 1 and 1440 minutes".into());
        }
        let scopes = |v: &[Scope]| -> Result<Vec<Scope>, String> {
            if v.len() > MAX_SCOPES {
                return Err(format!("at most {MAX_SCOPES} targets or senders per watch"));
            }
            v.iter().map(Scope::check).collect()
        };
        Ok(OtWatch {
            id, name, enabled: self.enabled, proto: self.proto.clone(), writes: self.writes, controls: self.controls, commands,
            targets: scopes(&self.targets)?, allowed_senders: scopes(&self.allowed_senders)?, score: self.score, cooldown_minutes: self.cooldown_minutes,
        })
    }
}

impl Overrides {
    /// The configuration in force: `base` with these overrides applied.
    pub fn apply(&self, base: &DetectConfig) -> DetectConfig {
        let mut c = base.clone();
        if let Some(m) = self.min_score {
            c.min_score = m;
        }
        for (rule, w) in &self.weights {
            c.weights.insert(rule.clone(), *w);
        }
        for p in PARAMS {
            if let Some(v) = self.params.get(p.key) {
                (p.set)(&mut c, *v);
            }
        }
        c.ot_watches = self.ot_watches.clone();
        c.rule_min_scores = self.min_scores.iter().map(|(k, v)| (k.clone(), *v)).collect();
        c
    }

    /// Should an alert of `rule` about (or sent by) one of these devices be dropped?
    pub fn excepted(&self, rule: &str, devices: &[(&crate::model::Asset, Option<&crate::model::AssetMeta>)]) -> bool {
        self.exceptions.get(rule).is_some_and(|list| list.iter().any(|s| devices.iter().any(|(a, m)| s.matches(a, *m))))
    }

    /// Apply a partial update. Atomic: on error `self` is unchanged. A value of
    /// `null` removes that override (back to the base value).
    ///
    /// ```json
    /// {"min_score": 40, "weights": {"new_device": 0.5, "new_port": null}, "params": {"silent_minutes": 240}}
    /// ```
    pub fn patch(&mut self, patch: &Value) -> Result<(), String> {
        let obj = patch.as_object().ok_or("expected a JSON object")?;
        let mut next = self.clone();
        for (k, v) in obj {
            match k.as_str() {
                "min_score" => match v {
                    Value::Null => next.min_score = None,
                    _ => {
                        let n = v.as_i64().ok_or("min_score must be a whole number")?;
                        if !(0..=100).contains(&n) {
                            return Err("min_score must be between 0 and 100".into());
                        }
                        next.min_score = Some(n as i32);
                    }
                },
                "weights" => {
                    for (rule, w) in v.as_object().ok_or("weights must be an object")? {
                        if !RULES.contains(&rule.as_str()) {
                            return Err(format!("unknown rule {rule:?}"));
                        }
                        match w {
                            Value::Null => {
                                next.weights.remove(rule);
                            }
                            _ => {
                                let x = w.as_f64().filter(|x| x.is_finite()).ok_or(format!("the weight of {rule} must be a number"))?;
                                if !(0.0..=5.0).contains(&x) {
                                    return Err(format!("the weight of {rule} must be between 0 (off) and 5"));
                                }
                                next.weights.insert(rule.clone(), (x * 100.0).round() / 100.0);
                            }
                        }
                    }
                }
                "params" => {
                    for (key, val) in v.as_object().ok_or("params must be an object")? {
                        let p = PARAMS.iter().find(|p| p.key == key).ok_or(format!("unknown setting {key:?}"))?;
                        match val {
                            Value::Null => {
                                next.params.remove(key);
                            }
                            _ => {
                                let x = val.as_f64().filter(|x| x.is_finite()).ok_or(format!("{key} must be a number"))?;
                                if x < p.min || x > p.max {
                                    return Err(format!("{} must be between {} and {}", p.label, p.min, p.max));
                                }
                                next.params.insert(key.clone(), x);
                            }
                        }
                    }
                }
                "min_scores" => {
                    for (rule, val) in v.as_object().ok_or("min_scores must be an object")? {
                        if !RULES.contains(&rule.as_str()) {
                            return Err(format!("unknown rule {rule:?}"));
                        }
                        match val {
                            Value::Null => {
                                next.min_scores.remove(rule);
                            }
                            _ => {
                                let n = val.as_i64().filter(|n| (0..=100).contains(n)).ok_or(format!("the minimum score of {rule} must be a whole number from 0 to 100"))?;
                                next.min_scores.insert(rule.clone(), n as i32);
                            }
                        }
                    }
                }
                "exceptions" => {
                    for (rule, list) in v.as_object().ok_or("exceptions must be an object")? {
                        if !RULES.contains(&rule.as_str()) {
                            return Err(format!("unknown rule {rule:?}"));
                        }
                        match list {
                            Value::Null => {
                                next.exceptions.remove(rule);
                            }
                            _ => {
                                let scopes: Vec<Scope> = serde_json::from_value(list.clone()).map_err(|_| format!("the exceptions of {rule} must be a list of {{kind, value}}"))?;
                                if scopes.len() > MAX_SCOPES {
                                    return Err(format!("at most {MAX_SCOPES} exceptions per rule"));
                                }
                                let checked: Vec<Scope> = scopes.iter().map(Scope::check).collect::<Result<_, _>>()?;
                                if checked.is_empty() {
                                    next.exceptions.remove(rule);
                                } else {
                                    next.exceptions.insert(rule.clone(), checked);
                                }
                            }
                        }
                    }
                }
                "ot_watches" => {
                    let watches: Vec<OtWatch> = serde_json::from_value(v.clone()).map_err(|e| format!("ot_watches must be a list of watches ({e})"))?;
                    if watches.len() > MAX_WATCHES {
                        return Err(format!("at most {MAX_WATCHES} watches"));
                    }
                    let checked: Vec<OtWatch> = watches.iter().map(OtWatch::check).collect::<Result<_, _>>()?;
                    let mut ids: Vec<&str> = checked.iter().map(|w| w.id.as_str()).collect();
                    ids.sort_unstable();
                    ids.dedup();
                    if ids.len() != checked.len() {
                        return Err("watch ids must be unique".into());
                    }
                    next.ot_watches = checked;
                }
                other => return Err(format!("unknown field {other:?}")),
            }
        }
        *self = next;
        Ok(())
    }
}

pub fn load(store: &dyn Store) -> Result<Overrides> {
    Ok(store.get_setting(KEY)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default())
}

pub fn save(store: &dyn Store, o: &Overrides, now: i64) -> Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(o)?, now)
}

/// Everything the Rules screen needs: each rule with its effective and default
/// values, and which of them an administrator has changed.
pub fn describe(base: &DetectConfig, o: &Overrides) -> Value {
    let eff = o.apply(base);
    let num = |x: f64| (x * 1000.0).round() / 1000.0;
    let rules: Vec<Value> = RULE_INFO
        .iter()
        .map(|r| {
            let w = eff.weights.get(r.id).copied().unwrap_or(1.0);
            let dw = base.weights.get(r.id).copied().unwrap_or(1.0);
            let params: Vec<Value> = r
                .params
                .iter()
                .filter_map(|k| PARAMS.iter().find(|p| p.key == *k))
                .map(|p| {
                    json!({
                        "key": p.key, "label": p.label, "unit": p.unit, "help": p.help,
                        "min": p.min, "max": p.max, "step": p.step,
                        "value": num((p.get)(&eff)), "default": num((p.get)(base)),
                        "overridden": o.params.contains_key(p.key),
                    })
                })
                .collect();
            json!({
                "id": r.id, "title": r.title, "group": r.group, "summary": r.summary, "needs": r.needs,
                "weight": w, "default_weight": dw, "enabled": w > 0.0,
                "overridden": o.weights.contains_key(r.id), "params": params,
                "min_score": o.min_scores.get(r.id).copied(),
            })
        })
        .collect();
    json!({
        "min_score": { "value": eff.min_score, "default": base.min_score, "overridden": o.min_score.is_some() },
        "rules": rules,
        "any_override": *o != Overrides::default(),
        "exceptions": o.exceptions,
        "ot_watches": o.ot_watches,
        "watch_protocols": WATCH_PROTOS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_is_described_and_every_param_is_used_and_within_its_own_limits() {
        for r in RULES {
            assert!(RULE_INFO.iter().any(|i| i.id == *r), "rule {r} has no description in the portal");
        }
        for i in RULE_INFO {
            assert!(RULES.contains(&i.id), "{} is not a real rule", i.id);
            for k in i.params {
                assert!(PARAMS.iter().any(|p| p.key == *k), "{k}");
            }
        }
        for p in PARAMS {
            assert!(RULE_INFO.iter().any(|r| r.params.contains(&p.key)), "{} belongs to no rule", p.key);
            // the defaults themselves must be inside the allowed range, or "reset" would be invalid
            let d = (p.get)(&DetectConfig::default());
            assert!(d >= p.min && d <= p.max, "default of {} = {d} outside {}..{}", p.key, p.min, p.max);
        }
        // each setter and getter agree (round trip through the overrides)
        for p in PARAMS {
            let mut o = Overrides::default();
            o.patch(&json!({"params": {p.key: p.max}})).unwrap();
            let c = o.apply(&DetectConfig::default());
            assert!(((p.get)(&c) - p.max).abs() < 1e-6, "{}: {} vs {}", p.key, (p.get)(&c), p.max);
        }
    }

    #[test]
    fn overrides_win_over_the_base_and_null_returns_to_it() {
        let mut base = DetectConfig::default();
        base.weights.insert("new_port".into(), 0.5); // from the command line
        let mut o = Overrides::default();
        o.patch(&json!({"min_score": 45, "weights": {"new_device": 0, "new_port": 2}, "params": {"silent_minutes": 240, "volume_z_threshold": 4.5}})).unwrap();
        let c = o.apply(&base);
        assert_eq!((c.min_score, c.silent_secs, c.z_threshold), (45, 240 * 60, 4.5));
        assert_eq!((c.weights["new_device"], c.weights["new_port"]), (0.0, 2.0));
        o.patch(&json!({"weights": {"new_port": null}, "min_score": null})).unwrap();
        let c = o.apply(&base);
        assert_eq!((c.min_score, c.weights["new_port"]), (30, 0.5), "back to the command-line value, not the built-in one");
        let d = describe(&base, &o);
        let np = d["rules"].as_array().unwrap().iter().find(|r| r["id"] == "new_port").unwrap();
        assert_eq!((np["weight"].as_f64(), np["overridden"].as_bool()), (Some(0.5), Some(false)));
        let nd = d["rules"].as_array().unwrap().iter().find(|r| r["id"] == "new_device").unwrap();
        assert_eq!((nd["enabled"].as_bool(), nd["overridden"].as_bool()), (Some(false), Some(true)));
        assert_eq!(d["any_override"], true);
        assert_eq!(describe(&base, &Overrides::default())["any_override"], false);
    }

    #[test]
    fn nonsense_is_refused_atomically() {
        let mut o = Overrides::default();
        for bad in [
            json!({"min_score": 101}), json!({"min_score": -1}), json!({"min_score": "x"}), json!({"min_score": 1.5}),
            json!({"weights": {"no_such_rule": 1}}), json!({"weights": {"new_device": 6}}), json!({"weights": {"new_device": -1}}),
            json!({"weights": {"new_device": "high"}}), json!({"weights": []}),
            json!({"params": {"volume_z_threshold": 0.1}}), json!({"params": {"silent_minutes": 100000}}), json!({"params": {"nope": 1}}),
            json!({"params": {"silent_minutes": null, "volume_z_threshold": 99}}),
            json!({"surprise": 1}), json!([1]), json!("x"),
        ] {
            assert!(o.patch(&bad).is_err(), "{bad}");
            assert_eq!(o, Overrides::default(), "a refused patch must change nothing: {bad}");
        }
        // NaN/infinity can only arrive as strings in JSON, and are refused as non-numbers
        assert!(o.patch(&json!({"params": {"volume_z_threshold": "NaN"}})).is_err());
    }

    #[test]
    fn overrides_survive_the_database() {
        let s = crate::store::sqlite::SqliteStore::open_in_memory().unwrap();
        assert_eq!(load(&s).unwrap(), Overrides::default());
        let mut o = Overrides::default();
        o.patch(&json!({"weights": {"arp_conflict": 1.5}, "params": {"arp_cooldown_min": 10}})).unwrap();
        save(&s, &o, 1).unwrap();
        assert_eq!(load(&s).unwrap(), o);
        s.set_setting(KEY, b"{not json", 2).unwrap();
        assert_eq!(load(&s).unwrap(), Overrides::default(), "a damaged value means defaults, never a crash");
    }

    fn asset_at(id: i64, ty: &str, ip: [u8; 4]) -> crate::model::Asset {
        let mut a = crate::model::Asset::new(crate::model::Mac([2, 0, 0, 0, 0, id as u8]), 1);
        a.id = id;
        a.device_type = ty.into();
        a.ip_history.push(crate::model::IpRecord { ip: std::net::Ipv4Addr::from(ip), first_seen: 1, last_seen: 1 });
        a
    }

    #[test]
    fn scopes_match_by_device_type_tag_and_network_and_are_validated() {
        let a = asset_at(7, "plc", [10, 1, 2, 3]);
        let meta = crate::model::AssetMeta { tags: vec!["Line1".into()], type_override: Some("hmi".into()), ..Default::default() };
        let s = |k: &str, v: &str| Scope { kind: k.into(), value: v.into() };
        assert!(s("device", "7").matches(&a, None) && !s("device", "8").matches(&a, None));
        assert!(s("type", "PLC").matches(&a, None), "case-insensitive");
        assert!(!s("type", "plc").matches(&a, Some(&meta)) && s("type", "hmi").matches(&a, Some(&meta)), "a type set by hand wins");
        assert!(s("tag", "line1").matches(&a, Some(&meta)) && !s("tag", "line1").matches(&a, None));
        assert!(s("cidr", "10.1.0.0/16").matches(&a, None) && !s("cidr", "10.2.0.0/16").matches(&a, None) && s("cidr", "0.0.0.0/0").matches(&a, None));
        for bad in [s("device", "abc"), s("cidr", "10.1.2.3"), s("cidr", "10.1.2.3/33"), s("cidr", "x/8"), s("colour", "red"), s("tag", ""), s("tag", &"x".repeat(61)), s("tag", "a\nb")] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        assert_eq!(s("tag", "  Lab ").check().unwrap().value, "Lab");
    }

    #[test]
    fn exceptions_and_watches_are_saved_validated_and_refused_atomically() {
        let mut o = Overrides::default();
        o.patch(&json!({"exceptions": {"new_device": [{"kind": "type", "value": "printer"}]},
            "ot_watches": [{"id": "w1", "name": " S7 stop ", "enabled": true, "proto": "s7", "controls": true, "commands": [" 0x29 ", ""],
                            "targets": [{"kind": "tag", "value": "line1"}], "allowed_senders": [], "score": 90, "cooldown_minutes": 5}]})).unwrap();
        assert_eq!(o.ot_watches[0].name, "S7 stop");
        assert_eq!(o.ot_watches[0].commands, vec!["0x29".to_string()]);
        let c = o.apply(&DetectConfig::default());
        assert_eq!(c.ot_watches.len(), 1, "the watches reach the detector");
        // an emptied list removes the exception; null too
        o.patch(&json!({"exceptions": {"new_device": []}})).unwrap();
        assert!(o.exceptions.is_empty());
        let before = o.clone();
        let w = |extra: Value| {
            let mut base = json!({"id": "w2", "name": "n", "enabled": true, "proto": "any", "writes": true, "score": 50, "cooldown_minutes": 10});
            for (k, v) in extra.as_object().unwrap() {
                base[k] = v.clone();
            }
            json!({"ot_watches": [base]})
        };
        for bad in [
            json!({"exceptions": {"no_such_rule": []}}), json!({"exceptions": {"new_device": [{"kind": "cidr", "value": "nope"}]}}),
            json!({"exceptions": {"new_device": "all"}}), json!({"exceptions": []}),
            w(json!({"id": "Has Space"})), w(json!({"name": ""})), w(json!({"proto": "telnet"})), w(json!({"score": 0})), w(json!({"score": 101})),
            w(json!({"cooldown_minutes": 0})), w(json!({"writes": false})), // matches nothing
            w(json!({"commands": vec!["x"; 11], "writes": false})),
            w(json!({"targets": [{"kind": "device", "value": "x"}]})),
            json!({"ot_watches": [{"id": "a", "name": "n", "enabled": true, "proto": "any", "writes": true, "score": 5, "cooldown_minutes": 1},
                                  {"id": "a", "name": "m", "enabled": true, "proto": "any", "writes": true, "score": 5, "cooldown_minutes": 1}]}),
            json!({"ot_watches": "all"}),
        ] {
            assert!(o.patch(&bad).is_err(), "{bad}");
            assert_eq!(o, before, "a refused change changes nothing: {bad}");
        }
        // too many
        let many: Vec<Value> = (0..=MAX_WATCHES).map(|i| json!({"id": format!("w{i}"), "name": "n", "enabled": true, "proto": "any", "writes": true, "score": 5, "cooldown_minutes": 1})).collect();
        assert!(o.patch(&json!({"ot_watches": many})).is_err());
        // it all shows up in the description the console reads
        let d = describe(&DetectConfig::default(), &o);
        assert!(d["ot_watches"].is_array() && d["exceptions"].is_object() && d["watch_protocols"].as_array().unwrap().len() > 5);
    }
}
