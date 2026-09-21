//! Core data types shared by capture, storage, engine and web layers.
//!
//! `Asset` and `Event` carry a nullable `agent_id` from day one so the Phase 2
//! master/agent split does not need to reshape stored data.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// 48-bit MAC address. Serialised as `aa:bb:cc:dd:ee:ff`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Group (multicast/broadcast) addresses are never a device identity.
    pub fn is_unicast(&self) -> bool {
        self.0[0] & 0x01 == 0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    /// A usable device identity: unicast and non-zero.
    pub fn is_valid(&self) -> bool {
        self.is_unicast() && !self.is_zero()
    }

    /// Locally-administered bit: set on randomised ("private") Wi-Fi addresses,
    /// which have no meaningful OUI vendor.
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Mac {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 6];
        let mut parts = s.split(':');
        for byte in out.iter_mut() {
            let p = parts.next().ok_or_else(|| format!("bad MAC {s:?}"))?;
            *byte = u8::from_str_radix(p, 16).map_err(|_| format!("bad MAC {s:?}"))?;
        }
        if parts.next().is_some() {
            return Err(format!("bad MAC {s:?}"));
        }
        Ok(Mac(out))
    }
}

impl Serialize for Mac {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Mac {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpRecord {
    pub ip: Ipv4Addr,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPort {
    pub port: u16,
    pub proto: String,
    pub service: Option<String>,
}

/// TCP SYN / SYN-ACK signature used for passive OS guessing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpSig {
    pub ttl: u8,
    pub window: u16,
    /// Option kinds in wire order, one letter each: M(SS) N(OP) W(scale)
    /// S(ACK-permitted) T(imestamp) E(OL) ?(other).
    pub options: String,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
}

/// Raw evidence collected about a device; the device-type / OS guess is a
/// pure function of this plus vendor, hostnames and open ports.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub dhcp_vendor_class: Option<String>,
    pub dhcp_param_list: Option<String>,
    pub mdns_services: Vec<String>,
    pub mdns_names: Vec<String>,
    pub mdns_models: Vec<String>,
    pub ssdp_server: Option<String>,
    pub ssdp_types: Vec<String>,
    pub tcp_sig: Option<TcpSig>,
    pub ttl: Option<u8>,
    /// Industrial / building-automation protocols this device speaks, and in
    /// which role (learned passively from the wire).
    #[serde(default)]
    pub ot: std::collections::BTreeMap<String, OtRole>,
    /// Self-reported identity from LLDP/CDP/PROFINET/EtherNet-IP/BACnet, keyed
    /// `source.field` (e.g. `lldp.system_name`, `enip.product_name`).
    #[serde(default)]
    pub identity: std::collections::BTreeMap<String, String>,
}

/// Role of a device in one industrial protocol.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OtRole {
    /// Answers requests (PLC, RTU, drive, sensor...).
    pub server: bool,
    /// Sends requests (HMI, SCADA, engineering workstation...).
    pub client: bool,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asset {
    pub id: i64,
    pub agent_id: Option<String>,
    pub mac: Mac,
    pub vendor: Option<String>,
    /// True when the MAC is locally administered (randomised / virtual).
    pub randomized_mac: bool,
    pub ip_history: Vec<IpRecord>,
    pub hostnames: Vec<String>,
    pub device_type: String,
    pub os_guess: Option<String>,
    /// Why the guess was made; makes wrong guesses debuggable.
    pub guess_reasons: Vec<String>,
    pub open_ports: Vec<OpenPort>,
    /// Unix seconds of the last completed port scan, if any.
    pub ports_scanned_at: Option<i64>,
    pub fingerprint: Fingerprint,
    pub is_self: bool,
    pub is_gateway: bool,
    pub first_seen: i64,
    pub last_seen: i64,
}

impl Asset {
    pub fn new(mac: Mac, now: i64) -> Self {
        Asset {
            id: 0,
            agent_id: None,
            mac,
            vendor: None,
            randomized_mac: mac.is_locally_administered(),
            ip_history: Vec::new(),
            hostnames: Vec::new(),
            device_type: "unknown".into(),
            os_guess: None,
            guess_reasons: Vec::new(),
            open_ports: Vec::new(),
            ports_scanned_at: None,
            fingerprint: Fingerprint::default(),
            is_self: false,
            is_gateway: false,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Most recently seen IP.
    pub fn current_ip(&self) -> Option<Ipv4Addr> {
        self.ip_history
            .iter()
            .max_by_key(|r| r.last_seen)
            .map(|r| r.ip)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub agent_id: Option<String>,
    pub asset_id: i64,
    /// `new_device`, `new_destination`, `volume_anomaly`; Phase 3 adds
    /// `arp_conflict`, ...
    #[serde(rename = "type")]
    pub kind: String,
    pub timestamp: i64,
    /// `info`, `low`, `medium`, `high`. `info` is a log entry, not an alert.
    pub severity: String,
    /// 0-100. Info events carry 0. Rules scale this by a per-rule weight so a
    /// noisy rule can be turned down without being disabled.
    pub score: i32,
    pub acked: bool,
    pub raw_details: serde_json::Value,
}

/// One fact learned from the wire (passive capture) or from an active probe.
#[derive(Clone, Debug)]
pub enum Observation {
    /// This machine itself (never seen on its own wire).
    SelfHost {
        mac: Mac,
        ip: Ipv4Addr,
        hostname: Option<String>,
    },
    Arp {
        mac: Mac,
        ip: Ipv4Addr,
    },
    Dhcp {
        mac: Mac,
        ip: Option<Ipv4Addr>,
        hostname: Option<String>,
        vendor_class: Option<String>,
        param_list: Option<String>,
    },
    Mdns {
        mac: Mac,
        ip: Ipv4Addr,
        hostnames: Vec<String>,
        services: Vec<String>,
        names: Vec<String>,
        models: Vec<String>,
    },
    Ssdp {
        mac: Mac,
        ip: Ipv4Addr,
        server: Option<String>,
        types: Vec<String>,
    },
    Tcp {
        mac: Mac,
        ip: Ipv4Addr,
        sig: TcpSig,
    },
    /// ICMP echo reply (TTL only).
    Ttl {
        mac: Mac,
        ip: Ipv4Addr,
        ttl: u8,
    },
    /// Result of an active port scan; resolved to an asset by IP.
    Ports {
        ip: Ipv4Addr,
        open: Vec<OpenPort>,
    },
    /// One packet's worth of traffic. Folded into `Flows` by the capture thread
    /// and never reaches the inventory.
    FlowSample(FlowSample),
    /// A closed aggregation window of flow and conversation records.
    Flows(FlowBatch),
    /// A suspicious fact noticed on the wire (e.g. an ARP sender-address mismatch).
    Signal(Signal),
    /// One industrial-protocol message between two local devices.
    Ot(OtSample),
    /// Self-reported identity from a link-layer or industrial protocol.
    Link(LinkInfo),
}

/// What an industrial message *does*, coarse enough to reason about safely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtClass {
    /// Reads values or configuration.
    Read,
    /// Writes values (registers, coils, tags, setpoints).
    Write,
    /// Changes the controller's state: STOP/START, program download, restart,
    /// operate/select commands. The actions that matter most in OT.
    Control,
    /// Asks a device who it is (device identification, Who-Is, ListIdentity).
    Identify,
    /// Session set-up, acknowledgements, responses, anything else.
    Other,
}

/// A decoded industrial protocol data unit.
#[derive(Clone, Debug, PartialEq)]
pub struct OtPdu {
    /// Protocol name: `modbus`, `s7`, `enip`, `dnp3`, `bacnet`, `opcua`, `iec104`.
    pub proto: &'static str,
    /// The source is the server/outstation/PLC side (a response or announcement).
    pub server_is_src: bool,
    /// Only requests carry a class; responses are `Other`.
    pub class: OtClass,
    /// Human-readable function, e.g. `write multiple registers (16)`.
    pub detail: String,
    /// The transport port of the server side.
    pub port: u16,
    /// Identity announced by this message (EtherNet/IP ListIdentity, BACnet I-Am).
    pub identity: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OtSample {
    pub src_mac: Mac,
    pub dst_mac: Mac,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub bytes: u32,
    pub pdu: OtPdu,
}

/// Identity learned from a discovery protocol, attached to the sending MAC.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkInfo {
    pub mac: Mac,
    /// `lldp`, `cdp` or `profinet`.
    pub source: &'static str,
    pub ip: Option<Ipv4Addr>,
    pub fields: std::collections::BTreeMap<String, String>,
}

/// One conversation between a client and a server over one industrial
/// protocol in one window (the "communications matrix" row).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConvRecord {
    pub client_mac: Mac,
    pub server_mac: Mac,
    pub client_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub proto: String,
    pub port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub reads: u64,
    pub writes: u64,
    /// STOP/START, download, restart, operate: the alarming ones.
    pub controls: u64,
    /// Example of the most severe function seen (`PLC stop (0x29)`).
    pub note: Option<String>,
    /// Which functions were used and how often in this window (`write single register (6)`: 12). Bounded.
    #[serde(default)]
    pub commands: std::collections::BTreeMap<String, u32>,
    pub window_start: i64,
    pub window_secs: u32,
}

/// Everything one closed capture window produced.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowBatch {
    pub flows: Vec<FlowRecord>,
    pub convs: Vec<ConvRecord>,
}

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Clone, Debug, PartialEq)]
pub struct FlowSample {
    /// The local device (Ethernet source when outbound, destination when inbound).
    pub mac: Mac,
    pub remote: Ipv4Addr,
    pub proto: u8,
    pub port: u16,
    pub bytes: u32,
    pub outbound: bool,
}

/// Traffic between one local device and one remote address in one window.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowRecord {
    pub mac: Mac,
    pub remote: Ipv4Addr,
    pub proto: u8,
    /// Service port: the smaller of the two ports (clients use ephemeral ones).
    pub port: u16,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub packets: u64,
    pub window_start: i64,
    pub window_secs: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DestStat {
    pub first_seen: i64,
    pub last_seen: i64,
    pub bytes: u64,
}

/// Exponentially-weighted mean/variance of outbound bytes per bucket.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VolumeStats {
    pub n: u32,
    pub mean: f64,
    pub var: f64,
}

/// What "normal" looks like for one device. Fields follow the brief's Baseline
/// entity; `active_hours` (UTC) is collected now and used by Phase 3 rules.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub asset_id: i64,
    pub typical_destinations: std::collections::BTreeMap<String, DestStat>,
    /// `tcp/443` -> number of windows seen.
    pub typical_ports: std::collections::BTreeMap<String, u64>,
    pub volume: VolumeStats,
    pub active_hours: [u32; 24],
    /// First time any traffic from this device was observed.
    pub observed_since: i64,
    pub buckets: u64,
    pub updated_at: i64,
}

impl Baseline {
    pub fn new(asset_id: i64, now: i64) -> Self {
        Baseline {
            asset_id,
            typical_destinations: Default::default(),
            typical_ports: Default::default(),
            volume: VolumeStats::default(),
            active_hours: [0; 24],
            observed_since: now,
            buckets: 0,
            updated_at: now,
        }
    }
}

pub fn proto_name(p: u8) -> &'static str {
    match p {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        PROTO_ICMP => "icmp",
        _ => "ip",
    }
}

/// A remote collector registered with the master.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub site: Option<String>,
    pub version: String,
    pub subnet: String,
    pub first_seen: i64,
    pub last_report_at: i64,
    /// Idempotency: the last (run, sequence) batch applied from this agent.
    pub last_run_id: String,
    pub last_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentMeta {
    pub id: String,
    pub name: String,
    pub site: Option<String>,
    pub version: String,
    pub subnet: String,
}

/// Agent -> master batch. Assets are upserted by `(agent id, mac)`; flow
/// records are additive, so a `(run_id, seq)` the master has already applied is
/// acknowledged but not re-applied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub agent: AgentMeta,
    pub run_id: String,
    pub seq: u64,
    pub sent_at: i64,
    pub assets: Vec<Asset>,
    pub flows: Vec<FlowRecord>,
    /// Absent in reports from Phase 2 agents.
    #[serde(default)]
    pub signals: Vec<Signal>,
    /// Industrial conversations (absent in reports from older agents).
    #[serde(default)]
    pub conversations: Vec<ConvRecord>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReportAck {
    pub seq: u64,
    pub assets: usize,
    pub flows: usize,
    pub duplicate: bool,
}

pub fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip() {
        let m: Mac = "aa:bb:cc:00:11:22".parse().unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:00:11:22");
        assert!("aa:bb:cc".parse::<Mac>().is_err());
        assert!("aa:bb:cc:00:11:22:33".parse::<Mac>().is_err());
        assert!("zz:bb:cc:00:11:22".parse::<Mac>().is_err());
    }

    #[test]
    fn mac_flags() {
        assert!(!Mac([0xff; 6]).is_valid());
        assert!(!Mac([0x01, 0, 0x5e, 0, 0, 1]).is_valid());
        assert!(!Mac([0; 6]).is_valid());
        let private = Mac([0x3a, 1, 2, 3, 4, 5]);
        assert!(private.is_valid() && private.is_locally_administered());
        assert!(!Mac([0x00, 0x1b, 0x63, 1, 2, 3]).is_locally_administered());
    }
}


/// A raw suspicious observation from a collector. Collectors *notice* (only
/// they see the frames); the master *judges* (scores, deduplicates, alerts).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    /// `arp_conflict`: an address is claimed by a second MAC while the first
    /// still holds it. `arp_mismatch`: ARP sender hardware address differs
    /// from the Ethernet source.
    pub kind: String,
    pub ts: i64,
    /// The claimant (the MAC that appeared).
    pub mac: Mac,
    pub ip: Ipv4Addr,
    /// The previous holder of `ip`, or the hardware address the frame claimed.
    pub other_mac: Option<Mac>,
    /// The contested address is the default gateway.
    pub gateway: bool,
}

/// Hours in which a device was seen, for "was reliably online" judgements.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Presence {
    pub asset_id: i64,
    /// Unix hour indices (`ts / 3600`), pruned to the last 14 days.
    pub hours: std::collections::BTreeSet<i64>,
    /// A silence alert has been raised and the device has not been seen since.
    pub silent_alerted: bool,
}

/// One 5-minute sample of network health for the trend charts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    pub ts: i64,
    /// `""` for the local collector, else the agent id.
    pub agent_id: String,
    pub devices_total: i64,
    pub devices_online: i64,
    /// Bytes to/from outside the LAN during this interval.
    pub bytes_out: i64,
    pub bytes_in: i64,
    pub alerts: i64,
}


/// Manually maintained information about an asset. Kept apart from everything
/// discovered so a re-scan never overwrites what a person typed, and an edit
/// never gets lost when a device is re-fingerprinted.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetMeta {
    /// Shown instead of the discovered hostname.
    pub display_name: Option<String>,
    pub asset_tag: Option<String>,
    pub serial_number: Option<String>,
    pub model: Option<String>,
    /// Overrides the OUI vendor.
    pub manufacturer: Option<String>,
    /// Corrects a wrong device-type guess.
    pub type_override: Option<String>,
    pub os_override: Option<String>,
    pub owner: Option<String>,
    pub department: Option<String>,
    pub location: Option<String>,
    pub supplier: Option<String>,
    /// `YYYY-MM-DD`
    pub purchase_date: Option<String>,
    pub purchase_price: Option<String>,
    /// `YYYY-MM-DD`
    pub warranty_expires: Option<String>,
    /// `active` (default), `spare`, `retired`, `lost`, `stolen`.
    pub status: Option<String>,
    /// `low`, `normal` (default), `high`, `critical`: scales how much its
    /// alerts weigh in the risk score.
    pub criticality: Option<String>,
    pub notes: Option<String>,
    /// Icon shown in the UI; `None` = chosen automatically from the device type.
    pub icon: Option<String>,
    /// Network zone / cell, free text (e.g. "Line 3 cell", "DMZ").
    pub zone: Option<String>,
    /// Purdue model level for OT assets: `0`, `1`, `2`, `3`, `3.5`, `4`, `5`.
    pub purdue_level: Option<String>,
    /// `YYYY-MM-DD`: no outgoing notifications (chat, e-mail, …) about this device until the
    /// end of that day (planned maintenance, a test bench). Alerts still show in the console.
    pub muted_until: Option<String>,
    pub tags: Vec<String>,
    pub custom: std::collections::BTreeMap<String, String>,
    /// Created by hand rather than discovered (may not exist on the wire yet).
    pub manual: bool,
    /// A person has looked at this device and accepted it as known (the review queue).
    #[serde(default)]
    pub reviewed: bool,
    /// Part of the built-in demo data (fictional; removable in one step).
    #[serde(default)]
    pub demo: bool,
}

/// One accepted change, for the audit trail.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub field: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    /// `viewer`, `editor`, `admin`
    pub role: String,
    pub created_at: i64,
    pub disabled: bool,
    /// The password was set by someone else; it must be changed at next login.
    pub must_change: bool,
    pub last_login: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: i64,
    pub user: String,
    pub action: String,
    pub asset_id: Option<i64>,
    pub detail: serde_json::Value,
}


/// A person's decision to live with a finding on one device ("accept the risk"), with the reason and, usually, an end date.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RiskAcceptance {
    pub id: i64,
    /// The kind of finding (`telnet_open`, `ftp_open`…).
    pub finding_id: String,
    pub asset_id: i64,
    pub reason: String,
    pub accepted_by: String,
    pub accepted_at: i64,
    /// After this the finding counts again; `None` = until someone withdraws the decision.
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
}

impl RiskAcceptance {
    /// In force at `now`: not withdrawn and not expired.
    pub fn is_active(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| e > now)
    }
}

/// A persistent row of the communications matrix: which asset talks to which
/// over which industrial protocol, and what kind of messages it sends.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Conversation {
    pub client_id: i64,
    pub server_id: i64,
    pub proto: String,
    pub port: u16,
    pub first_seen: i64,
    pub last_seen: i64,
    pub packets: i64,
    pub bytes: i64,
    pub reads: i64,
    pub writes: i64,
    pub controls: i64,
    /// Example of the most severe function ever seen on this path.
    pub note: Option<String>,
    /// Every function seen on this path and how often (bounded to [`MAX_COMMANDS`]).
    #[serde(default)]
    pub commands: std::collections::BTreeMap<String, i64>,
}

/// The most distinct functions remembered per path (a hostile sender must not grow it without limit).
pub const MAX_COMMANDS: usize = 32;
