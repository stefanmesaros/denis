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
    /// A closed aggregation window of flow records.
    Flows(Vec<FlowRecord>),
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
