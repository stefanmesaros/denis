//! Passive decoding of industrial (OT) and building-automation protocols, plus
//! the link-layer discovery protocols (LLDP, CDP, PROFINET DCP) that let
//! devices announce who they are.
//!
//! Everything here is a pure function over bytes taken from the network, so:
//! * nothing is ever sent (safe on fragile OT networks),
//! * every length is bounds-checked (frames are attacker-controlled),
//! * each decoder insists on the protocol's own signature (magic bytes,
//!   consistent length fields) so ordinary traffic that merely uses the same
//!   port number is not mistaken for industrial traffic.
//!
//! Decoding is deliberately shallow: enough to say *which protocol*, *which
//! side is the server*, and *whether the message reads, writes or changes the
//! controller's state*. That last distinction ("STOP CPU", "program download")
//! is the one OT security cares about most.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::model::{OtClass, OtPdu};
use crate::parse::clean_str;

/// Well-known industrial server ports. Traffic to/from these towards the
/// *outside* of the network is an exposure finding on its own.
pub const OT_PORTS: &[(u16, &str)] = &[
    (502, "modbus"),
    (102, "s7"),
    (44818, "enip"),
    (20000, "dnp3"),
    (47808, "bacnet"),
    (4840, "opcua"),
    (2404, "iec104"),
    (1911, "niagara-fox"),
    (9600, "omron-fins"),
    (18245, "ge-srtp"),
    (5007, "melsec"),
    (1962, "pcworx"),
    (2455, "codesys"),
];

/// Protocol name for an OT server port, if it is one.
pub fn ot_proto_for_port(port: u16) -> Option<&'static str> {
    OT_PORTS.iter().find(|(p, _)| *p == port).map(|(_, n)| *n)
}

fn pdu(proto: &'static str, server_is_src: bool, class: OtClass, detail: impl Into<String>, port: u16) -> OtPdu {
    OtPdu { proto, server_is_src, class, detail: detail.into(), port, identity: BTreeMap::new() }
}

/// Decode one TCP/UDP payload as an industrial protocol, choosing the decoder
/// by the transport port. Returns `None` unless the payload carries that
/// protocol's signature.
pub fn parse_pdu(is_tcp: bool, sport: u16, dport: u16, payload: &[u8]) -> Option<OtPdu> {
    // The server is the side on the well-known port.
    let server_port = |p: u16| (sport == p || dport == p).then_some(p);
    if is_tcp {
        if let Some(p) = server_port(502) {
            return modbus(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(102) {
            return s7(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(44818) {
            return enip(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(20000) {
            return dnp3(payload, p);
        }
        if let Some(p) = server_port(4840) {
            return opcua(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(2404) {
            return iec104(payload, sport == p && dport != p, p);
        }
    } else {
        if let Some(p) = server_port(47808) {
            return bacnet(payload, p);
        }
        if let Some(p) = server_port(44818) {
            return enip(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(20000) {
            return dnp3(payload, p);
        }
    }
    None
}

// ------------------------------------------------------------------ Modbus

fn modbus_fn_name(f: u8) -> &'static str {
    match f {
        1 => "read coils",
        2 => "read discrete inputs",
        3 => "read holding registers",
        4 => "read input registers",
        5 => "write single coil",
        6 => "write single register",
        7 => "read exception status",
        8 => "diagnostics",
        15 => "write multiple coils",
        16 => "write multiple registers",
        17 => "report server id",
        20 => "read file record",
        21 => "write file record",
        22 => "mask write register",
        23 => "read/write multiple registers",
        43 => "read device identification",
        _ => "function",
    }
}

/// Modbus/TCP: a 7-byte MBAP header (protocol id must be 0, length must match)
/// followed by the function code.
fn modbus(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    if b.len() < 8 || b[2] != 0 || b[3] != 0 {
        return None;
    }
    let len = u16::from_be_bytes([b[4], b[5]]) as usize;
    if len < 2 || len > b.len() - 6 {
        return None;
    }
    let fc = b[7];
    if server_is_src {
        let exc = fc & 0x80 != 0;
        let detail = if exc { format!("exception response ({:#04x})", fc & 0x7f) } else { "response".to_string() };
        return Some(pdu("modbus", true, OtClass::Other, detail, port));
    }
    let class = match fc {
        1..=4 | 20 => OtClass::Read,
        5 | 6 | 15 | 16 | 21 | 22 | 23 => OtClass::Write,
        43 | 17 => OtClass::Identify,
        // Diagnostics sub-functions 1 (restart communications) and 4 (force
        // listen-only) take a device off the bus.
        8 if b.len() >= 10 && matches!(u16::from_be_bytes([b[8], b[9]]), 1 | 4) => OtClass::Control,
        _ => OtClass::Other,
    };
    Some(pdu("modbus", false, class, format!("{} ({fc})", modbus_fn_name(fc)), port))
}

// ---------------------------------------------------------------------- S7

/// Siemens S7comm over ISO-on-TCP: TPKT, COTP, then the S7 header (0x32).
fn s7(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    // TPKT: version 3, reserved 0, length.
    if b.len() < 7 || b[0] != 3 || b[1] != 0 || u16::from_be_bytes([b[2], b[3]]) as usize > b.len() {
        return None;
    }
    let li = b[4] as usize; // COTP length indicator
    match b[5] {
        // connection request/confirm: identifies the server but carries no S7
        0xe0 | 0xd0 => return Some(pdu("s7", server_is_src, OtClass::Other, "connection setup", port)),
        0xf0 => {} // data
        _ => return None,
    }
    let h = 5 + li; // start of the S7 header
    if b.len() < h + 10 || b[h] != 0x32 {
        return None;
    }
    let rosctr = b[h + 1];
    if rosctr != 1 {
        // acks / userdata: session traffic
        return Some(pdu("s7", server_is_src, OtClass::Other, "acknowledgement / userdata", port));
    }
    let func = *b.get(h + 10)?; // first parameter byte of a Job
    let (class, name) = match func {
        0x04 => (OtClass::Read, "read variable"),
        0x05 => (OtClass::Write, "write variable"),
        0x1a..=0x1c => (OtClass::Control, "program download"),
        0x1d..=0x1f => (OtClass::Read, "program upload"),
        0x28 => (OtClass::Control, "PLC control (start/restart)"),
        0x29 => (OtClass::Control, "PLC stop"),
        0xf0 => (OtClass::Other, "setup communication"),
        _ => (OtClass::Other, "job"),
    };
    Some(pdu("s7", server_is_src, class, format!("{name} ({func:#04x})"), port))
}

// ------------------------------------------------------------- EtherNet/IP

const ENIP_COMMANDS: &[u16] = &[0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006f, 0x0070];

/// EtherNet/IP encapsulation (24-byte header). ListIdentity responses carry the
/// device's vendor, product name and serial number; SendRRData/SendUnitData
/// carry CIP services whose first byte says read/write/start/stop.
fn enip(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    if b.len() < 24 {
        return None;
    }
    let cmd = u16::from_le_bytes([b[0], b[1]]);
    let len = u16::from_le_bytes([b[2], b[3]]) as usize;
    if !ENIP_COMMANDS.contains(&cmd) || len > b.len() - 24 {
        return None;
    }
    let data = &b[24..24 + len];
    match cmd {
        0x0063 => {
            let mut p = pdu("enip", server_is_src, OtClass::Identify, if server_is_src { "identity response" } else { "list identity" }, port);
            if server_is_src {
                p.identity = enip_identity(data).unwrap_or_default();
            }
            Some(p)
        }
        0x006f | 0x0070 if !server_is_src => {
            let svc = enip_cip_service(data);
            let (class, name) = match svc {
                Some(0x0e) | Some(0x01) | Some(0x03) | Some(0x4c) | Some(0x4e) => (OtClass::Read, "read"),
                Some(0x10) | Some(0x02) | Some(0x4d) | Some(0x4f) => (OtClass::Write, "write"),
                Some(0x05) => (OtClass::Control, "reset"),
                Some(0x06) => (OtClass::Control, "start"),
                Some(0x07) => (OtClass::Control, "stop"),
                Some(0x54) | Some(0x5b) => (OtClass::Control, "forward open (connection set-up)"),
                _ => (OtClass::Other, "CIP message"),
            };
            let detail = match svc {
                Some(s) => format!("CIP {name} (service {s:#04x})"),
                None => name.to_string(),
            };
            Some(pdu("enip", false, class, detail, port))
        }
        0x0065 | 0x0066 => Some(pdu("enip", server_is_src, OtClass::Other, "session", port)),
        _ => Some(pdu("enip", server_is_src, OtClass::Other, format!("encapsulation command {cmd:#06x}"), port)),
    }
}

/// First CIP service code inside a SendRRData / SendUnitData payload.
fn enip_cip_service(data: &[u8]) -> Option<u8> {
    // interface handle (4) + timeout (2) + item count (2), then items:
    // type (2), length (2), data. 0x00b2 = unconnected data, 0x00b1 = connected
    // data (which starts with a 2-byte sequence number).
    let count = u16::from_le_bytes([*data.get(6)?, *data.get(7)?]) as usize;
    let mut i = 8;
    for _ in 0..count.min(8) {
        let ty = u16::from_le_bytes([*data.get(i)?, *data.get(i + 1)?]);
        let len = u16::from_le_bytes([*data.get(i + 2)?, *data.get(i + 3)?]) as usize;
        let item = data.get(i + 4..i + 4 + len)?;
        match ty {
            0x00b2 => return item.first().copied(),
            0x00b1 => return item.get(2).copied(),
            _ => i += 4 + len,
        }
    }
    None
}

fn enip_vendor(id: u16) -> Option<&'static str> {
    Some(match id {
        1 => "Rockwell Automation / Allen-Bradley",
        5 => "Rockwell Automation / Reliance",
        9 => "Omron",
        26 => "Festo",
        40 => "WAGO",
        47 => "Omron Corporation",
        50 => "Eaton / Cutler-Hammer",
        90 => "HMS Industrial Networks",
        243 => "Schneider Electric",
        283 => "Hilscher",
        _ => return None,
    })
}

/// ListIdentity reply: item count, then identity items (type 0x000c).
fn enip_identity(d: &[u8]) -> Option<BTreeMap<String, String>> {
    let count = u16::from_le_bytes([*d.first()?, *d.get(1)?]);
    if count == 0 || u16::from_le_bytes([*d.get(2)?, *d.get(3)?]) != 0x000c {
        return None;
    }
    let body = d.get(6..)?;
    // encapsulation version (2) + socket address (16), then the identity object
    let o = body.get(18..)?;
    let vendor = u16::from_le_bytes([*o.first()?, *o.get(1)?]);
    let dev_type = u16::from_le_bytes([*o.get(2)?, *o.get(3)?]);
    let product_code = u16::from_le_bytes([*o.get(4)?, *o.get(5)?]);
    let rev = (*o.get(6)?, *o.get(7)?);
    let serial = u32::from_le_bytes([*o.get(10)?, *o.get(11)?, *o.get(12)?, *o.get(13)?]);
    let name_len = *o.get(14)? as usize;
    let name = String::from_utf8_lossy(o.get(15..15 + name_len)?).to_string();
    let mut m = BTreeMap::new();
    m.insert("vendor".into(), enip_vendor(vendor).map_or_else(|| format!("vendor id {vendor}"), str::to_string));
    m.insert("device_type".into(), dev_type.to_string());
    m.insert("product_code".into(), product_code.to_string());
    m.insert("revision".into(), format!("{}.{}", rev.0, rev.1));
    m.insert("serial".into(), format!("{serial:08x}"));
    if let Some(n) = clean_str(&name) {
        m.insert("product_name".into(), n);
    }
    Some(m)
}

// -------------------------------------------------------------------- DNP3

/// DNP3 link layer (0x0564) + transport + application function code.
fn dnp3(b: &[u8], port: u16) -> Option<OtPdu> {
    if b.len() < 10 || b[0] != 0x05 || b[1] != 0x64 || b[2] < 5 {
        return None;
    }
    let from_master = b[3] & 0x80 != 0; // DIR bit
    let server_is_src = !from_master;
    if b.len() < 13 || b[2] < 8 {
        // link-layer only (reset/ack/status): identifies the roles, nothing more
        return Some(pdu("dnp3", server_is_src, OtClass::Other, "link layer", port));
    }
    let func = b[12];
    if server_is_src {
        return Some(pdu("dnp3", true, OtClass::Other, "response", port));
    }
    let (class, name) = match func {
        1 => (OtClass::Read, "read"),
        2 => (OtClass::Write, "write"),
        3 => (OtClass::Control, "select"),
        4 => (OtClass::Control, "operate"),
        5 | 6 => (OtClass::Control, "direct operate"),
        13 => (OtClass::Control, "cold restart"),
        14 => (OtClass::Control, "warm restart"),
        17 => (OtClass::Control, "start application"),
        18 => (OtClass::Control, "stop application"),
        20 | 21 => (OtClass::Write, "enable/disable unsolicited"),
        _ => (OtClass::Other, "function"),
    };
    Some(pdu("dnp3", false, class, format!("{name} ({func})"), port))
}

// ------------------------------------------------------------------ BACnet

/// BACnet/IP: BVLC (0x81), NPDU, APDU. Confirmed WriteProperty /
/// ReinitializeDevice / DeviceCommunicationControl are the notable services;
/// an I-Am announcement carries the device instance and vendor id.
fn bacnet(b: &[u8], port: u16) -> Option<OtPdu> {
    if b.len() < 6 || b[0] != 0x81 || u16::from_be_bytes([b[2], b[3]]) as usize != b.len() {
        return None;
    }
    // BVLC function 0x04 (forwarded NPDU) has a 6-byte origin address first.
    let mut i = if b[1] == 0x04 { 10 } else { 4 };
    if *b.get(i)? != 1 {
        return None; // NPDU version
    }
    let ctrl = *b.get(i + 1)?;
    i += 2;
    if ctrl & 0x20 != 0 {
        i += 3 + *b.get(i + 2)? as usize; // DNET(2) DLEN(1) DADR
    }
    if ctrl & 0x08 != 0 {
        i += 3 + *b.get(i + 2)? as usize; // SNET(2) SLEN(1) SADR
    }
    if ctrl & 0x20 != 0 {
        i += 1; // hop count
    }
    if ctrl & 0x80 != 0 {
        return Some(pdu("bacnet", false, OtClass::Other, "network layer message", port));
    }
    let apdu = b.get(i..)?;
    let kind = *apdu.first()? >> 4;
    match kind {
        // confirmed request: [type/flags][max segs][invoke id][service]
        0 => {
            let service = *apdu.get(3)?;
            let (class, name) = match service {
                12 | 14 => (OtClass::Read, "read property"),
                15 | 16 => (OtClass::Write, "write property"),
                17 => (OtClass::Control, "device communication control"),
                20 => (OtClass::Control, "reinitialize device"),
                _ => (OtClass::Other, "service"),
            };
            Some(pdu("bacnet", false, class, format!("{name} ({service})"), port))
        }
        // unconfirmed request: [type][service]
        1 => match *apdu.get(1)? {
            0 => {
                let mut p = pdu("bacnet", true, OtClass::Identify, "I-Am", port);
                p.identity = bacnet_i_am(apdu.get(2..)?).unwrap_or_default();
                Some(p)
            }
            8 => Some(pdu("bacnet", false, OtClass::Identify, "Who-Is", port)),
            s => Some(pdu("bacnet", false, OtClass::Other, format!("unconfirmed service ({s})"), port)),
        },
        // simple ack, complex ack, segment ack, error, reject, abort: responses
        2..=7 => Some(pdu("bacnet", true, OtClass::Other, "response", port)),
        _ => None,
    }
}

/// I-Am parameters: object identifier, max APDU, segmentation, vendor id.
fn bacnet_i_am(d: &[u8]) -> Option<BTreeMap<String, String>> {
    if *d.first()? != 0xc4 {
        return None;
    }
    let obj = u32::from_be_bytes([*d.get(1)?, *d.get(2)?, *d.get(3)?, *d.get(4)?]);
    let (obj_type, instance) = (obj >> 22, obj & 0x3f_ffff);
    // skip max-APDU (unsigned) and segmentation (enumerated) to reach the vendor id
    let mut i = 5;
    for _ in 0..2 {
        i += 1 + (*d.get(i)? & 0x07) as usize;
    }
    let vt = *d.get(i)?;
    let n = (vt & 0x07) as usize;
    let vendor = d.get(i + 1..i + 1 + n)?.iter().fold(0u32, |a, b| (a << 8) | *b as u32);
    let mut m = BTreeMap::new();
    if obj_type == 8 {
        m.insert("device_instance".into(), instance.to_string());
    }
    m.insert("vendor".into(), bacnet_vendor(vendor).map_or_else(|| format!("vendor id {vendor}"), str::to_string));
    Some(m)
}

fn bacnet_vendor(id: u32) -> Option<&'static str> {
    Some(match id {
        5 => "Johnson Controls",
        7 => "Siemens Building Technologies",
        8 => "Delta Controls",
        10 => "Schneider Electric",
        11 => "TAC / Schneider",
        24 => "Honeywell",
        36 => "Trane",
        42 => "Automated Logic",
        95 => "Distech Controls",
        343 => "Tridium / Niagara",
        _ => return None,
    })
}

// ----------------------------------------------------------------- OPC UA

/// OPC UA binary: a 3-letter message type, a chunk flag and the message size.
fn opcua(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    if b.len() < 8 || !matches!(&b[0..3], b"HEL" | b"ACK" | b"OPN" | b"MSG" | b"CLO" | b"ERR" | b"RHE")
        || !matches!(b[3], b'F' | b'C' | b'A')
        || u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize > b.len().max(1) + 65_536
    {
        return None;
    }
    // The service inside MSG (read, write, call...) is not decoded: that needs
    // the full node-id machinery, so OPC UA traffic is reported as "Other".
    Some(pdu("opcua", server_is_src, OtClass::Other, String::from_utf8_lossy(&b[0..3]).to_string(), port))
}

// ----------------------------------------------------------------- IEC 104

/// IEC 60870-5-104: APCI start byte 0x68; I-frames carry an ASDU whose type id
/// tells commands (45..=64, clock sync, reset) from monitoring data.
fn iec104(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    if b.len() < 6 || b[0] != 0x68 || b[1] < 4 || b[1] as usize > b.len() - 2 {
        return None;
    }
    if b[2] & 1 != 0 {
        return Some(pdu("iec104", server_is_src, OtClass::Other, "supervisory / control frame", port));
    }
    // I-format: type id at offset 6
    let type_id = *b.get(6)?;
    if server_is_src {
        return Some(pdu("iec104", true, OtClass::Other, format!("data (type {type_id})"), port));
    }
    let (class, name) = match type_id {
        45..=64 => (OtClass::Control, "command"),
        103 => (OtClass::Control, "clock synchronisation"),
        105 => (OtClass::Control, "reset process"),
        100 => (OtClass::Other, "interrogation"),
        _ => (OtClass::Other, "ASDU"),
    };
    Some(pdu("iec104", false, class, format!("{name} (type {type_id})"), port))
}

// ------------------------------------------------------ link-layer identity

fn sanitize(bytes: &[u8]) -> Option<String> {
    clean_str(&String::from_utf8_lossy(bytes))
}

/// LLDP (EtherType 0x88cc): a sequence of type/length/value fields. Switches,
/// access points, IP phones and many industrial devices announce themselves.
pub fn parse_lldp(mut b: &[u8]) -> Option<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    let mut seen_chassis = false;
    while b.len() >= 2 {
        let h = u16::from_be_bytes([b[0], b[1]]);
        let (ty, len) = (h >> 9, (h & 0x1ff) as usize);
        let v = b.get(2..2 + len)?;
        b = &b[2 + len..];
        match ty {
            0 => break,
            1 => {
                seen_chassis = true;
                if v.len() == 7 && v[0] == 4 {
                    m.insert("chassis_id".into(), format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", v[1], v[2], v[3], v[4], v[5], v[6]));
                } else if let Some(s) = v.get(1..).and_then(sanitize) {
                    m.insert("chassis_id".into(), s);
                }
            }
            2 => {
                if let Some(s) = v.get(1..).and_then(sanitize) {
                    m.insert("port_id".into(), s);
                }
            }
            4 => {
                if let Some(s) = sanitize(v) {
                    m.insert("port_description".into(), s);
                }
            }
            5 => {
                if let Some(s) = sanitize(v) {
                    m.insert("system_name".into(), s);
                }
            }
            6 => {
                if let Some(s) = sanitize(v) {
                    m.insert("system_description".into(), s);
                }
            }
            7 if v.len() >= 4 => {
                let enabled = u16::from_be_bytes([v[2], v[3]]);
                let names = ["other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station"];
                let caps: Vec<&str> = names.iter().enumerate().filter(|(i, _)| enabled & (1 << i) != 0).map(|(_, n)| *n).collect();
                if !caps.is_empty() {
                    m.insert("capabilities".into(), caps.join(","));
                }
            }
            8 if v.len() >= 7 && v[1] == 1 => {
                // management address, subtype 1 = IPv4
                m.insert("management_ip".into(), Ipv4Addr::new(v[2], v[3], v[4], v[5]).to_string());
            }
            _ => {}
        }
    }
    (seen_chassis && !m.is_empty()).then_some(m)
}

/// CDP (Cisco Discovery Protocol), after the LLC/SNAP header.
pub fn parse_cdp(b: &[u8]) -> Option<BTreeMap<String, String>> {
    let mut b = b.get(4..)?; // version, ttl, checksum
    let mut m = BTreeMap::new();
    while b.len() >= 4 {
        let (ty, len) = (u16::from_be_bytes([b[0], b[1]]), u16::from_be_bytes([b[2], b[3]]) as usize);
        if len < 4 || len > b.len() {
            break;
        }
        let v = &b[4..len];
        b = &b[len..];
        match ty {
            0x0001 => {
                if let Some(s) = sanitize(v) {
                    m.insert("system_name".into(), s);
                }
            }
            0x0003 => {
                if let Some(s) = sanitize(v) {
                    m.insert("port_id".into(), s);
                }
            }
            0x0004 if v.len() >= 4 => {
                let c = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                let names = [(0x01, "router"), (0x02, "bridge"), (0x08, "switch"), (0x10, "station"), (0x40, "repeater")];
                let caps: Vec<&str> = names.iter().filter(|(bit, _)| c & bit != 0).map(|(_, n)| *n).collect();
                if !caps.is_empty() {
                    m.insert("capabilities".into(), caps.join(","));
                }
            }
            0x0005 => {
                if let Some(s) = sanitize(v) {
                    m.insert("system_description".into(), s);
                }
            }
            0x0006 => {
                if let Some(s) = sanitize(v) {
                    m.insert("platform".into(), s);
                }
            }
            _ => {}
        }
    }
    (!m.is_empty()).then_some(m)
}

fn profinet_vendor(id: u16) -> Option<&'static str> {
    Some(match id {
        0x002a => "Siemens",
        0x0019 => "Phoenix Contact",
        0x011e => "Beckhoff",
        0x0009 => "Bosch Rexroth",
        0x0023 => "Turck",
        0x0093 => "Endress+Hauser",
        0x0021 => "Festo",
        0x0130 => "Hilscher",
        0x0079 => "Wago",
        0x0024 => "Pepperl+Fuchs",
        _ => return None,
    })
}

/// PROFINET DCP (EtherType 0x8892): an Identify/Hello *response* tells us the
/// station name, vendor and role of a device, and its IP.
pub fn parse_profinet_dcp(b: &[u8]) -> Option<(BTreeMap<String, String>, Option<Ipv4Addr>)> {
    if b.len() < 12 {
        return None;
    }
    let frame_id = u16::from_be_bytes([b[0], b[1]]);
    let (service, kind) = (b[2], b[3]);
    // DCP frame ids 0xfefc..=0xfeff; service 5 = Identify, 6 = Hello; type bit 0 = response
    if !(0xfefc..=0xfeff).contains(&frame_id) || !matches!(service, 5 | 6) || kind & 1 == 0 {
        return None;
    }
    let total = u16::from_be_bytes([b[10], b[11]]) as usize;
    let mut blocks = b.get(12..12 + total.min(b.len() - 12))?;
    let (mut m, mut ip) = (BTreeMap::new(), None);
    while blocks.len() >= 4 {
        let (opt, sub) = (blocks[0], blocks[1]);
        let len = u16::from_be_bytes([blocks[2], blocks[3]]) as usize;
        let v = blocks.get(4..4 + len)?;
        blocks = blocks.get(4 + len + (len & 1)..).unwrap_or(&[]); // blocks are padded to even length
        let data = v.get(2..).unwrap_or(&[]); // skip the 2-byte block info
        match (opt, sub) {
            (2, 1) => {
                if let Some(s) = sanitize(data) {
                    m.insert("manufacturer".into(), s);
                }
            }
            (2, 2) => {
                if let Some(s) = sanitize(data) {
                    m.insert("station_name".into(), s);
                }
            }
            (2, 3) if data.len() >= 4 => {
                let vid = u16::from_be_bytes([data[0], data[1]]);
                m.insert("vendor_id".into(), format!("{vid:#06x}"));
                m.insert("device_id".into(), format!("{:#06x}", u16::from_be_bytes([data[2], data[3]])));
                if let Some(n) = profinet_vendor(vid) {
                    m.insert("vendor".into(), n.to_string());
                }
            }
            (2, 4) if !data.is_empty() => {
                let r = data[0];
                let roles: Vec<&str> = [(1, "io-device"), (2, "io-controller"), (4, "multiplexer"), (8, "supervisor")]
                    .iter().filter(|(bit, _)| r & bit != 0).map(|(_, n)| *n).collect();
                if !roles.is_empty() {
                    m.insert("role".into(), roles.join(","));
                }
            }
            (1, 2) if data.len() >= 4 => {
                let a = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                if !a.is_unspecified() {
                    ip = Some(a);
                    m.insert("ip".into(), a.to_string());
                }
            }
            _ => {}
        }
    }
    (!m.is_empty()).then_some((m, ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class_of(p: Option<OtPdu>) -> (&'static str, bool, OtClass) {
        let p = p.expect("decoded");
        (p.proto, p.server_is_src, p.class)
    }

    /// MBAP header + PDU
    fn mbap(pdu: &[u8]) -> Vec<u8> {
        let mut v = vec![0, 1, 0, 0];
        v.extend(((pdu.len() + 1) as u16).to_be_bytes());
        v.push(1); // unit id
        v.extend(pdu);
        v
    }

    #[test]
    fn modbus_classifies_reads_writes_and_control() {
        let req = |pdu: &[u8]| parse_pdu(true, 50_000, 502, &mbap(pdu));
        assert_eq!(class_of(req(&[3, 0, 0, 0, 10])), ("modbus", false, OtClass::Read));
        assert_eq!(class_of(req(&[1, 0, 0, 0, 8])), ("modbus", false, OtClass::Read));
        for f in [5u8, 6, 15, 16, 22, 23] {
            assert_eq!(req(&[f, 0, 0, 0, 1]).unwrap().class, OtClass::Write, "fc {f}");
        }
        assert_eq!(req(&[43, 14, 1, 0]).unwrap().class, OtClass::Identify);
        // diagnostics: restart communications / force listen only are control, echo is not
        assert_eq!(req(&[8, 0, 1, 0, 0]).unwrap().class, OtClass::Control);
        assert_eq!(req(&[8, 0, 4, 0, 0]).unwrap().class, OtClass::Control);
        assert_eq!(req(&[8, 0, 0, 0x12, 0x34]).unwrap().class, OtClass::Other);
        let w = req(&[16, 0, 0, 0, 1, 2, 0, 5]).unwrap();
        assert_eq!(w.detail, "write multiple registers (16)");
        assert_eq!(w.port, 502);
        // a response comes from the server and carries no class
        let resp = parse_pdu(true, 502, 50_000, &mbap(&[3, 2, 0, 5]));
        assert_eq!(class_of(resp), ("modbus", true, OtClass::Other));
        let exc = parse_pdu(true, 502, 50_000, &mbap(&[0x83, 2])).unwrap();
        assert!(exc.detail.contains("exception"));
    }

    #[test]
    fn modbus_requires_its_signature() {
        // wrong protocol id, inconsistent length, too short, garbage
        assert!(parse_pdu(true, 50_000, 502, &[0, 1, 0, 1, 0, 2, 1, 3]).is_none());
        assert!(parse_pdu(true, 50_000, 502, &[0, 1, 0, 0, 0, 200, 1, 3]).is_none());
        assert!(parse_pdu(true, 50_000, 502, &[0, 1, 0, 0]).is_none());
        assert!(parse_pdu(true, 50_000, 502, b"GET / HTTP/1.1\r\n").is_none());
        assert!(parse_pdu(true, 50_000, 8080, &mbap(&[3, 0, 0, 0, 1])).is_none(), "port decides the decoder");
    }

    /// TPKT + COTP data + S7 job header (10 bytes) + function byte
    fn s7_job(func: u8) -> Vec<u8> {
        let mut v = vec![3, 0, 0, 0, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 1, 0, 0, func, 0];
        let n = v.len() as u16;
        v[2..4].copy_from_slice(&n.to_be_bytes());
        v
    }

    #[test]
    fn s7_recognises_stop_download_and_writes() {
        let d = |f| parse_pdu(true, 50_000, 102, &s7_job(f)).unwrap();
        assert_eq!(d(0x04).class, OtClass::Read);
        assert_eq!(d(0x05).class, OtClass::Write);
        assert_eq!((d(0x29).class, d(0x29).detail.as_str()), (OtClass::Control, "PLC stop (0x29)"));
        assert_eq!(d(0x28).class, OtClass::Control);
        for f in [0x1a, 0x1b, 0x1c] {
            assert_eq!(d(f).class, OtClass::Control, "download {f:#x}");
        }
        assert_eq!(d(0x1d).class, OtClass::Read, "upload reads the program");
        assert_eq!(d(0xf0).class, OtClass::Other);
        // COTP connection request identifies the server side without any S7
        let cr = [3, 0, 0, 7, 2, 0xe0, 0x00];
        assert!(parse_pdu(true, 102, 50_000, &cr).unwrap().server_is_src);
        // not S7: TPKT ok but wrong S7 magic; truncated
        let mut bad = s7_job(4);
        bad[7] = 0x33;
        assert!(parse_pdu(true, 50_000, 102, &bad).is_none());
        assert!(parse_pdu(true, 50_000, 102, &s7_job(4)[..10]).is_none());
    }

    fn enip_frame(cmd: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(cmd.to_le_bytes());
        v.extend((data.len() as u16).to_le_bytes());
        v.extend([0u8; 20]);
        v.extend(data);
        v
    }

    #[test]
    fn enip_cip_services_and_list_identity() {
        // SendRRData with an unconnected CIP item whose first byte is the service
        let cip = |svc: u8| {
            let mut d = vec![0, 0, 0, 0, 0, 0, 2, 0]; // handle, timeout, 2 items
            d.extend([0, 0, 0, 0]); // null address item
            d.extend([0xb2, 0, 4, 0, svc, 0, 0, 0]);
            enip_frame(0x6f, &d)
        };
        let d = |svc| parse_pdu(true, 50_000, 44818, &cip(svc)).unwrap();
        assert_eq!(d(0x4c).class, OtClass::Read);
        assert_eq!(d(0x4d).class, OtClass::Write);
        assert_eq!(d(0x07).class, OtClass::Control);
        assert_eq!(d(0x06).class, OtClass::Control);
        assert_eq!(d(0x99).class, OtClass::Other);
        assert!(d(0x07).detail.contains("stop"));

        // ListIdentity response
        let mut item = vec![1, 0]; // encapsulation protocol version
        item.extend([2, 0, 0xaf, 0x12, 10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0]); // sockaddr
        item.extend(1u16.to_le_bytes()); // vendor: Rockwell
        item.extend(14u16.to_le_bytes()); // device type
        item.extend(55u16.to_le_bytes()); // product code
        item.extend([20, 11]); // revision
        item.extend([0, 0]); // status
        item.extend(0xdead_beefu32.to_le_bytes());
        item.push(11);
        item.extend(b"1756-L83E/B");
        item.push(3); // state
        let mut d = vec![1, 0, 0x0c, 0];
        d.extend((item.len() as u16).to_le_bytes());
        d.extend(item);
        let p = parse_pdu(false, 44818, 50_000, &enip_frame(0x63, &d)).unwrap();
        assert_eq!((p.proto, p.server_is_src, p.class), ("enip", true, OtClass::Identify));
        assert_eq!(p.identity["vendor"], "Rockwell Automation / Allen-Bradley");
        assert_eq!(p.identity["product_name"], "1756-L83E/B");
        assert_eq!((p.identity["serial"].as_str(), p.identity["revision"].as_str()), ("deadbeef", "20.11"));
        // the broadcast request has no identity
        let q = parse_pdu(false, 50_000, 44818, &enip_frame(0x63, &[])).unwrap();
        assert!(!q.server_is_src && q.identity.is_empty());
        // wrong length / unknown command are rejected
        let mut bad = enip_frame(0x63, &[]);
        bad[2] = 9;
        assert!(parse_pdu(false, 50_000, 44818, &bad).is_none());
        assert!(parse_pdu(false, 50_000, 44818, &enip_frame(0x1234, &[])).is_none());
    }

    fn dnp3_frame(from_master: bool, func: u8) -> Vec<u8> {
        let ctrl = if from_master { 0xc4 } else { 0x44 };
        vec![0x05, 0x64, 8, ctrl, 1, 0, 2, 0, 0xaa, 0xbb, 0xc0, 0xc1, func, 0, 0]
    }

    #[test]
    fn dnp3_function_codes() {
        let d = |f| parse_pdu(true, 50_000, 20000, &dnp3_frame(true, f)).unwrap();
        assert_eq!(d(1).class, OtClass::Read);
        assert_eq!(d(2).class, OtClass::Write);
        for f in [3, 4, 5, 6, 13, 14, 17, 18] {
            assert_eq!(d(f).class, OtClass::Control, "fc {f}");
        }
        assert!(!d(1).server_is_src);
        let r = parse_pdu(true, 20000, 50_000, &dnp3_frame(false, 129)).unwrap();
        assert!(r.server_is_src && r.class == OtClass::Other);
        // works over UDP too; a wrong start sequence is rejected
        assert!(parse_pdu(false, 50_000, 20000, &dnp3_frame(true, 1)).is_some());
        let mut bad = dnp3_frame(true, 1);
        bad[0] = 0x06;
        assert!(parse_pdu(true, 50_000, 20000, &bad).is_none());
    }

    fn bvlc(npdu_apdu: &[u8]) -> Vec<u8> {
        let mut v = vec![0x81, 0x0a];
        v.extend(((npdu_apdu.len() + 4) as u16).to_be_bytes());
        v.extend(npdu_apdu);
        v
    }

    #[test]
    fn bacnet_services_and_i_am() {
        let confirmed = |svc: u8| parse_pdu(false, 47808, 47808, &bvlc(&[1, 0x04, 0x00, 0x05, 0x01, svc, 0, 0])).unwrap();
        assert_eq!(confirmed(12).class, OtClass::Read);
        assert_eq!(confirmed(15).class, OtClass::Write);
        assert_eq!(confirmed(16).class, OtClass::Write);
        assert_eq!(confirmed(20).class, OtClass::Control);
        assert_eq!(confirmed(17).class, OtClass::Control);
        assert!(!confirmed(12).server_is_src);
        // Who-Is (broadcast request) and I-Am (announcement with identity)
        let who = parse_pdu(false, 47808, 47808, &bvlc(&[1, 0x20, 0xff, 0xff, 0, 0xff, 0x10, 0x08])).unwrap();
        assert_eq!((who.class, who.server_is_src), (OtClass::Identify, false));
        // I-Am: device 1234, max apdu 1476 (0x22 05 c4), segmentation 3 (0x91 03), vendor 7 (0x21 07)
        let obj: u32 = (8 << 22) | 1234;
        let mut iam = vec![1, 0x20, 0xff, 0xff, 0, 0xff, 0x10, 0x00, 0xc4];
        iam.extend(obj.to_be_bytes());
        iam.extend([0x22, 0x05, 0xc4, 0x91, 0x03, 0x21, 0x07]);
        let p = parse_pdu(false, 47808, 47808, &bvlc(&iam)).unwrap();
        assert!(p.server_is_src);
        assert_eq!((p.identity["device_instance"].as_str(), p.identity["vendor"].as_str()), ("1234", "Siemens Building Technologies"));
        // responses come from the server; wrong magic or length is rejected
        assert!(parse_pdu(false, 47808, 47808, &bvlc(&[1, 0x00, 0x30, 0x01, 0x0c, 0])).unwrap().server_is_src);
        assert!(parse_pdu(false, 47808, 47808, &[0x82, 0x0a, 0, 6, 1, 0]).is_none());
        assert!(parse_pdu(false, 47808, 47808, &[0x81, 0x0a, 0, 99, 1, 0]).is_none());
    }

    #[test]
    fn opcua_and_iec104_are_identified() {
        let mut hel = b"HELF".to_vec();
        hel.extend(28u32.to_le_bytes());
        hel.extend([0u8; 20]);
        let p = parse_pdu(true, 50_000, 4840, &hel).unwrap();
        assert_eq!((p.proto, p.server_is_src, p.detail.as_str()), ("opcua", false, "HEL"));
        assert!(parse_pdu(true, 50_000, 4840, b"GET / HTTP/1.1").is_none());

        // I-format ASDU with type 45 (single command): a control action
        let cmd = [0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 45, 1, 6, 0, 1, 0, 1, 0, 0, 0x01];
        let p = parse_pdu(true, 50_000, 2404, &cmd).unwrap();
        assert_eq!((p.proto, p.class), ("iec104", OtClass::Control));
        let data = [0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 13, 1, 3, 0, 1, 0, 1, 0, 0, 0x01];
        assert_eq!(parse_pdu(true, 2404, 50_000, &data).unwrap().class, OtClass::Other);
        // U-format (STARTDT) and a bad start byte
        assert_eq!(parse_pdu(true, 50_000, 2404, &[0x68, 4, 0x07, 0, 0, 0]).unwrap().class, OtClass::Other);
        assert!(parse_pdu(true, 50_000, 2404, &[0x69, 4, 0x07, 0, 0, 0]).is_none());
    }

    fn tlv(ty: u16, v: &[u8]) -> Vec<u8> {
        let mut o = ((ty << 9) | v.len() as u16).to_be_bytes().to_vec();
        o.extend(v);
        o
    }

    #[test]
    fn lldp_yields_name_description_port_capabilities_and_mgmt_ip() {
        let mut f = tlv(1, &[4, 0x00, 0x1b, 0x63, 0xaa, 0xbb, 0xcc]);
        f.extend(tlv(2, &[5, b'G', b'i', b'1', b'/', b'0', b'/', b'7']));
        f.extend(tlv(3, &[0, 120]));
        f.extend(tlv(5, b"core-sw-01"));
        f.extend(tlv(6, b"Cisco IOS Software, C2960"));
        f.extend(tlv(7, &[0, 0x14, 0, 0x14])); // bridge + router enabled
        f.extend(tlv(8, &[5, 1, 10, 0, 0, 2, 2, 0, 0, 0, 1, 0]));
        f.extend(tlv(0, &[]));
        let m = parse_lldp(&f).unwrap();
        assert_eq!(m["system_name"], "core-sw-01");
        assert_eq!(m["port_id"], "Gi1/0/7");
        assert_eq!(m["capabilities"], "bridge,router");
        assert_eq!(m["management_ip"], "10.0.0.2");
        assert_eq!(m["chassis_id"], "00:1b:63:aa:bb:cc");
        // hostile: control characters are stripped, truncation is safe
        let evil = [tlv(1, &[4, 1, 2, 3, 4, 5, 6]), tlv(5, b"a\x00b\r\n<x>")].concat();
        assert_eq!(parse_lldp(&evil).unwrap()["system_name"], "ab<x>");
        for n in 0..f.len() {
            let _ = parse_lldp(&f[..n]);
        }
        assert!(parse_lldp(&[]).is_none() && parse_lldp(&tlv(5, b"no chassis")).is_none());
    }

    #[test]
    fn cdp_yields_device_id_capabilities_and_platform() {
        let t = |ty: u16, v: &[u8]| {
            let mut o = ty.to_be_bytes().to_vec();
            o.extend(((v.len() + 4) as u16).to_be_bytes());
            o.extend(v);
            o
        };
        let mut f = vec![2, 180, 0, 0];
        f.extend(t(1, b"edge-sw-3"));
        f.extend(t(3, b"FastEthernet0/1"));
        f.extend(t(4, &[0, 0, 0, 0x08]));
        f.extend(t(5, b"Cisco IOS 15.2"));
        f.extend(t(6, b"cisco WS-C2960"));
        let m = parse_cdp(&f).unwrap();
        assert_eq!((m["system_name"].as_str(), m["capabilities"].as_str(), m["platform"].as_str()), ("edge-sw-3", "switch", "cisco WS-C2960"));
        for n in 0..f.len() {
            let _ = parse_cdp(&f[..n]);
        }
        assert!(parse_cdp(&[2, 180, 0, 0]).is_none());
    }

    #[test]
    fn profinet_dcp_identify_response() {
        let block = |opt: u8, sub: u8, data: &[u8]| {
            let mut v = vec![opt, sub];
            v.extend(((data.len() + 2) as u16).to_be_bytes());
            v.extend([0, 0]); // block info
            v.extend(data);
            if v.len() % 2 == 1 {
                v.push(0); // padding
            }
            v
        };
        let mut blocks = block(2, 2, b"plc-line3");
        blocks.extend(block(2, 3, &[0x00, 0x2a, 0x01, 0x0d]));
        blocks.extend(block(2, 4, &[0x02, 0]));
        blocks.extend(block(1, 2, &[10, 1, 2, 3, 255, 255, 255, 0, 10, 1, 2, 1]));
        let mut f = vec![0xfe, 0xff, 5, 1, 0, 0, 0, 1, 0, 0];
        f.extend((blocks.len() as u16).to_be_bytes());
        f.extend(&blocks);
        let (m, ip) = parse_profinet_dcp(&f).unwrap();
        assert_eq!((m["station_name"].as_str(), m["vendor"].as_str(), m["role"].as_str()), ("plc-line3", "Siemens", "io-controller"));
        assert_eq!(ip, Some(Ipv4Addr::new(10, 1, 2, 3)));
        // requests (type bit 0 clear), other services and short frames are ignored
        let mut req = f.clone();
        req[3] = 0;
        assert!(parse_profinet_dcp(&req).is_none());
        assert!(parse_profinet_dcp(&f[..8]).is_none());
        for n in 0..f.len() {
            let _ = parse_profinet_dcp(&f[..n]);
        }
    }

    #[test]
    fn every_ot_port_has_a_name_and_random_payloads_never_panic() {
        assert_eq!(ot_proto_for_port(502), Some("modbus"));
        assert_eq!(ot_proto_for_port(80), None);
        let mut x = 0xdead_beef_cafe_f00du64;
        for _ in 0..20_000 {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            let n = (x.wrapping_mul(0x2545_f491_4f6c_dd1d) % 90) as usize;
            let payload: Vec<u8> = (0..n).map(|i| (x >> (i % 56)) as u8 ^ i as u8).collect();
            for (port, tcp) in [(502, true), (102, true), (44818, true), (44818, false), (20000, true), (47808, false), (4840, true), (2404, true)] {
                let _ = parse_pdu(tcp, 50_000, port, &payload);
                let _ = parse_pdu(tcp, port, 50_000, &payload);
            }
            let _ = (parse_lldp(&payload), parse_cdp(&payload), parse_profinet_dcp(&payload));
        }
    }
}
