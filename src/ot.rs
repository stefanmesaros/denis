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

/// Ports DENIS decodes the content of (used by [`parse_pdu`]) and names in a conversation, keyed the same as
/// [`EXPOSURE_PORTS`] so both lists agree on the name for a port they share.
pub const OT_PORTS: &[(u16, &str)] = &[
    (502, "modbus"),
    (102, "s7"),
    (44818, "enip"),
    (20000, "dnp3"),
    (47808, "bacnet"),
    (4840, "opcua"),
    (2404, "iec104"),
    (9600, "fins"),
    (5094, "hart-ip"),
    (3671, "knxnet-ip"),
    (1883, "mqtt"),
    (5683, "coap"),
];

/// Ports that name a protocol for the "industrial port crossing the network boundary" finding **only**: a device
/// on one of these ports talking to the outside is worth a look because of the *port* alone, whatever the payload
/// turns out to be (DENIS never decodes or names a conversation from these: it has no verifiable signature for them,
/// so a wrong guess would be a false industrial-conversation claim). The finding's own wording says so.
const EXPOSURE_ONLY_PORTS: &[(u16, &str)] = &[(1911, "niagara-fox"), (18245, "ge-srtp"), (5007, "melsec"), (1962, "pcworx"), (2455, "codesys")];

/// The protocol usually run on an industrial port, for the boundary-exposure finding. Not a claim that traffic
/// on this port really is that protocol (see [`EXPOSURE_ONLY_PORTS`]); for the ports DENIS actually decodes it is
/// the confirmed name.
pub fn ot_proto_for_port(port: u16) -> Option<&'static str> {
    OT_PORTS.iter().chain(EXPOSURE_ONLY_PORTS).find(|(p, _)| *p == port).map(|(_, n)| *n)
}

/// Industrial protocols that run inside TLS on their own port: what is on the wire is encrypted, but the port says which protocol it is.
pub const SECURE_OT_PORTS: &[(u16, &str)] = &[(802, "modbus-tls"), (4843, "opcua-tls"), (19998, "iec104-tls"), (19999, "dnp3-tls"), (8883, "mqtt-tls")];

/// Is this the protocol name of traffic DENIS cannot read into (TLS, or a secured industrial protocol)?
pub fn is_encrypted_proto(proto: &str) -> bool {
    proto == "tls" || proto.ends_with("-tls")
}

fn pdu(proto: &'static str, server_is_src: bool, class: OtClass, detail: impl Into<String>, port: u16) -> OtPdu {
    OtPdu { proto, server_is_src, class, detail: detail.into(), port, identity: BTreeMap::new() }
}

// ------------------------------------------------------------------ what cannot be read

/// A TLS record header: content type 20-23, version 3.1-3.4, a plausible length. Encrypted payloads are opaque, but the
/// header, the handshake (protocol version, the server name the client asked for) and the direction are in the clear.
pub(crate) fn tls_record(p: &[u8]) -> Option<(u8, u16)> {
    let (t, major, minor) = (*p.first()?, *p.get(1)?, *p.get(2)?);
    let len = u16::from_be_bytes([*p.get(3)?, *p.get(4)?]);
    ((0x14..=0x17).contains(&t) && major == 3 && (1..=4).contains(&minor) && len > 0 && len <= 16384 + 2048).then_some((t, len))
}

fn tls_version(v: u16) -> Option<&'static str> {
    match v {
        0x0301 => Some("1.0"),
        0x0302 => Some("1.1"),
        0x0303 => Some("1.2"),
        0x0304 => Some("1.3"),
        _ => None,
    }
}

/// What a ClientHello or ServerHello says: the protocol version and (client) the server name asked for. Every read is
/// bounds-checked; a hello cut short by the capture just gives less.
fn tls_hello(p: &[u8], client: bool) -> (Option<&'static str>, Option<String>) {
    let rd16 = |i: usize| p.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let mut version = rd16(9).and_then(tls_version);
    let mut sni = None;
    let mut step = || -> Option<()> {
        let mut i = 43; // record 5 + handshake 4 + version 2 + random 32
        i += 1 + *p.get(i)? as usize; // session id
        if client {
            i += 2 + rd16(i)? as usize; // cipher suites
            i += 1 + *p.get(i)? as usize; // compression methods
        } else {
            i += 3; // the chosen cipher suite and compression method
        }
        let end = (i + 2 + rd16(i)? as usize).min(p.len());
        i += 2;
        while i + 4 <= end {
            let (t, l) = (rd16(i)?, rd16(i + 2)? as usize);
            let body = p.get(i + 4..(i + 4 + l).min(end))?;
            match (t, client) {
                (0, true) if body.len() >= 5 => {
                    let n = u16::from_be_bytes([body[3], body[4]]) as usize;
                    sni = body.get(5..5 + n).and_then(|b| crate::parse::clean_str(&String::from_utf8_lossy(b)));
                }
                // supported_versions: the client lists them (the newest wins), the server names the one it chose
                (43, true) if body.len() >= 3 => {
                    let newest = body[1..].as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).filter(|v| tls_version(*v).is_some()).max();
                    version = newest.and_then(tls_version).or(version);
                }
                (43, false) if body.len() == 2 => version = tls_version(u16::from_be_bytes([body[0], body[1]])).or(version),
                _ => {}
            }
            i += 4 + l;
        }
        Some(())
    };
    let _ = step();
    (version, sni)
}

/// Traffic between two *local* devices that is not decoded: TLS on any port, a secured industrial protocol on its
/// port, or a known industrial port whose payload is not the protocol DENIS decodes. The content is unknown; the
/// path is not. A device's TLS ClientHello to the *outside* is a separate, narrower check living in
/// `parse::parse_flow` (JA3 only, no conversation/path bookkeeping) — this function only ever sees two local MACs.
pub fn parse_opaque(is_tcp: bool, sport: u16, dport: u16, payload: &[u8]) -> Option<OtPdu> {
    let known = |p: u16| SECURE_OT_PORTS.iter().find(|(q, _)| *q == p).map(|(q, n)| (*q, *n)).or_else(|| ot_proto_for_port(p).map(|n| (p, n)));
    let named = known(dport).or_else(|| known(sport));
    if is_tcp {
        if let Some((t, _)) = tls_record(payload) {
            let (mut src_is_server, mut detail) = match &named {
                Some((p, _)) => (sport == *p && dport != *p, String::new()),
                None => (sport < dport, String::new()), // the server is on the lower (well-known) port
            };
            let mut version = tls_version(u16::from_be_bytes([*payload.get(1)?, *payload.get(2)?]));
            let mut identity = BTreeMap::new();
            if t == 0x16 && payload.len() > 9 {
                match payload[5] {
                    1 | 2 => {
                        let client = payload[5] == 1;
                        src_is_server = !client;
                        let (v, sni) = tls_hello(payload, client);
                        version = v.or(version);
                        detail = format!("TLS {} handshake{}", version.unwrap_or("?"), sni.map(|s| format!(" (server name {s})")).unwrap_or_default());
                        // JA3/JA3S: who is talking, not what is said. The fingerprint belongs to
                        // this message's sender (the client for a ClientHello, the server for a
                        // ServerHello) and is attached below via `identity`, same as any other
                        // self-announced identity (LLDP, EtherNet/IP, BACnet).
                        identity = crate::ja3::identity(payload, client);
                    }
                    _ => detail = "TLS handshake".into(),
                }
            }
            if detail.is_empty() {
                detail = match t {
                    0x17 => "TLS data".into(),
                    0x15 => "TLS alert".into(),
                    _ => "TLS handshake".into(),
                };
            }
            let (port, proto) = match named {
                Some((p, n)) if SECURE_OT_PORTS.iter().any(|(q, _)| *q == p) => (p, n),
                _ => (if src_is_server { sport } else { dport }, "tls"),
            };
            return Some(OtPdu { identity, ..pdu(proto, src_is_server, OtClass::Opaque, detail, port) });
        }
    }
    // Nothing else is named from a port alone: a port number is not evidence, only a hint at where to look, and a
    // wrong guess here would show up as a false industrial conversation. Traffic that is not TLS and does not match
    // one of the decoders in `parse_pdu` is simply not reported as an OT path.
    None
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
        if let Some(p) = server_port(5094) {
            return hart_ip(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(1883) {
            return mqtt(payload, sport == p && dport != p, p);
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
        if let Some(p) = server_port(9600) {
            return fins(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(5094) {
            return hart_ip(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(3671) {
            return knxnet_ip(payload, sport == p && dport != p, p);
        }
        if let Some(p) = server_port(5683) {
            return coap(payload, sport == p && dport != p, p);
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

// ------------------------------------------------------------------ FINS (Omron)

/// Omron FINS over UDP/TCP: a 10-byte header (ICF, RSV, GCT, 3 network addresses each, SID), then a 2-byte command
/// code (MRC/SRC). Only the command groups documented in Omron's FINS command reference (W342) are classified;
/// everything else is named but not judged, so an unfamiliar sub-command is never mislabelled as a read or a write.
fn fins(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    if b.len() < 12 {
        return None;
    }
    let icf = b[0];
    // 0x80/0x81 = command (a response is required or not), 0xc0/0xc1 = response. GCT (byte 2) is a small hop count.
    if !matches!(icf, 0x80 | 0x81 | 0xc0 | 0xc1) || b[2] > 8 {
        return None;
    }
    let is_response = icf & 0x40 != 0;
    if is_response != server_is_src {
        return None; // the direction the header claims must agree with which side holds the well-known port
    }
    let (mrc, src) = (b[10], b[11]);
    if is_response {
        return Some(pdu("fins", true, OtClass::Other, format!("response ({mrc:#04x}.{src:#04x})"), port));
    }
    let (class, name) = match (mrc, src) {
        (0x01, 0x01 | 0x04 | 0x05) => (OtClass::Read, "memory area read"),
        (0x01, 0x02) => (OtClass::Write, "memory area write"),
        (0x01, 0x03) => (OtClass::Write, "memory area fill"),
        (0x02, 0x01) => (OtClass::Read, "parameter area read"),
        (0x02, 0x02) => (OtClass::Write, "parameter area write"),
        (0x02, 0x03) => (OtClass::Write, "parameter area clear"),
        (0x03, 0x06) => (OtClass::Read, "program area read"),
        (0x03, 0x07) => (OtClass::Write, "program area write"),
        (0x03, 0x08) => (OtClass::Write, "program area clear"),
        // Run/Stop is the one command in the whole protocol that matters most for OT security.
        (0x04, 0x01) => (OtClass::Control, "run"),
        (0x04, 0x02) => (OtClass::Control, "stop"),
        (0x06, 0x01 | 0x03 | 0x20) => (OtClass::Read, "status read"),
        _ => (OtClass::Other, "function"),
    };
    Some(pdu("fins", false, class, format!("{name} ({mrc:#04x}.{src:#04x})"), port))
}

// ------------------------------------------------------------------ HART-IP

/// HART-IP (IEC 62734 / FieldComm Group HCF SPEC-081): an 8-byte header (version, message type, message id, status,
/// sequence number, byte count) wrapping a HART command. Only the header is decoded: HART's own command set needs
/// the field-instrument universal/common-practice/device-specific command tables to judge read from write, which
/// is a lot of ground to cover correctly, so DENIS names the protocol and the direction and stops there (as it
/// already does for OPC UA).
fn hart_ip(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    if b.len() < 8 || b[0] != 1 {
        return None; // version must be 1: everything issued under HART-IP so far uses it
    }
    let (msg_type, msg_id) = (b[1], b[2]);
    if msg_type > 6 || msg_id > 9 {
        return None;
    }
    let byte_count = u16::from_be_bytes([b[6], b[7]]) as usize;
    if byte_count < 8 || byte_count > b.len() + 512 {
        return None; // the declared size must be in the right ballpark of what actually arrived
    }
    let kind = match msg_type {
        0 => "request",
        1 => "response",
        2 => "publish",
        _ => "message",
    };
    Some(pdu("hart-ip", server_is_src, OtClass::Other, format!("{kind} (id {msg_id})"), port))
}

// ------------------------------------------------------------------ KNXnet/IP

/// KNXnet/IP (ISO/IEC 14543-3, formerly EIBnet/IP): every frame starts with a 6-byte header whose first two bytes
/// are always `06 10` (header length, protocol version), the third and fourth are the service type (one of the
/// small set the standard defines), and the last two are the total frame length, which must match exactly.
///
/// A TUNNELLING_REQUEST or ROUTING_INDICATION carries a cEMI frame whose APCI would say whether a group address is
/// being read or written, but locating it correctly needs to walk past a variable-length "additional information"
/// block first; without a real capture to check that against, DENIS names the protocol and stops there rather than
/// risk turning a read into a write (or the reverse) on a byte offset that was never seen in practice.
fn knxnet_ip(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    if b.len() < 6 || b[0] != 0x06 || b[1] != 0x10 || u16::from_be_bytes([b[4], b[5]]) as usize != b.len() {
        return None;
    }
    let service = u16::from_be_bytes([b[2], b[3]]);
    let name = match service {
        0x0201..=0x0206 => "search/description/connect",
        0x0310..=0x0315 => "connection state/disconnect",
        0x0420 | 0x0421 => "tunnelling",
        0x0530 | 0x0531 => "routing",
        _ => return None,
    };
    Some(pdu("knxnet-ip", server_is_src, OtClass::Other, name, port))
}

// ------------------------------------------------------------------ MQTT

/// MQTT (OASIS standard, versions 3.1.1 and 5): a fixed header of a control-packet-type nibble and a "remaining
/// length" encoded as a 1-4 byte variable-length integer that must account for exactly the rest of the packet.
/// Devices in the field are usually publishers (sensor readings) or subscribers (setpoints, commands); CONNECT
/// carries the protocol name, which is one more check against mistaking other traffic for MQTT.
fn mqtt(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    let ptype = b.first()? >> 4;
    if !(1..=14).contains(&ptype) {
        return None;
    }
    let mut len = 0u32;
    let mut i = 1;
    for shift in 0..4 {
        let byte = *b.get(i)?;
        len |= ((byte & 0x7f) as u32) << (shift * 7);
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if i + len as usize != b.len() {
        return None;
    }
    let (class, name) = match ptype {
        1 => {
            // CONNECT: variable header starts with a length-prefixed protocol name ("MQTT" or the 3.1 "MQIsdp").
            let body = b.get(i..)?;
            let name_len = u16::from_be_bytes([*body.first()?, *body.get(1)?]) as usize;
            let proto_name = body.get(2..2 + name_len)?;
            if proto_name != b"MQTT" && proto_name != b"MQIsdp" {
                return None;
            }
            (OtClass::Other, "connect")
        }
        2 => (OtClass::Other, "connack"),
        3 => (OtClass::Write, "publish"), // a device announcing data, or a controller pushing a command topic
        8 => (OtClass::Read, "subscribe"),
        10 => (OtClass::Read, "unsubscribe"),
        14 => (OtClass::Other, "disconnect"),
        _ => (OtClass::Other, "packet"),
    };
    Some(pdu("mqtt", server_is_src, class, name, port))
}

// ------------------------------------------------------------------ CoAp

/// CoAP (RFC 7252): a 4-byte header whose top two bits are always the version (1); the method codes of a request
/// (GET/POST/PUT/DELETE, class 0) map onto read/write the same way HTTP verbs do. Responses (class 2-5) are not judged.
fn coap(b: &[u8], server_is_src: bool, port: u16) -> Option<OtPdu> {
    if b.len() < 4 {
        return None;
    }
    let ver = b[0] >> 6;
    let tkl = b[0] & 0x0f;
    if ver != 1 || tkl > 8 || (4 + tkl as usize) > b.len() {
        return None;
    }
    let code = b[1];
    let (class_bits, detail) = (code >> 5, code & 0x1f);
    if class_bits > 5 {
        return None;
    }
    let (class, name) = if class_bits == 0 && detail > 0 {
        match detail {
            1 => (OtClass::Read, "GET"),
            2 => (OtClass::Write, "POST"),
            3 => (OtClass::Write, "PUT"),
            4 => (OtClass::Write, "DELETE"),
            _ => (OtClass::Other, "request"),
        }
    } else if class_bits == 0 {
        (OtClass::Other, "empty")
    } else {
        (OtClass::Other, "response")
    };
    Some(pdu("coap", server_is_src, class, name, port))
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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

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

    // -------------------------------------------------------------- FINS (real bytes: automayt/ICS-pcap FINS (OMRON)/omron.pcap)

    #[test]
    fn fins_classifies_memory_reads_writes_and_the_run_stop_command() {
        // real FINS header from the capture: ICF RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID = 80 00 02 00 00 00 00 00 00 7a
        const H: &str = "8000020000000000007a";
        // Memory Area Read request (mrc 01, src 01)
        assert_eq!(class_of(fins(&unhex(&format!("{H}0101")), false, 9600)), ("fins", false, OtClass::Read));
        // Memory Area Write (01.02)
        assert_eq!(class_of(fins(&unhex(&format!("{H}0102")), false, 9600)), ("fins", false, OtClass::Write));
        // RUN (04.01) and STOP (04.02): the one command that matters most for OT security
        let run = fins(&unhex(&format!("{H}0401000001")), false, 9600).unwrap();
        assert_eq!((run.class, run.detail.as_str()), (OtClass::Control, "run (0x04.0x01)"));
        assert_eq!(fins(&unhex(&format!("{H}0402")), false, 9600).unwrap().class, OtClass::Control);
        // a response (ICF bit 6 set), the real reply bytes: never judged, only named
        let resp = fins(&unhex("c000020000000000007a010100cccccc0001"), true, 9600).unwrap();
        assert_eq!((resp.class, resp.detail.as_str()), (OtClass::Other, "response (0x01.0x01)"));
        // the direction the header claims must agree with which side holds the well-known port
        assert!(fins(&unhex("c000020000000000007a0101"), false, 9600).is_none(), "a response header from the 'client' side is refused");
        // an unfamiliar sub-command is named but never guessed at
        assert_eq!(class_of(fins(&unhex(&format!("{H}2601")), false, 9600)), ("fins", false, OtClass::Other));
        // not FINS: a bad ICF or an absurd hop count
        assert!(fins(&unhex("0000020000000000007a0101"), false, 9600).is_none());
        assert!(fins(&[0x80, 0, 0xff, 0, 0, 0, 0, 0, 0, 0x7a, 1, 1], false, 9600).is_none());
        assert!(fins(&[0x80, 0], false, 9600).is_none(), "too short");
    }

    // -------------------------------------------------------------- HART-IP (real bytes: automayt/ICS-pcap HART IP/hart_ip.pcap)

    #[test]
    fn hart_ip_is_identified_by_its_header_but_never_claims_to_read_the_wrapped_hart_command() {
        // real bytes from the capture: version, type(0=request), id(0), status(0), seq(2), byte-count(0x0b=11), then 3 body bytes
        let req = hart_ip(&unhex("010000000002000b010000"), false, 5094).unwrap();
        assert_eq!((req.proto, req.server_is_src, req.class), ("hart-ip", false, OtClass::Other));
        assert!(req.detail.contains("request"));
        // the real response: type 1, id 1, seq 8, byte-count 0x0d=13, 5 body bytes
        let resp = hart_ip(&unhex("010101000008000d0100003075"), true, 5094).unwrap();
        assert!(resp.server_is_src && resp.detail.contains("response"));
        // a wrapped command (id 3 = token-passing PDU) still says nothing about read or write: HART's own command table is not decoded
        assert_eq!(hart_ip(&unhex("0100030000000011822640000000010203"), false, 5094).unwrap().class, OtClass::Other);
        // not HART-IP: wrong version, an out-of-range message type or id, a byte count nowhere near the packet
        assert!(hart_ip(&unhex("020000000002000b010000"), false, 5094).is_none());
        assert!(hart_ip(&[1, 9, 0, 0, 0, 0, 0, 8], false, 5094).is_none());
        assert!(hart_ip(&[1, 0, 10, 0, 0, 0, 0, 8], false, 5094).is_none());
        assert!(hart_ip(&[1, 0, 0, 0, 0, 0, 0xff, 0xff], false, 5094).is_none());
        assert!(hart_ip(&[1, 0, 0, 0, 0, 0, 0], false, 5094).is_none(), "too short");
    }

    // -------------------------------------------------------------- CoAP (real bytes: Wireshark wiki sample capture coap-cbor.pcap)

    #[test]
    fn coap_maps_its_methods_onto_read_and_write_from_real_bytes_and_never_guesses_a_response() {
        // real POST request and its 4.05 (Method Not Allowed) response
        let post = coap(&unhex("44020c3cd19796c1c13cff00"), false, 5683).unwrap();
        assert_eq!((post.proto, post.server_is_src, post.class, post.detail.as_str()), ("coap", false, OtClass::Write, "POST"));
        let resp = coap(&unhex("64850c3cd19796c1"), true, 5683).unwrap();
        assert_eq!((resp.server_is_src, resp.class), (true, OtClass::Other));
        // GET reads, PUT and DELETE write; an empty message (code 0.00) and a version other than 1 are refused
        assert_eq!(coap(&[0x40, 0x01, 0, 0], false, 5683).unwrap().class, OtClass::Read);
        assert_eq!(coap(&[0x40, 0x03, 0, 0], false, 5683).unwrap().class, OtClass::Write);
        assert_eq!(coap(&[0x40, 0x04, 0, 0], false, 5683).unwrap().class, OtClass::Write);
        assert_eq!(coap(&[0x40, 0x00, 0, 0], false, 5683).unwrap().class, OtClass::Other);
        assert!(coap(&[0x80, 0x01, 0, 0], false, 5683).is_none(), "version 2 is not CoAP");
        assert!(coap(&[0x4f, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false, 5683).is_none(), "a token length of 15 is reserved");
        assert!(coap(&[0x40], false, 5683).is_none(), "too short");
    }

    // -------------------------------------------------------------- KNXnet/IP (spec-exact bytes: ISO/IEC 14543-3 / KNX Association's KNXnet/IP)

    #[test]
    fn knxnet_ip_is_matched_by_its_fixed_header_and_named_by_service_type() {
        // TUNNELLING_REQUEST (0x0420): header(6) + connection header(4) + a cEMI frame it does not look inside
        let tunnel = [0x06, 0x10, 0x04, 0x20, 0, 16, /*conn hdr*/ 4, 0, 0, 0, /*cemi*/ 0x29, 0, 0xbc, 0xe0, 0x11, 0];
        assert_eq!(class_of(knxnet_ip(&tunnel, false, 3671)), ("knxnet-ip", false, OtClass::Other));
        // ROUTING_INDICATION (multicast)
        let routed = [0x06, 0x10, 0x05, 0x30, 0, 12, 0x29, 0, 0xbc, 0xe0, 0x11, 0];
        assert_eq!(knxnet_ip(&routed, true, 3671).unwrap().detail.as_str(), "routing");
        // connection management (SEARCH_REQUEST)
        let connect = [0x06, 0x10, 0x02, 0x01, 0, 6];
        assert_eq!(knxnet_ip(&connect, false, 3671).unwrap().detail.as_str(), "search/description/connect");
        // not KNXnet/IP: wrong magic, an unrecognised service type, or a declared length that does not match what arrived
        assert!(knxnet_ip(&[0x06, 0x11, 0x02, 0x01, 0, 6], false, 3671).is_none());
        assert!(knxnet_ip(&[0x06, 0x10, 0x09, 0x01, 0, 6], false, 3671).is_none());
        assert!(knxnet_ip(&[0x06, 0x10, 0x02, 0x01, 0, 7], false, 3671).is_none());
        assert!(knxnet_ip(&[0x06, 0x10], false, 3671).is_none(), "too short");
    }

    // -------------------------------------------------------------- MQTT (spec-exact bytes: OASIS MQTT 3.1.1)

    #[test]
    fn mqtt_is_matched_by_its_remaining_length_and_publish_subscribe_map_onto_write_and_read() {
        // CONNECT: type 1, protocol name "MQTT", level 4, flags 2, keepalive 60, an empty client id
        assert_eq!(class_of(mqtt(&unhex("100c00044d5154540402003c0000"), false, 1883)), ("mqtt", false, OtClass::Other));
        // PUBLISH (type 3) is a device announcing data (or a controller pushing a command topic): treated as a write
        let publish: Vec<u8> = [vec![0x30, 8, 0, 5], b"a/b/c".to_vec(), b"1".to_vec()].concat();
        assert_eq!(class_of(mqtt(&publish, true, 1883)), ("mqtt", true, OtClass::Write));
        // SUBSCRIBE (type 8) is a read: packet id, then one topic filter "a" with QoS 0
        let subscribe: Vec<u8> = vec![0x82, 6, 0, 1, 0, 1, b'a', 0];
        assert_eq!(mqtt(&subscribe, false, 1883).unwrap().class, OtClass::Read);
        // a "remaining length" that does not exactly account for the rest of the packet is refused
        assert!(mqtt(&[0x30, 20, 0, 5, b'x'], false, 1883).is_none());
        // a CONNECT that does not name the MQTT protocol is refused (some other protocol reusing the port/framing)
        assert!(mqtt(&unhex("100600044e4f5045"), false, 1883).is_none());
        assert!(mqtt(&[0x00, 0], false, 1883).is_none(), "control packet type 0 is reserved");
        assert!(mqtt(&[0xf0, 0], false, 1883).is_none(), "type 15 is reserved");
    }

    #[test]
    fn every_ot_port_has_a_name_and_random_payloads_never_panic() {
        assert_eq!(ot_proto_for_port(502), Some("modbus"));
        assert_eq!(ot_proto_for_port(9600), Some("fins"));
        assert_eq!(ot_proto_for_port(1911), Some("niagara-fox"), "named for the boundary-exposure finding only");
        assert_eq!(ot_proto_for_port(80), None);
        let mut x = 0xdead_beef_cafe_f00du64;
        for _ in 0..20_000 {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            let n = (x.wrapping_mul(0x2545_f491_4f6c_dd1d) % 90) as usize;
            let payload: Vec<u8> = (0..n).map(|i| (x >> (i % 56)) as u8 ^ i as u8).collect();
            for (port, tcp) in [
                (502, true), (102, true), (44818, true), (44818, false), (20000, true), (47808, false), (4840, true), (2404, true),
                (9600, false), (5094, true), (5094, false), (3671, false), (1883, true), (5683, false),
            ] {
                let _ = parse_pdu(tcp, 50_000, port, &payload);
                let _ = parse_pdu(tcp, port, 50_000, &payload);
                let _ = parse_opaque(tcp, 50_000, port, &payload);
            }
            let _ = (parse_lldp(&payload), parse_cdp(&payload), parse_profinet_dcp(&payload));
        }
    }

    // Real TLS handshakes, captured from OpenSSL (Python's ssl over memory buffers): a client asking for the server name
    // "plc1.plant.local" and the server's answer, for TLS 1.3 and TLS 1.2.
    const CH13: &str = "16030100f5010000f103030fa623c5423c7f6a6b13f467d45a8e8d9b2996fde3ab0deb2fd075d0e6a3352720fc60ed75deb6ce734c292061782722550ecc57a98166d4d318a3d359cc40a1e2000813021303130100ff010000a0000000150013000010706c63312e706c616e742e6c6f63616c000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020099865fe339018d045a3f56bff77221709a47c4e04d2927373447f08e3763618";
    const SH13: &str = "160303007a02000076030390270d1d1332bef2dae3874f44db3602ba33c00dba0edddff5e742ddad57c2b320fc60ed75deb6ce734c292061782722550ecc57a98166d4d318a3d359cc40a1e2130200002e002b0002030400330024001d002041c915f8f2b1fbf4e424636b0f46cc74302e81774e0271a457ba915740ffce751403030001011703030017054121be38534f1d71150eb6779fb2098e59d50e5c5cda17030303398f6c8d3bfd16a8e5346801fc2c8cc5a13c33a8e504cc036d953f3153afde1bfe82d3";
    const CH12: &str = "16030100b6010000b203033e524f541158034b7959d9fcd0df491917236716a0dd21bcd4aa7507804281b800001ec02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100006b000000150013000010706c63312e706c616e742e6c6f63616c000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602";
    const SH12: &str = "16030300410200003d0303cc741492be19e37fee390c0532dccaa52fcc5c6dee5039f9ebf2731e2f61ea6f00c030000015ff01000100000b000403000102002300000017000016030303250b00032100031e00031b30820317308201ffa00302010202141d17203d338e9504ffdef86c470d69ddf216dd72300d06092a864886f70d01010b0500301b3119301706035504030c10706c63312e706c616e742e6c6f63616c301e170d3236303932313139323934395a170d3236303932333139323934395a301b3119";

    #[test]
    fn a_tls_handshake_gives_the_version_the_direction_and_the_server_name_without_reading_any_content() {
        for (ch, sh, version) in [(CH13, SH13, "1.3"), (CH12, SH12, "1.2")] {
            // on an unknown port the server is the lower one; the hello decides the direction anyway
            let c = parse_opaque(true, 51_000, 8443, &unhex(ch)).unwrap();
            assert_eq!((c.proto, c.server_is_src, c.class, c.port), ("tls", false, OtClass::Opaque, 8443));
            assert_eq!(c.detail, format!("TLS {version} handshake (server name plc1.plant.local)"));
            assert_eq!(c.identity["ja3"].len(), 32, "a real ClientHello yields a JA3 hash");
            assert_eq!(c.identity["ja3"], crate::ja3::client_ja3(&unhex(ch)).unwrap().1);
            let s = parse_opaque(true, 8443, 51_000, &unhex(sh)).unwrap();
            assert_eq!((s.proto, s.server_is_src, s.detail.as_str()), ("tls", true, format!("TLS {version} handshake").as_str()));
            assert_eq!(s.identity["ja3s"].len(), 32, "a real ServerHello yields a JA3S hash");
        }
        // application data and alerts carry no names, only the direction the ports give
        let data = [0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5];
        let d = parse_opaque(true, 51_000, 4843, &data).unwrap();
        assert_eq!((d.proto, d.port, d.server_is_src, d.detail.as_str()), ("opcua-tls", 4843, false, "TLS data"), "a secured OPC UA port names the protocol");
        let r = parse_opaque(true, 4843, 51_000, &[0x15, 3, 3, 0, 2, 2, 40]).unwrap();
        assert_eq!((r.server_is_src, r.detail.as_str()), (true, "TLS alert"));
        // secured industrial protocols by port
        for (port, name) in [(802, "modbus-tls"), (19998, "iec104-tls"), (19999, "dnp3-tls"), (8883, "mqtt-tls")] {
            assert_eq!(parse_opaque(true, 40_000, port, &data).unwrap().proto, name);
            assert!(is_encrypted_proto(name));
        }
        assert!(is_encrypted_proto("tls") && !is_encrypted_proto("modbus") && !is_encrypted_proto("s7"));
    }

    #[test]
    fn an_industrial_port_with_content_that_matches_no_decoder_is_not_named_from_the_port_alone() {
        // a port a decoded protocol normally lives on, with bytes that fail that decoder's signature: no claim
        assert!(parse_opaque(false, 40_000, 9600, b"\x80\x00\x02\x00\x00\x00").is_none());
        assert!(parse_opaque(true, 9600, 40_000, b"x").is_none());
        // a port that is only ever named for the boundary-exposure finding: never a decoded conversation either
        assert!(parse_opaque(false, 40_000, 1911, b"hello there").is_none());
        // ordinary traffic on an ordinary port is not industrial, and TLS is looked for over TCP only
        assert!(parse_opaque(true, 40_000, 8080, b"GET / HTTP/1.1\r\n").is_none());
        assert!(parse_opaque(false, 5353, 40_000, b"\x17\x03\x03\x00\x05abcde").is_none());
    }

    #[test]
    fn hostile_and_truncated_bytes_never_panic_and_never_invent_a_name() {
        let full = unhex(CH13);
        for n in 0..full.len() {
            let _ = parse_opaque(true, 51_000, 8443, &full[..n]);
        }
        for i in 0..full.len().min(120) {
            for v in [0u8, 0xff, 0x80, 0x01, 0x16] {
                let mut bad = full.clone();
                bad[i] = v;
                let _ = parse_opaque(true, 51_000, 8443, &bad);
            }
        }
        // a control-character-laden name is cleaned; an absurd record length is not TLS
        let mut c = full.clone();
        let at = c.windows(16).position(|w| w == b"plc1.plant.local").unwrap();
        c[at] = 0x07;
        let d = parse_opaque(true, 51_000, 8443, &c).unwrap();
        assert!(!d.detail.chars().any(|ch| ch.is_control()), "{}", d.detail);
        assert!(parse_opaque(true, 51_000, 8443, &[0x16, 3, 3, 0xff, 0xff, 1, 2, 3]).is_none());
        assert!(parse_opaque(true, 51_000, 8443, &[0x16, 2, 3, 0, 10, 1, 2, 3]).is_none());
    }
}
