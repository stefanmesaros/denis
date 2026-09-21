//! Pure, allocation-light parsers: Ethernet frame -> zero or more `Observation`s.
//!
//! Nothing here touches the network, so it is fully unit-testable with
//! hand-built frames. Every length is bounds-checked: frames come from an
//! untrusted network.
//!
//! Identity rule: an IP is only attributed to a MAC when the IP is inside the
//! monitored subnet. Frames routed in from elsewhere carry the router's MAC and
//! would otherwise pollute the router's IP history.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::model::{FlowSample, LinkInfo, Mac, Observation, OtSample, Signal, TcpSig, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::ot;

pub struct Ctx {
    pub subnet: Ipv4Net,
    pub own_mac: Mac,
    pub own_ip: Ipv4Addr,
    /// Also account per-device traffic to/from outside the subnet (needs the
    /// wider `BPF_FILTER_FLOWS`).
    pub flows: bool,
    /// Decode industrial protocols between local devices (needs the wide
    /// filter too, so it is enabled together with `flows`).
    pub ot: bool,
}

const ETH_ARP: u16 = 0x0806;
const ETH_IPV4: u16 = 0x0800;
const ETH_VLAN: u16 = 0x8100;
const ETH_QINQ: u16 = 0x88a8;

// The filters below also capture link-layer discovery: LLDP (EtherType 0x88cc),
// PROFINET (0x8892) and CDP (multicast to 01:00:0c:cc:cc:cc, an 802.3 frame with
// no EtherType). All are rare, so they are captured by default: switches, access
// points and industrial devices announcing themselves are free identity.

/// Classic BPF filter matching exactly what `parse_frame` understands, so the
/// kernel drops everything else before it reaches userspace.
pub const BPF_FILTER: &str = "arp \
    or (udp and (port 67 or port 68 or port 5353 or port 1900)) \
    or (tcp[tcpflags] & tcp-syn != 0) \
    or (icmp[icmptype] == icmp-echoreply) \
    or ether proto 0x88cc or ether proto 0x8892 or ether dst 01:00:0c:cc:cc:cc";

/// With flow accounting every IPv4 frame is needed (plus the link-layer set).
pub const BPF_FILTER_FLOWS: &str = "arp or ip or ether proto 0x88cc or ether proto 0x8892 or ether dst 01:00:0c:cc:cc:cc";

pub fn bpf_filter(flows: bool) -> &'static str {
    if flows {
        BPF_FILTER_FLOWS
    } else {
        BPF_FILTER
    }
}

pub fn parse_frame(ctx: &Ctx, frame: &[u8]) -> Vec<Observation> {
    let mut out = Vec::new();
    if frame.len() < 14 {
        return out;
    }
    let dst_mac = Mac(frame[0..6].try_into().unwrap());
    let src_mac = Mac(frame[6..12].try_into().unwrap());
    if !src_mac.is_valid() {
        return out;
    }
    // Our own frames are never a device to discover, but they *are* traffic
    // attributable to the self asset.
    let own = src_mac == ctx.own_mac;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut off = 14;
    while (ethertype == ETH_VLAN || ethertype == ETH_QINQ) && frame.len() >= off + 4 {
        ethertype = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
        off += 4;
    }
    let payload = &frame[off..];
    // CDP frames are 802.3 (the "EtherType" is a length) addressed to a fixed multicast.
    if !own && dst_mac.0 == [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc] && ethertype <= 1500 {
        // LLC/SNAP: AA AA 03, OUI 00 00 0c, protocol 0x2000
        if payload.len() > 8 && payload[..8] == [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00] {
            if let Some(f) = ot::parse_cdp(&payload[8..]) {
                out.push(Observation::Link(LinkInfo { mac: src_mac, source: "cdp", ip: None, fields: f }));
            }
        }
        return out;
    }
    match ethertype {
        0x88cc if !own => {
            if let Some(f) = ot::parse_lldp(payload) {
                let ip = f.get("management_ip").and_then(|v| v.parse().ok()).filter(|ip| ctx.subnet.contains(ip));
                out.push(Observation::Link(LinkInfo { mac: src_mac, source: "lldp", ip, fields: f }));
            }
        }
        0x8892 if !own => {
            if let Some((f, ip)) = ot::parse_profinet_dcp(payload) {
                out.push(Observation::Link(LinkInfo { mac: src_mac, source: "profinet", ip: ip.filter(|ip| ctx.subnet.contains(ip)), fields: f }));
            }
        }
        ETH_ARP if !own => parse_arp(ctx, src_mac, payload, &mut out),
        ETH_IPV4 => {
            if ctx.flows {
                parse_flow(ctx, src_mac, dst_mac, payload, own, &mut out);
            }
            if ctx.ot {
                parse_ot(ctx, src_mac, dst_mac, payload, &mut out);
            }
            if !own {
                parse_ipv4(ctx, src_mac, payload, &mut out);
            }
        }
        _ => {}
    }
    out
}

/// Addresses that are neither on the monitored subnet nor a "destination":
/// multicast, broadcast, loopback, link-local, unspecified.
fn is_external(ctx: &Ctx, ip: Ipv4Addr) -> bool {
    !ctx.subnet.contains(&ip)
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
}

/// Industrial protocol decoding for traffic between two *local* devices (the
/// communications matrix). Traffic to the outside is handled by flow accounting,
/// which flags OT ports leaving the network by port alone.
fn parse_ot(ctx: &Ctx, src_mac: Mac, dst_mac: Mac, p: &[u8], out: &mut Vec<Observation>) {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return;
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    if ihl < 20 || p.len() < ihl || u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 {
        return;
    }
    let proto = p[9];
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    if !ctx.subnet.contains(&src) || !ctx.subnet.contains(&dst) || !dst_mac.is_unicast() {
        return;
    }
    let l4 = &p[ihl..];
    let (is_tcp, hdr) = match proto {
        PROTO_TCP if l4.len() >= 20 => (true, (l4[12] >> 4) as usize * 4),
        PROTO_UDP if l4.len() >= 8 => (false, 8),
        _ => return,
    };
    if hdr < 8 || l4.len() <= hdr {
        return;
    }
    let (sport, dport) = (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]]));
    if let Some(pdu) = ot::parse_pdu(is_tcp, sport, dport, &l4[hdr..]).or_else(|| ot::parse_opaque(is_tcp, sport, dport, &l4[hdr..])) {
        out.push(Observation::Ot(OtSample {
            src_mac,
            dst_mac,
            src_ip: src,
            dst_ip: dst,
            bytes: u32::from_be_bytes([0, 0, p[2], p[3]]),
            pdu,
        }));
    }
}

/// Traffic accounting: bytes between a local device and an outside address.
/// Outbound is attributed by Ethernet source, inbound by Ethernet destination,
/// so the device is the LAN-side endpoint even when a router forwards for it.
fn parse_flow(ctx: &Ctx, src_mac: Mac, dst_mac: Mac, p: &[u8], own: bool, out: &mut Vec<Observation>) {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return;
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    if ihl < 20 || p.len() < ihl || u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 {
        return;
    }
    let proto = p[9];
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    // TSO/checksum offload can leave the length field zero on our own frames.
    let total = match u16::from_be_bytes([p[2], p[3]]) {
        0 => p.len(),
        n => n as usize,
    } as u32;
    let l4 = &p[ihl..];
    let port = match proto {
        PROTO_TCP | PROTO_UDP if l4.len() >= 4 => {
            let (s, d) = (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]]));
            s.min(d)
        }
        PROTO_ICMP => 0,
        PROTO_TCP | PROTO_UDP => return,
        _ => 0,
    };

    if ctx.subnet.contains(&src) && is_external(ctx, dst) {
        out.push(Observation::FlowSample(FlowSample {
            mac: src_mac,
            remote: dst,
            proto,
            port,
            bytes: total,
            outbound: true,
        }));
        // A device that talks to the internet has obviously revealed its binding.
        if !own {
            out.push(Observation::Arp { mac: src_mac, ip: src });
        }
    } else if ctx.subnet.contains(&dst) && is_external(ctx, src) && dst_mac.is_valid() {
        out.push(Observation::FlowSample(FlowSample {
            mac: dst_mac,
            remote: src,
            proto,
            port,
            bytes: total,
            outbound: false,
        }));
    }
}

fn parse_arp(ctx: &Ctx, eth_src: Mac, p: &[u8], out: &mut Vec<Observation>) {
    if p.len() < 28 {
        return;
    }
    // Ethernet/IPv4 ARP only.
    if p[0..2] != [0, 1] || p[2..4] != [8, 0] || p[4] != 6 || p[5] != 4 {
        return;
    }
    let op = u16::from_be_bytes([p[6], p[7]]);
    if op != 1 && op != 2 {
        return;
    }
    let sha = Mac(p[8..14].try_into().unwrap());
    let spa = Ipv4Addr::new(p[14], p[15], p[16], p[17]);
    // Probes (spa == 0.0.0.0) carry no binding.
    if spa.is_unspecified() || !sha.is_valid() || !ctx.subnet.contains(&spa) || spa == ctx.own_ip {
        return;
    }
    // A sender hardware address that differs from the Ethernet source is
    // unusual (proxy-ARP done badly, or a crude spoofing tool). It carries no
    // trustworthy binding, so report it as a signal instead of learning from it.
    if sha != eth_src {
        out.push(Observation::Signal(Signal {
            kind: "arp_mismatch".into(),
            ts: 0, // stamped by the aggregator: parsing has no clock
            mac: eth_src,
            ip: spa,
            other_mac: Some(sha),
            gateway: false, // the inventory knows the gateway
        }));
        return;
    }
    out.push(Observation::Arp { mac: sha, ip: spa });
}

fn parse_ipv4(ctx: &Ctx, src_mac: Mac, p: &[u8], out: &mut Vec<Observation>) {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return;
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    if ihl < 20 || p.len() < ihl {
        return;
    }
    // Non-first fragments have no transport header.
    let frag_off = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
    if frag_off != 0 {
        return;
    }
    let ttl = p[8];
    let proto = p[9];
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let l4 = &p[ihl..];

    // DHCP clients legitimately send from 0.0.0.0, so it bypasses the subnet gate.
    if proto == 17 && l4.len() >= 8 {
        let sport = u16::from_be_bytes([l4[0], l4[1]]);
        let dport = u16::from_be_bytes([l4[2], l4[3]]);
        if matches!(sport, 67 | 68) && matches!(dport, 67 | 68) {
            if let Some(obs) = parse_dhcp(ctx, &l4[8..]) {
                out.push(obs);
            }
            // An offer or acknowledgement: this device is acting as a DHCP server.
            if is_dhcp_server_reply(&l4[8..]) && src_mac.is_valid() && ctx.subnet.contains(&src) && src != ctx.own_ip {
                out.push(Observation::Signal(Signal {
                    kind: "dhcp_server".into(),
                    ts: 0, // stamped by the inventory
                    mac: src_mac,
                    ip: src,
                    other_mac: None,
                    gateway: false, // the inventory knows the gateway
                }));
            }
            return;
        }
    }

    if !ctx.subnet.contains(&src) || src == ctx.own_ip {
        return;
    }

    match proto {
        1 if l4.len() >= 8 && l4[0] == 0 => out.push(Observation::Ttl {
            mac: src_mac,
            ip: src,
            ttl,
        }),
        6 => {
            if let Some(sig) = parse_tcp_sig(l4, ttl) {
                out.push(Observation::Tcp {
                    mac: src_mac,
                    ip: src,
                    sig,
                });
            }
        }
        17 if l4.len() >= 8 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let data = &l4[8..];
            if sport == 5353 || dport == 5353 {
                if let Some(obs) = parse_mdns(src_mac, src, data) {
                    out.push(obs);
                }
            } else if sport == 1900 || dport == 1900 {
                if let Some(obs) = parse_ssdp(src_mac, src, data) {
                    out.push(obs);
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------- TCP

fn parse_tcp_sig(l4: &[u8], ttl: u8) -> Option<TcpSig> {
    if l4.len() < 20 {
        return None;
    }
    let flags = l4[13];
    let syn = flags & 0x02 != 0;
    let rst = flags & 0x04 != 0;
    if !syn || rst {
        return None;
    }
    let data_off = (l4[12] >> 4) as usize * 4;
    if data_off < 20 || l4.len() < data_off {
        return None;
    }
    let window = u16::from_be_bytes([l4[14], l4[15]]);
    let opts = &l4[20..data_off];

    let mut options = String::new();
    let (mut mss, mut wscale) = (None, None);
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => {
                options.push('E');
                break;
            }
            1 => {
                options.push('N');
                i += 1;
            }
            kind => {
                let len = *opts.get(i + 1)? as usize;
                if len < 2 || i + len > opts.len() {
                    break;
                }
                match kind {
                    2 if len == 4 => {
                        options.push('M');
                        mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                    }
                    3 if len == 3 => {
                        options.push('W');
                        wscale = Some(opts[i + 2]);
                    }
                    4 => options.push('S'),
                    8 => options.push('T'),
                    _ => options.push('?'),
                }
                i += len;
            }
        }
    }
    Some(TcpSig {
        ttl,
        window,
        options,
        mss,
        wscale,
    })
}

// ---------------------------------------------------------------- DHCP

/// Is this a DHCP server's OFFER (2) or ACK (5)? Only the fixed header and the message-type
/// option are read.
fn is_dhcp_server_reply(b: &[u8]) -> bool {
    if b.len() < 241 || b[0] != 2 || b[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return false;
    }
    let mut i = 240;
    while i < b.len() {
        match b[i] {
            255 => break,
            0 => i += 1,
            code => {
                let Some(&len) = b.get(i + 1) else { break };
                if code == 53 && len == 1 {
                    return matches!(b.get(i + 2), Some(2 | 5));
                }
                i += 2 + len as usize;
            }
        }
    }
    false
}

fn parse_dhcp(ctx: &Ctx, b: &[u8]) -> Option<Observation> {
    if b.len() < 240 || b[1] != 1 || b[2] != 6 || b[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }
    let op = b[0];
    let ciaddr = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let yiaddr = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    let mac = Mac(b[28..34].try_into().unwrap());
    if !mac.is_valid() || mac == ctx.own_mac {
        return None;
    }

    let (mut msg_type, mut hostname, mut vendor_class, mut param_list) = (0u8, None, None, None);
    let mut i = 240;
    while i < b.len() {
        let code = b[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = *b.get(i + 1)? as usize;
        let val = b.get(i + 2..i + 2 + len)?;
        match code {
            53 if len == 1 => msg_type = val[0],
            12 => hostname = clean_text(val),
            60 => vendor_class = clean_text(val),
            55 => {
                param_list = Some(
                    val.iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                )
            }
            _ => {}
        }
        i += 2 + len;
    }

    // Only bind an IP when the server confirmed it (ACK -> yiaddr) or the client
    // is renewing one it already holds (ciaddr). A bare REQUEST is only a wish.
    let ip = match (op, msg_type) {
        (2, 5) => Some(yiaddr),
        (1, _) if !ciaddr.is_unspecified() => Some(ciaddr),
        _ => None,
    }
    .filter(|ip| ctx.subnet.contains(ip));

    Some(Observation::Dhcp {
        mac,
        ip,
        hostname,
        vendor_class,
        param_list,
    })
}

// ---------------------------------------------------------------- mDNS

fn parse_mdns(mac: Mac, ip: Ipv4Addr, d: &[u8]) -> Option<Observation> {
    if d.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([d[2], d[3]]);
    if flags & 0x8000 == 0 {
        return None; // query, not an announcement
    }
    let qd = u16::from_be_bytes([d[4], d[5]]) as usize;
    let rrs = u16::from_be_bytes([d[6], d[7]]) as usize
        + u16::from_be_bytes([d[8], d[9]]) as usize
        + u16::from_be_bytes([d[10], d[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qd.min(32) {
        let (_, next) = read_name(d, pos)?;
        pos = next + 4;
    }

    let (mut hostnames, mut services, mut names, mut models) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());

    for _ in 0..rrs.min(128) {
        let Some((labels, next)) = read_name(d, pos) else {
            break;
        };
        let Some(hdr) = d.get(next..next + 10) else {
            break;
        };
        let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
        let rd_start = next + 10;
        let Some(rdata) = d.get(rd_start..rd_start + rdlen) else {
            break;
        };
        pos = rd_start + rdlen;

        match rtype {
            // A / AAAA: `name.local` is the device's hostname.
            1 | 28 => {
                if let Some(h) = local_hostname(&labels) {
                    push_uniq(&mut hostnames, h);
                }
            }
            // PTR: `_svc._tcp.local -> Instance._svc._tcp.local`, or the
            // service-enumeration record `_services._dns-sd._udp.local`.
            12 => {
                if let Some((target, _)) = read_name(d, rd_start) {
                    if labels.first().map(String::as_str) == Some("_services") {
                        if let Some(s) = service_type(&target) {
                            push_uniq(&mut services, s);
                        }
                    } else if let Some(s) = service_type(&labels) {
                        push_uniq(&mut services, s);
                        if let Some(inst) = target.first().filter(|_| target.len() > 3) {
                            push_uniq(&mut names, inst.clone());
                        }
                    }
                }
            }
            // SRV: instance name + target host.
            33 if rdlen >= 6 => {
                if let Some(s) = service_type(&labels) {
                    push_uniq(&mut services, s);
                    if labels.len() > 3 {
                        push_uniq(&mut names, labels[0].clone());
                    }
                }
                if let Some((target, _)) = read_name(d, rd_start + 6) {
                    if let Some(h) = local_hostname(&target) {
                        push_uniq(&mut hostnames, h);
                    }
                }
            }
            // TXT: pick up model strings (Apple `model=` / `md=`).
            16 => {
                let mut j = 0;
                while j < rdata.len() {
                    let l = rdata[j] as usize;
                    let Some(s) = rdata.get(j + 1..j + 1 + l) else {
                        break;
                    };
                    j += 1 + l;
                    let s = String::from_utf8_lossy(s);
                    if let Some(v) = s.strip_prefix("model=").or_else(|| s.strip_prefix("md=")) {
                        if let Some(v) = clean_str(v) {
                            push_uniq(&mut models, v);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if hostnames.is_empty() && services.is_empty() && names.is_empty() && models.is_empty() {
        return None;
    }
    Some(Observation::Mdns {
        mac,
        ip,
        hostnames,
        services,
        names,
        models,
    })
}

/// Read a (possibly compressed) DNS name. Returns the labels and the offset of
/// the byte after the name in the original position (pointers do not advance it).
fn read_name(d: &[u8], start: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *d.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let lo = *d.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = ((len & 0x3f) << 8) | lo;
            jumps += 1;
            if jumps > 10 {
                return None;
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label = d.get(pos + 1..pos + 1 + len)?;
        labels.push(clean_str(&String::from_utf8_lossy(label)).unwrap_or_default());
        pos += 1 + len;
        if labels.len() > 32 {
            return None;
        }
    }
    Some((labels, end.unwrap_or(pos)))
}

/// `["Foo", "_airplay", "_tcp", "local"]` -> `_airplay._tcp`.
fn service_type(labels: &[String]) -> Option<String> {
    let n = labels.len();
    if n >= 3 && labels[n - 1] == "local" && labels[n - 3].starts_with('_') {
        let (svc, proto) = (&labels[n - 3], &labels[n - 2]);
        if proto == "_tcp" || proto == "_udp" {
            return Some(format!("{svc}.{proto}"));
        }
    }
    None
}

/// `["macbook", "local"]` -> `macbook`. Rejects service names and reverse zones.
fn local_hostname(labels: &[String]) -> Option<String> {
    if labels.len() == 2 && labels[1] == "local" && !labels[0].starts_with('_') {
        clean_str(&labels[0])
    } else {
        None
    }
}

// ---------------------------------------------------------------- SSDP

fn parse_ssdp(mac: Mac, ip: Ipv4Addr, d: &[u8]) -> Option<Observation> {
    let text = String::from_utf8_lossy(&d[..d.len().min(2048)]);
    let mut lines = text.lines();
    let first = lines.next()?;
    if !(first.starts_with("NOTIFY")
        || first.starts_with("HTTP/1.1 200")
        || first.starts_with("M-SEARCH"))
    {
        return None;
    }
    let mut server = None;
    let mut types = Vec::new();
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            // M-SEARCH carries the *searcher's* USER-AGENT, which identifies
            // its OS just as well as a responder's SERVER header.
            "server" | "user-agent" => server = server.or_else(|| clean_str(v)),
            "nt" | "st" => {
                if let Some(t) = clean_str(v) {
                    if types.len() < 8 {
                        push_uniq(&mut types, t);
                    }
                }
            }
            _ => {}
        }
    }
    if server.is_none() && types.is_empty() {
        return None;
    }
    Some(Observation::Ssdp {
        mac,
        ip,
        server,
        types,
    })
}

// ---------------------------------------------------------------- helpers

/// Network-supplied text is attacker-controlled: drop control chars, cap length.
pub(crate) fn clean_str(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(96)
        .collect::<String>()
        .trim()
        .to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

fn clean_text(b: &[u8]) -> Option<String> {
    clean_str(&String::from_utf8_lossy(b).replace('\0', ""))
}

fn push_uniq(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Ctx {
        Ctx {
            subnet: "192.168.1.0/24".parse().unwrap(),
            own_mac: Mac([0x02, 0, 0, 0, 0, 0x99]),
            own_ip: Ipv4Addr::new(192, 168, 1, 10),
            flows: false,
            ot: false,
        }
    }

    const DEV: [u8; 6] = [0x3c, 0x22, 0xfb, 0x11, 0x22, 0x33];

    fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn ipv4(proto: u8, ttl: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, ttl, proto, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    fn udp(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(data);
        u
    }

    fn arp(op: u16, sha: [u8; 6], spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0, 1, 8, 0, 6, 4];
        p.extend_from_slice(&op.to_be_bytes());
        p.extend_from_slice(&sha);
        p.extend_from_slice(&spa);
        p.extend_from_slice(&[0; 6]);
        p.extend_from_slice(&tpa);
        p
    }

    #[test]
    fn arp_reply_in_subnet() {
        let f = eth(
            [0x02, 0, 0, 0, 0, 0x99],
            DEV,
            ETH_ARP,
            &arp(2, DEV, [192, 168, 1, 20], [192, 168, 1, 10]),
        );
        let obs = parse_frame(&ctx(), &f);
        assert!(matches!(
            obs.as_slice(),
            [Observation::Arp { mac, ip }] if mac.0 == DEV && *ip == Ipv4Addr::new(192,168,1,20)
        ));
    }

    #[test]
    fn arp_ignored_when_probe_foreign_subnet_or_mismatched_sha() {
        let c = ctx();
        let probe = eth([0xff; 6], DEV, ETH_ARP, &arp(1, DEV, [0; 4], [192, 168, 1, 20]));
        assert!(parse_frame(&c, &probe).is_empty());
        let foreign = eth([0xff; 6], DEV, ETH_ARP, &arp(2, DEV, [10, 0, 0, 5], [192, 168, 1, 10]));
        assert!(parse_frame(&c, &foreign).is_empty());
        // sender hardware address != Ethernet source: never learned, but reported
        let spoof = eth([0xff; 6], DEV, ETH_ARP, &arp(2, [0x02, 2, 3, 4, 5, 6], [192, 168, 1, 20], [0; 4]));
        let obs = parse_frame(&c, &spoof);
        assert!(matches!(
            obs.as_slice(),
            [Observation::Signal(s)] if s.kind == "arp_mismatch" && s.mac.0 == DEV
                && s.other_mac == Some(Mac([0x02, 2, 3, 4, 5, 6])) && s.ip == Ipv4Addr::new(192, 168, 1, 20)
        ));
        // ...but not when the claimed address is outside the subnet or our own
        let far = eth([0xff; 6], DEV, ETH_ARP, &arp(2, [0x02, 2, 3, 4, 5, 6], [10, 0, 0, 9], [0; 4]));
        assert!(parse_frame(&c, &far).is_empty());
        // own frames and truncated frames
        let own = eth([0xff; 6], c.own_mac.0, ETH_ARP, &arp(1, c.own_mac.0, [192, 168, 1, 10], [192, 168, 1, 20]));
        assert!(parse_frame(&c, &own).is_empty());
        assert!(parse_frame(&c, &probe[..20]).is_empty());
    }

    #[test]
    fn vlan_tagged_arp() {
        let mut payload = vec![0x00, 0x05, 0x08, 0x06];
        payload.extend(arp(2, DEV, [192, 168, 1, 21], [0; 4]));
        let f = eth([0xff; 6], DEV, ETH_VLAN, &payload);
        assert_eq!(parse_frame(&ctx(), &f).len(), 1);
    }

    fn tcp_syn(flags: u8, window: u16, opts: &[u8]) -> Vec<u8> {
        let mut t = vec![0; 20];
        t[0..2].copy_from_slice(&50000u16.to_be_bytes());
        t[2..4].copy_from_slice(&443u16.to_be_bytes());
        t[12] = (((20 + opts.len()) / 4) as u8) << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&window.to_be_bytes());
        t.extend_from_slice(opts);
        t
    }

    #[test]
    fn tcp_syn_signature_windows_like() {
        // MSS 1460, NOP, WS 8, NOP, NOP, SACK-permitted
        let opts = [2, 4, 5, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2];
        let f = eth(
            [0xff; 6],
            DEV,
            ETH_IPV4,
            &ipv4(6, 128, [192, 168, 1, 30], [1, 1, 1, 1], &tcp_syn(0x02, 64240, &opts)),
        );
        let obs = parse_frame(&ctx(), &f);
        let Some(Observation::Tcp { sig, .. }) = obs.first() else {
            panic!("expected tcp obs, got {obs:?}");
        };
        assert_eq!(sig.ttl, 128);
        assert_eq!(sig.window, 64240);
        assert_eq!(sig.options, "MNWNNS");
        assert_eq!(sig.mss, Some(1460));
        assert_eq!(sig.wscale, Some(8));
    }

    #[test]
    fn tcp_non_syn_and_rst_ignored() {
        let c = ctx();
        for flags in [0x10u8, 0x14, 0x04] {
            let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [1, 1, 1, 1], &tcp_syn(flags, 1000, &[])));
            assert!(parse_frame(&c, &f).is_empty(), "flags {flags:#x}");
        }
        // SYN-ACK is accepted (our own port scan elicits these).
        let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [192, 168, 1, 10], &tcp_syn(0x12, 65535, &[])));
        assert_eq!(parse_frame(&c, &f).len(), 1);
    }

    #[test]
    fn malformed_tcp_options_do_not_panic() {
        // option claims length 40 but only 4 bytes exist
        let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [1, 1, 1, 1], &tcp_syn(0x02, 1000, &[2, 40, 0, 0])));
        let _ = parse_frame(&ctx(), &f);
        // zero-length option must not loop forever
        let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [1, 1, 1, 1], &tcp_syn(0x02, 1000, &[9, 0, 0, 0])));
        let _ = parse_frame(&ctx(), &f);
    }

    #[test]
    fn icmp_echo_reply_gives_ttl() {
        let icmp = [0u8, 0, 0, 0, 0, 1, 0, 1];
        let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(1, 64, [192, 168, 1, 40], [192, 168, 1, 10], &icmp));
        assert!(matches!(
            parse_frame(&ctx(), &f).as_slice(),
            [Observation::Ttl { ttl: 64, .. }]
        ));
    }

    fn dhcp(op: u8, msg_type: u8, chaddr: [u8; 6], yiaddr: [u8; 4], opts: &[(u8, &[u8])]) -> Vec<u8> {
        let mut b = vec![0u8; 240];
        b[0] = op;
        b[1] = 1;
        b[2] = 6;
        b[16..20].copy_from_slice(&yiaddr);
        b[28..34].copy_from_slice(&chaddr);
        b[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        b.extend_from_slice(&[53, 1, msg_type]);
        for (code, val) in opts {
            b.push(*code);
            b.push(val.len() as u8);
            b.extend_from_slice(val);
        }
        b.push(255);
        b
    }

    #[test]
    fn dhcp_request_from_zero_ip() {
        let d = dhcp(1, 3, DEV, [0; 4], &[(12, b"Anns-iPhone"), (60, b"android-dhcp-13"), (55, &[1, 3, 6, 15])]);
        let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(17, 64, [0; 4], [255; 4], &udp(68, 67, &d)));
        let obs = parse_frame(&ctx(), &f);
        let [Observation::Dhcp { mac, ip, hostname, vendor_class, param_list }] = obs.as_slice() else {
            panic!("{obs:?}");
        };
        assert_eq!(mac.0, DEV);
        assert_eq!(*ip, None); // a bare REQUEST doesn't bind an address
        assert_eq!(hostname.as_deref(), Some("Anns-iPhone"));
        assert_eq!(vendor_class.as_deref(), Some("android-dhcp-13"));
        assert_eq!(param_list.as_deref(), Some("1,3,6,15"));
    }

    #[test]
    fn dhcp_ack_binds_ip() {
        let d = dhcp(2, 5, DEV, [192, 168, 1, 77], &[]);
        let f = eth(DEV, [0x00, 0x1b, 0x63, 1, 1, 1], ETH_IPV4, &ipv4(17, 64, [192, 168, 1, 1], [192, 168, 1, 77], &udp(67, 68, &d)));
        let obs = parse_frame(&ctx(), &f);
        assert!(matches!(
            obs.as_slice(),
            [Observation::Dhcp { ip: Some(ip), .. }, Observation::Signal(_)] if *ip == Ipv4Addr::new(192,168,1,77)
        ), "{obs:?}");
    }

    #[test]
    fn a_dhcp_offer_or_ack_marks_its_sender_as_a_server_but_requests_and_other_replies_do_not() {
        let server = [0x00, 0x1b, 0x63, 1, 1, 1];
        let frame = |op, ty, src: [u8; 4]| eth(DEV, server, ETH_IPV4, &ipv4(17, 64, src, [255; 4], &udp(67, 68, &dhcp(op, ty, DEV, [192, 168, 1, 77], &[]))));
        let signal = |f: &[u8]| parse_frame(&ctx(), f).into_iter().find_map(|o| if let Observation::Signal(s) = o { Some(s) } else { None });
        for ty in [2, 5] {
            let s = signal(&frame(2, ty, [192, 168, 1, 1])).expect("server reply");
            assert_eq!((s.kind.as_str(), s.mac.0, s.ip), ("dhcp_server", server, Ipv4Addr::new(192, 168, 1, 1)));
        }
        assert!(signal(&frame(2, 6, [192, 168, 1, 1])).is_none(), "NAK is not an offer");
        assert!(signal(&frame(2, 3, [192, 168, 1, 1])).is_none(), "a REQUEST type in a reply");
        assert!(signal(&frame(1, 1, [0, 0, 0, 0])).is_none(), "a client DISCOVER");
        assert!(signal(&frame(2, 2, [10, 9, 9, 9])).is_none(), "a server outside our subnet is not ours to judge");
        // truncated or garbage bodies never panic and never claim a server
        for n in [0, 10, 239, 240, 241] {
            assert!(!is_dhcp_server_reply(&vec![2u8; n]));
        }
    }

    fn dns_name(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in name.split('.') {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn rr(name: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut v = name.to_vec();
        v.extend_from_slice(&rtype.to_be_bytes());
        v.extend_from_slice(&[0x80, 0x01, 0, 0, 0, 120]);
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    #[test]
    fn mdns_response_extracts_host_service_model() {
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0];
        m.extend(rr(&dns_name("_ipp._tcp.local"), 12, &dns_name("Office Printer._ipp._tcp.local")));
        let mut srv = vec![0, 0, 0, 0, 0x02, 0x77];
        srv.extend(dns_name("hp-laser.local"));
        m.extend(rr(&dns_name("Office Printer._ipp._tcp.local"), 33, &srv));
        m.extend(rr(&dns_name("hp-laser.local"), 1, &[192, 168, 1, 50]));
        let txt = b"\x0emodel=LaserJet";
        m.extend(rr(&dns_name("Office Printer._ipp._tcp.local"), 16, txt));

        let f = eth([0x01, 0, 0x5e, 0, 0, 0xfb], DEV, ETH_IPV4, &ipv4(17, 255, [192, 168, 1, 50], [224, 0, 0, 251], &udp(5353, 5353, &m)));
        let obs = parse_frame(&ctx(), &f);
        let [Observation::Mdns { hostnames, services, names, models, .. }] = obs.as_slice() else {
            panic!("{obs:?}");
        };
        assert_eq!(hostnames, &["hp-laser"]);
        assert_eq!(services, &["_ipp._tcp"]);
        assert_eq!(names, &["Office Printer"]);
        assert_eq!(models, &["LaserJet"]);
    }

    #[test]
    fn mdns_compression_pointer_loop_is_rejected() {
        // header + a name that points to itself
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(parse_mdns(Mac(DEV), Ipv4Addr::new(192, 168, 1, 5), &m).is_none());
    }

    #[test]
    fn mdns_queries_ignored() {
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend(dns_name("_airplay._tcp.local"));
        m.extend_from_slice(&[0, 12, 0, 1]);
        assert!(parse_mdns(Mac(DEV), Ipv4Addr::new(192, 168, 1, 5), &m).is_none());
    }

    #[test]
    fn ssdp_notify_and_msearch() {
        let n = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: Linux/5.4 UPnP/1.1 MiniUPnPd/2.2\r\n\r\n";
        let f = eth([0x01, 0, 0x5e, 0x7f, 0xff, 0xfa], DEV, ETH_IPV4, &ipv4(17, 64, [192, 168, 1, 1], [239, 255, 255, 250], &udp(1900, 1900, n)));
        let obs = parse_frame(&ctx(), &f);
        let [Observation::Ssdp { server, types, .. }] = obs.as_slice() else {
            panic!("{obs:?}");
        };
        assert!(server.as_deref().unwrap().contains("MiniUPnPd"));
        assert_eq!(types.len(), 1);

        let s = b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\nUSER-AGENT: Microsoft-Windows/10.0 UPnP/1.0\r\n\r\n";
        let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(17, 128, [192, 168, 1, 31], [239, 255, 255, 250], &udp(50000, 1900, s)));
        assert!(matches!(
            parse_frame(&ctx(), &f).as_slice(),
            [Observation::Ssdp { server: Some(s), .. }] if s.contains("Windows")
        ));
    }

    fn flow_ctx() -> Ctx {
        Ctx { flows: true, ..ctx() }
    }

    fn tcp_hdr(sport: u16, dport: u16) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = 0x10; // ACK: an ordinary data segment, not a SYN
        t
    }

    #[test]
    fn outbound_flow_to_the_internet_is_attributed_to_the_sender() {
        let router = [0x00, 0x1b, 0x63, 1, 1, 1];
        let f = eth(router, DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [93, 184, 216, 34], &tcp_hdr(51234, 443)));
        let obs = parse_frame(&flow_ctx(), &f);
        let sample = obs.iter().find_map(|o| match o { Observation::FlowSample(s) => Some(s), _ => None }).unwrap();
        assert_eq!(sample.mac.0, DEV);
        assert_eq!(sample.remote, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!((sample.proto, sample.port, sample.outbound), (6, 443, true));
        assert_eq!(sample.bytes, 40);
        // ...and doubles as an identity binding.
        assert!(obs.iter().any(|o| matches!(o, Observation::Arp { mac, .. } if mac.0 == DEV)));
    }

    #[test]
    fn inbound_flow_is_attributed_by_ethernet_destination() {
        let router = [0x00, 0x1b, 0x63, 1, 1, 1];
        let f = eth(DEV, router, ETH_IPV4, &ipv4(6, 52, [93, 184, 216, 34], [192, 168, 1, 30], &tcp_hdr(443, 51234)));
        let obs = parse_frame(&flow_ctx(), &f);
        let [Observation::FlowSample(s)] = obs.as_slice() else { panic!("{obs:?}") };
        assert_eq!((s.mac.0, s.outbound, s.port), (DEV, false, 443));
    }

    #[test]
    fn lan_local_multicast_broadcast_and_disabled_flows_are_not_flows() {
        let c = flow_ctx();
        let has_flow = |c: &Ctx, f: &[u8]| parse_frame(c, f).iter().any(|o| matches!(o, Observation::FlowSample(_)));
        // device-to-device inside the subnet
        let lan = eth([0x3c, 0x22, 0xfb, 9, 9, 9], DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [192, 168, 1, 31], &tcp_hdr(1000, 22)));
        assert!(!has_flow(&c, &lan));
        for dst in [[224, 0, 0, 251], [255, 255, 255, 255], [169, 254, 1, 1]] {
            let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(17, 1, [192, 168, 1, 30], dst, &udp(5000, 5000, b"x")));
            assert!(!has_flow(&c, &f), "{dst:?}");
        }
        let out = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [1, 1, 1, 1], &tcp_hdr(1000, 443)));
        assert!(has_flow(&c, &out));
        assert!(!has_flow(&ctx(), &out), "flows are opt-in");
    }

    #[test]
    fn our_own_traffic_counts_for_the_self_asset_but_is_not_discovered() {
        let c = flow_ctx();
        let f = eth([0x00, 0x1b, 0x63, 1, 1, 1], c.own_mac.0, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 10], [1, 1, 1, 1], &tcp_hdr(1000, 443)));
        let obs = parse_frame(&c, &f);
        assert!(matches!(obs.as_slice(), [Observation::FlowSample(s)] if s.mac == c.own_mac));
    }

    #[test]
    fn truncated_transport_header_yields_no_flow() {
        let f = eth([0xff; 6], DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [1, 1, 1, 1], &[0, 1]));
        assert!(parse_frame(&flow_ctx(), &f).is_empty());
    }

    #[test]
    fn hostile_text_is_sanitised() {
        assert_eq!(clean_str("a\u{0}b\r\n<x>").as_deref(), Some("ab<x>"));
        assert_eq!(clean_str(&"x".repeat(500)).unwrap().len(), 96);
        assert_eq!(clean_str("\u{1}\u{2}"), None);
    }

    // ------------------------------------------------------------------ fuzz

    /// Small deterministic PRNG (xorshift64*) so failures are reproducible.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    /// One valid frame of every kind the parser understands, as fuzzing seeds.
    fn seed_frames() -> Vec<Vec<u8>> {
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        m.extend(rr(&dns_name("_ipp._tcp.local"), 12, &dns_name("Printer._ipp._tcp.local")));
        let mut srv = vec![0, 0, 0, 0, 0x02, 0x77];
        srv.extend(dns_name("host.local"));
        m.extend(rr(&dns_name("Printer._ipp._tcp.local"), 33, &srv));
        m.extend(rr(&dns_name("host.local"), 1, &[192, 168, 1, 50]));
        let dhcp_body = dhcp(1, 3, DEV, [0; 4], &[(12, b"host"), (60, b"MSFT 5.0"), (55, &[1, 3, 6])]);
        let ssdp = b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nSERVER: Linux UPnP/1.0\r\n\r\n";
        let syn = tcp_syn(0x02, 64240, &[2, 4, 5, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2]);
        vec![
            eth([0xff; 6], DEV, ETH_ARP, &arp(2, DEV, [192, 168, 1, 20], [192, 168, 1, 10])),
            eth([0xff; 6], DEV, ETH_ARP, &arp(2, [0x02, 2, 3, 4, 5, 6], [192, 168, 1, 20], [0; 4])),
            eth([0xff; 6], DEV, ETH_IPV4, &ipv4(17, 64, [0; 4], [255; 4], &udp(68, 67, &dhcp_body))),
            eth([0x01, 0, 0x5e, 0, 0, 0xfb], DEV, ETH_IPV4, &ipv4(17, 255, [192, 168, 1, 50], [224, 0, 0, 251], &udp(5353, 5353, &m))),
            eth([0xff; 6], DEV, ETH_IPV4, &ipv4(17, 64, [192, 168, 1, 1], [239, 255, 255, 250], &udp(1900, 1900, ssdp))),
            eth([0xff; 6], DEV, ETH_IPV4, &ipv4(6, 128, [192, 168, 1, 30], [93, 184, 216, 34], &syn)),
            eth([0xff; 6], DEV, ETH_IPV4, &ipv4(1, 64, [192, 168, 1, 40], [192, 168, 1, 10], &[0, 0, 0, 0, 0, 1, 0, 1])),
            eth([0xff; 6], DEV, ETH_VLAN, &[0x00, 0x05, 0x08, 0x06]),
        ]
    }

    /// The parser reads bytes from the network, i.e. from an attacker: whatever
    /// arrives, it must neither panic nor loop. Every truncation of every valid
    /// frame, tens of thousands of mutations of them, and pure noise.
    #[test]
    fn hostile_frames_never_panic_the_parser() {
        let with_flows = Ctx { flows: true, ..ctx() };
        let without = ctx();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut frames_tried = 0u32;
        let mut run = |f: &[u8]| {
            let _ = parse_frame(&with_flows, f);
            let _ = parse_frame(&without, f);
            frames_tried += 1;
        };
        for seed in seed_frames() {
            // 1. every truncation
            for n in 0..=seed.len() {
                run(&seed[..n]);
            }
            // 2. random byte/bit mutations, sometimes combined with truncation
            for _ in 0..4000 {
                let mut f = seed.clone();
                for _ in 0..1 + rng.below(4) {
                    let i = rng.below(f.len());
                    match rng.below(3) {
                        0 => f[i] = rng.next() as u8,
                        1 => f[i] ^= 1 << rng.below(8),
                        _ => f[i] = [0x00, 0xff, 0x7f, 0x80, 0xc0][rng.below(5)],
                    }
                }
                if rng.below(4) == 0 {
                    f.truncate(rng.below(f.len() + 1));
                }
                run(&f);
            }
        }
        // 3. pure noise, half of it dressed up with a plausible Ethernet header
        for _ in 0..30_000 {
            let len = rng.below(400);
            let mut f: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if f.len() >= 14 && rng.below(2) == 0 {
                f[0..6].copy_from_slice(&[0xff; 6]);
                f[6..12].copy_from_slice(&DEV);
                let et = [ETH_ARP, ETH_IPV4, ETH_VLAN][rng.below(3)];
                f[12..14].copy_from_slice(&et.to_be_bytes());
                if et == ETH_IPV4 && f.len() > 14 {
                    f[14] = 0x40 | (f[14] & 0x0f).max(5); // valid-looking IPv4 header
                }
            }
            run(&f);
        }
        assert!(frames_tried > 60_000, "{frames_tried}");
    }

    /// DNS compression pointers that form a cycle, point forward, or point
    /// outside the message must terminate quickly with a rejection.
    #[test]
    fn dns_name_pointer_tricks_terminate() {
        let m = [0u8; 12];
        for evil in [
            vec![0xc0, 12],                     // points at itself
            vec![0xc0, 14, 0xc0, 12],           // two-node cycle
            vec![0xc0, 0xff],                   // outside the message
            vec![0x3f],                         // label longer than the buffer
            vec![0x40, 0, 0],                   // reserved label type
            [[1u8, b'a'].repeat(200), vec![0]].concat(), // absurdly many labels
        ] {
            let mut d = m.to_vec();
            d.extend(&evil);
            assert!(read_name(&d, 12).is_none(), "{evil:?}");
        }
    }

    // ------------------------------------------------------- OT integration

    fn ot_ctx() -> Ctx {
        Ctx { flows: true, ot: true, ..ctx() }
    }

    /// Ethernet+IPv4+TCP frame carrying `payload` from 192.168.1.<src> to 192.168.1.<dst>.
    fn tcp_frame(src_mac: [u8; 6], dst_mac: [u8; 6], src: u8, dst: u8, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut t = tcp_hdr(sport, dport);
        t.extend_from_slice(payload);
        eth(dst_mac, src_mac, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, src], [192, 168, 1, dst], &t))
    }

    const PLC: [u8; 6] = [0x00, 0x1b, 0x1b, 9, 9, 9];

    fn modbus_read() -> Vec<u8> {
        vec![0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 10]
    }

    #[test]
    fn modbus_between_local_devices_becomes_an_oriented_sample() {
        let f = tcp_frame(DEV, PLC, 30, 31, 50_000, 502, &modbus_read());
        let obs = parse_frame(&ot_ctx(), &f);
        let sample = obs.iter().find_map(|o| match o { Observation::Ot(s) => Some(s), _ => None }).expect("an OT sample");
        assert_eq!((sample.pdu.proto, sample.pdu.server_is_src, sample.pdu.class), ("modbus", false, crate::model::OtClass::Read));
        assert_eq!((sample.src_mac.0, sample.dst_mac.0), (DEV, PLC));
        assert_eq!((sample.src_ip, sample.dst_ip), (Ipv4Addr::new(192, 168, 1, 30), Ipv4Addr::new(192, 168, 1, 31)));
        // the PLC's answer is the same conversation seen from the server side
        let reply = tcp_frame(PLC, DEV, 31, 30, 502, 50_000, &[0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 5]);
        let obs = parse_frame(&ot_ctx(), &reply);
        assert!(obs.iter().any(|o| matches!(o, Observation::Ot(s) if s.pdu.server_is_src && s.pdu.proto == "modbus")));
    }

    #[test]
    fn encrypted_traffic_between_local_devices_is_a_path_with_its_handshake_metadata_and_needs_no_industrial_port() {
        let hello: Vec<u8> = (0..250).map(|i| u8::from_str_radix(&"16030100f5010000f103030fa623c5423c7f6a6b13f467d45a8e8d9b2996fde3ab0deb2fd075d0e6a3352720fc60ed75deb6ce734c292061782722550ecc57a98166d4d318a3d359cc40a1e2000813021303130100ff010000a0000000150013000010706c63312e706c616e742e6c6f63616c000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020099865fe339018d045a3f56bff77221709a47c4e04d2927373447f08e3763618"[2 * i..2 * i + 2], 16).unwrap()).collect();
        // a client opens TLS to 192.168.1.31:8443: who talks to whom is visible although nothing else is
        let f = tcp_frame(DEV, PLC, 30, 31, 50_000, 8443, &hello);
        let obs = parse_frame(&ot_ctx(), &f);
        let s = obs.iter().find_map(|o| match o { Observation::Ot(s) => Some(s), _ => None }).expect("a path");
        assert_eq!((s.pdu.proto, s.pdu.server_is_src, s.pdu.class, s.pdu.port), ("tls", false, crate::model::OtClass::Opaque, 8443));
        assert!(s.pdu.detail.contains("TLS 1.3") && s.pdu.detail.contains("plc1.plant.local"), "{}", s.pdu.detail);
        assert_eq!((s.src_mac.0, s.dst_mac.0), (DEV, PLC));
        // application data on a secured OPC UA port names the protocol by its port
        let data = tcp_frame(PLC, DEV, 31, 30, 4843, 50_000, &[0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5]);
        assert!(parse_frame(&ot_ctx(), &data).iter().any(|o| matches!(o, Observation::Ot(s) if s.pdu.proto == "opcua-tls" && s.pdu.server_is_src)));
        // TLS towards the outside is flow accounting's business, not a local path; and it is opt-in like the rest
        let out = eth(PLC, DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [8, 8, 8, 8], &{ let mut t = tcp_hdr(50_000, 443); t.extend_from_slice(&hello); t }));
        assert!(!parse_frame(&ot_ctx(), &out).iter().any(|o| matches!(o, Observation::Ot(_))));
        assert!(!parse_frame(&flow_ctx(), &f).iter().any(|o| matches!(o, Observation::Ot(_))));
        // a decoded protocol is still decoded, not called opaque
        assert!(parse_frame(&ot_ctx(), &tcp_frame(DEV, PLC, 30, 31, 50_000, 502, &modbus_read())).iter().any(|o| matches!(o, Observation::Ot(s) if s.pdu.proto == "modbus")));
    }

    #[test]
    fn industrial_decoding_is_opt_in_local_only_and_signature_checked() {
        let f = tcp_frame(DEV, PLC, 30, 31, 50_000, 502, &modbus_read());
        assert!(!parse_frame(&flow_ctx(), &f).iter().any(|o| matches!(o, Observation::Ot(_))), "off unless ot is enabled");
        // towards the outside it is flow accounting's business (flagged by port), not a local conversation
        let mut t = tcp_hdr(50_000, 502);
        t.extend_from_slice(&modbus_read());
        let out = eth(PLC, DEV, ETH_IPV4, &ipv4(6, 64, [192, 168, 1, 30], [8, 8, 8, 8], &t));
        let obs = parse_frame(&ot_ctx(), &out);
        assert!(!obs.iter().any(|o| matches!(o, Observation::Ot(_))));
        assert!(obs.iter().any(|o| matches!(o, Observation::FlowSample(s) if s.port == 502 && s.remote == Ipv4Addr::new(8, 8, 8, 8))));
        // same port, but not Modbus: no sample
        let web = tcp_frame(DEV, PLC, 30, 31, 50_000, 502, b"GET / HTTP/1.1\r\n\r\n");
        assert!(!parse_frame(&ot_ctx(), &web).iter().any(|o| matches!(o, Observation::Ot(_))));
        // the collector's own host is a participant like any other (as in flow accounting)
        let own = tcp_frame(ot_ctx().own_mac.0, PLC, 10, 31, 50_000, 502, &modbus_read());
        assert!(parse_frame(&ot_ctx(), &own).iter().any(|o| matches!(o, Observation::Ot(s) if s.src_mac == ot_ctx().own_mac)));
    }

    #[test]
    fn link_layer_announcements_become_identity() {
        // LLDP
        let mut lldp = vec![0x02, 0x07, 4, 0x00, 0x1b, 0x63, 1, 2, 3]; // chassis id (MAC)
        lldp.extend([0x0a, 0x08]); // system name TLV, 8 bytes
        lldp.extend(b"edge-sw1");
        lldp.extend([0, 0]);
        let f = eth([0x01, 0x80, 0xc2, 0, 0, 0x0e], DEV, 0x88cc, &lldp);
        let obs = parse_frame(&ctx(), &f);
        assert!(matches!(obs.as_slice(), [Observation::Link(l)] if l.source == "lldp" && l.mac.0 == DEV && l.fields["system_name"] == "edge-sw1"));

        // CDP: 802.3 length, LLC/SNAP, then TLVs
        let mut cdp = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00, 2, 180, 0, 0];
        cdp.extend([0x00, 0x01, 0x00, 0x0c]); // device id, 8 bytes of value
        cdp.extend(b"core-sw1");
        let len = cdp.len() as u16;
        let f = eth([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc], DEV, len, &cdp);
        let obs = parse_frame(&ctx(), &f);
        assert!(matches!(obs.as_slice(), [Observation::Link(l)] if l.source == "cdp" && l.fields["system_name"] == "core-sw1"));

        // PROFINET DCP identify response with a station name
        let name = b"plc-a";
        let mut block = vec![2, 2, 0, (name.len() + 2) as u8, 0, 0];
        block.extend(name);
        block.push(0); // pad to even
        let mut dcp = vec![0xfe, 0xff, 5, 1, 0, 0, 0, 1, 0, 0];
        dcp.extend((block.len() as u16).to_be_bytes());
        dcp.extend(&block);
        let f = eth([0xff; 6], DEV, 0x8892, &dcp);
        assert!(matches!(parse_frame(&ctx(), &f).as_slice(), [Observation::Link(l)] if l.source == "profinet" && l.fields["station_name"] == "plc-a"));
        // and the capture filters really ask the kernel for these frames
        assert!(BPF_FILTER.contains("0x88cc") && BPF_FILTER.contains("0x8892") && BPF_FILTER.contains("01:00:0c:cc:cc:cc"));
        assert!(BPF_FILTER_FLOWS.contains("0x88cc"));
    }
}
