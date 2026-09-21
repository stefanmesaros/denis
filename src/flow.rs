//! Capture-side flow aggregation: per-packet `FlowSample`s -> per-window
//! `FlowRecord`s, so only a small summary crosses threads (and, for a remote
//! agent, the network).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::model::{ConvRecord, FlowBatch, FlowRecord, FlowSample, Mac, OtClass, OtSample};

/// Upper bound on distinct (device, remote, proto, port) keys per window; a
/// port scan or P2P swarm must not be able to exhaust memory.
pub const MAX_KEYS: usize = 50_000;

type Key = (Mac, Ipv4Addr, u8, u16);

/// (client, server, protocol, server port)
type ConvKey = (Mac, Mac, &'static str, u16);

/// Upper bound on distinct conversations per window.
pub const MAX_CONVS: usize = 5_000;

#[derive(Default)]
struct ConvAcc {
    client_ip: Option<Ipv4Addr>,
    server_ip: Option<Ipv4Addr>,
    packets: u64,
    bytes: u64,
    reads: u64,
    writes: u64,
    controls: u64,
    note: Option<String>,
    commands: std::collections::BTreeMap<String, u32>,
}

pub struct FlowAgg {
    window_secs: i64,
    window_start: i64,
    map: HashMap<Key, (u64, u64, u64)>,
    convs: HashMap<ConvKey, ConvAcc>,
    pub dropped: u64,
}

impl FlowAgg {
    pub fn new(window_secs: u32, now: i64) -> Self {
        let w = window_secs.max(1) as i64;
        FlowAgg {
            window_secs: w,
            window_start: now / w * w,
            map: HashMap::new(),
            convs: HashMap::new(),
            dropped: 0,
        }
    }

    pub fn add(&mut self, s: &FlowSample) {
        let key = (s.mac, s.remote, s.proto, s.port);
        if !self.map.contains_key(&key) && self.map.len() >= MAX_KEYS {
            self.dropped += 1;
            return;
        }
        let e = self.map.entry(key).or_default();
        if s.outbound {
            e.0 += s.bytes as u64;
        } else {
            e.1 += s.bytes as u64;
        }
        e.2 += 1;
    }

    /// Account one industrial message. The "client" is whichever side asked;
    /// the orientation is what makes `PLC <- HMI` distinguishable from `HMI <- PLC`.
    pub fn add_conv(&mut self, s: &OtSample) {
        let (cm, sm, ci, si) = if s.pdu.server_is_src {
            (s.dst_mac, s.src_mac, s.dst_ip, s.src_ip)
        } else {
            (s.src_mac, s.dst_mac, s.src_ip, s.dst_ip)
        };
        let key = (cm, sm, s.pdu.proto, s.pdu.port);
        if !self.convs.contains_key(&key) && self.convs.len() >= MAX_CONVS {
            self.dropped += 1;
            return;
        }
        let a = self.convs.entry(key).or_default();
        a.client_ip = Some(ci);
        a.server_ip = Some(si);
        a.packets += 1;
        a.bytes += s.bytes as u64;
        // remember which functions were used (bounded): the detector can watch for specific ones
        if s.pdu.class != OtClass::Other && (a.commands.contains_key(&s.pdu.detail) || a.commands.len() < crate::model::MAX_COMMANDS) {
            *a.commands.entry(s.pdu.detail.clone()).or_insert(0) += 1;
        }
        match s.pdu.class {
            OtClass::Read | OtClass::Identify => a.reads += 1,
            OtClass::Write => a.writes += 1,
            OtClass::Control => {
                a.controls += 1;
                a.note.get_or_insert_with(|| s.pdu.detail.clone());
            }
            OtClass::Other | OtClass::Opaque => {}
        }
    }

    /// Close the window once `now` has left it. Returns its records (possibly
    /// none) and starts the window containing `now`.
    pub fn take_if_due(&mut self, now: i64) -> Option<FlowBatch> {
        if now < self.window_start + self.window_secs {
            return None;
        }
        let start = self.window_start;
        self.window_start = now / self.window_secs * self.window_secs;
        let secs = self.window_secs as u32;
        let records: Vec<FlowRecord> = self
            .map
            .drain()
            .map(|((mac, remote, proto, port), (out, inb, pk))| FlowRecord {
                mac,
                remote,
                proto,
                port,
                bytes_out: out,
                bytes_in: inb,
                packets: pk,
                window_start: start,
                window_secs: secs,
            })
            .collect();
        let convs: Vec<ConvRecord> = self
            .convs
            .drain()
            .map(|((cm, sm, proto, port), a)| ConvRecord {
                client_mac: cm,
                server_mac: sm,
                client_ip: a.client_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
                server_ip: a.server_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
                proto: proto.to_string(),
                port,
                packets: a.packets,
                bytes: a.bytes,
                reads: a.reads,
                writes: a.writes,
                controls: a.controls,
                note: a.note,
                commands: a.commands,
                window_start: start,
                window_secs: secs,
            })
            .collect();
        (!records.is_empty() || !convs.is_empty()).then_some(FlowBatch { flows: records, convs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: Mac = Mac([0x3c, 0x22, 0xfb, 1, 2, 3]);

    fn sample(out: bool, bytes: u32, port: u16) -> FlowSample {
        FlowSample { mac: M, remote: Ipv4Addr::new(1, 1, 1, 1), proto: 6, port, bytes, outbound: out }
    }

    #[test]
    fn packets_aggregate_per_key_and_direction() {
        let mut a = FlowAgg::new(10, 1000);
        a.add(&sample(true, 100, 443));
        a.add(&sample(true, 50, 443));
        a.add(&sample(false, 1400, 443));
        a.add(&sample(true, 10, 80));
        assert!(a.take_if_due(1005).is_none(), "window still open");
        let mut r = a.take_if_due(1010).unwrap().flows;
        r.sort_by_key(|f| f.port);
        assert_eq!(r.len(), 2);
        assert_eq!((r[1].port, r[1].bytes_out, r[1].bytes_in, r[1].packets), (443, 150, 1400, 3));
        assert_eq!((r[0].window_start, r[0].window_secs), (1000, 10));
    }

    #[test]
    fn windows_are_aligned_and_empty_windows_emit_nothing() {
        let mut a = FlowAgg::new(10, 1003);
        assert_eq!(a.window_start, 1000);
        assert!(a.take_if_due(1010).is_none());
        a.add(&sample(true, 1, 1));
        // a long stall skips forward rather than emitting phantom windows
        let r = a.take_if_due(1500).unwrap().flows;
        assert_eq!(r[0].window_start, 1010);
        assert!(a.take_if_due(1505).is_none());
    }

    fn ot(src: Mac, dst: Mac, server_is_src: bool, class: OtClass, detail: &str) -> OtSample {
        OtSample {
            src_mac: src, dst_mac: dst, src_ip: Ipv4Addr::new(10, 0, 0, 1), dst_ip: Ipv4Addr::new(10, 0, 0, 2), bytes: 60,
            pdu: crate::model::OtPdu { proto: "modbus", server_is_src, class, detail: detail.into(), port: 502, identity: Default::default() },
        }
    }

    #[test]
    fn conversations_are_oriented_client_to_server_and_count_by_class() {
        let (hmi, plc) = (Mac([2, 0, 0, 0, 0, 1]), Mac([2, 0, 0, 0, 0, 2]));
        let mut a = FlowAgg::new(10, 1000);
        a.add_conv(&ot(hmi, plc, false, OtClass::Read, "read holding registers (3)"));
        a.add_conv(&ot(plc, hmi, true, OtClass::Other, "response")); // the reply belongs to the same conversation
        a.add_conv(&ot(hmi, plc, false, OtClass::Write, "write single register (6)"));
        a.add_conv(&ot(hmi, plc, false, OtClass::Control, "PLC stop (0x29)"));
        a.add_conv(&ot(hmi, plc, false, OtClass::Control, "program download (0x1a)"));
        let b = a.take_if_due(1010).unwrap();
        assert!(b.flows.is_empty());
        assert_eq!(b.convs.len(), 1);
        let c = &b.convs[0];
        assert_eq!((c.client_mac, c.server_mac, c.proto.as_str(), c.port), (hmi, plc, "modbus", 502));
        assert_eq!((c.packets, c.reads, c.writes, c.controls), (5, 1, 1, 2));
        assert_eq!(c.note.as_deref(), Some("PLC stop (0x29)"), "first control action is kept as the example");
        assert_eq!((c.client_ip, c.server_ip), (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)));
        // the reverse direction is a different conversation
        a.add_conv(&ot(plc, hmi, false, OtClass::Read, "read"));
        assert_eq!(a.take_if_due(1020).unwrap().convs[0].client_mac, plc);
    }

    #[test]
    fn conversation_explosion_is_capped() {
        let mut a = FlowAgg::new(10, 0);
        for i in 0..(MAX_CONVS as u32 + 50) {
            let m = |n: u32| Mac([2, 0, (n >> 16) as u8, (n >> 8) as u8, n as u8, 0]);
            a.add_conv(&ot(m(i), m(i + 1_000_000), false, OtClass::Read, "r"));
        }
        assert_eq!(a.convs.len(), MAX_CONVS);
        assert_eq!(a.dropped, 50);
    }

    #[test]
    fn key_explosion_is_capped() {
        let mut a = FlowAgg::new(10, 0);
        for p in 0..(MAX_KEYS as u32 + 100) {
            let s = FlowSample { mac: M, remote: Ipv4Addr::from(p), proto: 6, port: 1, bytes: 1, outbound: true };
            a.add(&s);
        }
        assert_eq!(a.map.len(), MAX_KEYS);
        assert_eq!(a.dropped, 100);
        // existing keys still accumulate at the cap
        a.add(&FlowSample { mac: M, remote: Ipv4Addr::from(0u32), proto: 6, port: 1, bytes: 5, outbound: true });
        assert_eq!(a.dropped, 100);
    }
}
