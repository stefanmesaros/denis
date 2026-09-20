//! Capture-side flow aggregation: per-packet `FlowSample`s -> per-window
//! `FlowRecord`s, so only a small summary crosses threads (and, for a remote
//! agent, the network).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::model::{FlowRecord, FlowSample, Mac};

/// Upper bound on distinct (device, remote, proto, port) keys per window; a
/// port scan or P2P swarm must not be able to exhaust memory.
pub const MAX_KEYS: usize = 50_000;

type Key = (Mac, Ipv4Addr, u8, u16);

pub struct FlowAgg {
    window_secs: i64,
    window_start: i64,
    map: HashMap<Key, (u64, u64, u64)>,
    pub dropped: u64,
}

impl FlowAgg {
    pub fn new(window_secs: u32, now: i64) -> Self {
        let w = window_secs.max(1) as i64;
        FlowAgg {
            window_secs: w,
            window_start: now / w * w,
            map: HashMap::new(),
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

    /// Close the window once `now` has left it. Returns its records (possibly
    /// none) and starts the window containing `now`.
    pub fn take_if_due(&mut self, now: i64) -> Option<Vec<FlowRecord>> {
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
        (!records.is_empty()).then_some(records)
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
        let mut r = a.take_if_due(1010).unwrap();
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
        let r = a.take_if_due(1500).unwrap();
        assert_eq!(r[0].window_start, 1010);
        assert!(a.take_if_due(1505).is_none());
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
