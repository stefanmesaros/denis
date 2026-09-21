//! End-to-end replay of an industrial network through the real pipeline:
//! raw Ethernet frames -> parser -> capture-side aggregation -> inventory ->
//! database -> detector -> alerts. No network interface is needed.
//!
//! The scenario: an HMI polls a Siemens PLC over S7 during the learning
//! period; afterwards a *new* laptop connects to the PLC, downloads a program
//! and sends STOP; a Modbus device is queried; a PLC talks Modbus to the
//! Internet; a switch announces itself over LLDP.

use std::net::Ipv4Addr;

use denis::detect::{DetectConfig, Detector, RULE_OT_CONTROL, RULE_OT_EXPOSURE, RULE_OT_NEW_CONV};
use denis::flow::FlowAgg;
use denis::inventory::Inventory;
use denis::model::{Mac, Observation};
use denis::parse::{parse_frame, Ctx};
use denis::store::sqlite::SqliteStore;
use denis::store::Store;

const OWN: Mac = Mac([0x02, 0, 0, 0, 0, 0x99]);
const HMI: [u8; 6] = [0x3c, 0x22, 0xfb, 0, 0, 0x01];
const LAPTOP: [u8; 6] = [0x3c, 0x22, 0xfb, 0, 0, 0x02];
const PLC1: [u8; 6] = [0x00, 0x1b, 0x1b, 0, 0, 0x11];
const PLC2: [u8; 6] = [0x00, 0x1b, 0x1b, 0, 0, 0x12];
const SWITCH: [u8; 6] = [0x00, 0x1b, 0x63, 0, 0, 0x50];

fn ip_of(mac: [u8; 6]) -> [u8; 4] {
    [10, 0, 0, mac[5]]
}

fn ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = [&dst[..], &src[..], &ethertype.to_be_bytes()].concat();
    f.extend_from_slice(payload);
    f
}

fn tcp_frame(src: [u8; 6], dst: [u8; 6], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x18; // PSH|ACK: data
    tcp.extend_from_slice(payload);
    ip_frame(src, dst, ip_of(dst), 6, &tcp)
}

fn ip_frame(src: [u8; 6], dst_mac: [u8; 6], dst_ip: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
    ip.extend_from_slice(&ip_of(src));
    ip.extend_from_slice(&dst_ip);
    ip.extend_from_slice(l4);
    let n = ip.len() as u16;
    ip[2..4].copy_from_slice(&n.to_be_bytes());
    ethernet(dst_mac, src, 0x0800, &ip)
}

fn s7_job(func: u8) -> Vec<u8> {
    let mut v = vec![3, 0, 0, 0, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 1, 0, 0, func, 0];
    let n = v.len() as u16;
    v[2..4].copy_from_slice(&n.to_be_bytes());
    v
}

fn modbus(fc: u8) -> Vec<u8> {
    vec![0, 1, 0, 0, 0, 6, 1, fc, 0, 0, 0, 1]
}

/// The whole pipeline in miniature.
struct Rig {
    ctx: Ctx,
    inv: Inventory,
    agg: FlowAgg,
    /// Windows the capture loop has already closed.
    closed: Vec<denis::model::FlowBatch>,
    store: SqliteStore,
    det: Detector,
    now: i64,
}

impl Rig {
    fn new() -> Rig {
        let cfg = DetectConfig { learning_secs: 1000, ..Default::default() };
        Rig {
            ctx: Ctx { subnet: "10.0.0.0/24".parse().unwrap(), own_mac: OWN, own_ip: Ipv4Addr::new(10, 0, 0, 200), flows: true, ot: true },
            inv: Inventory::new(vec![], None, None),
            agg: FlowAgg::new(10, 0),
            closed: Vec::new(),
            store: SqliteStore::open_in_memory().unwrap(),
            det: Detector::new(cfg, vec![], 0),
            now: 0,
        }
    }

    /// Feed frames as the capture thread would: conversation/flow samples go to
    /// the aggregator, everything else to the inventory.
    fn wire(&mut self, frames: &[Vec<u8>]) {
        // The real capture loop closes due windows on every iteration, which is
        // what keeps a window's start time close to the traffic it holds.
        if let Some(b) = self.agg.take_if_due(self.now) {
            self.closed.push(b);
        }
        for f in frames {
            for obs in parse_frame(&self.ctx, f) {
                match &obs {
                    Observation::FlowSample(s) => self.agg.add(s),
                    Observation::Ot(s) => {
                        self.agg.add_conv(s);
                        self.inv.apply(obs.clone(), self.now);
                    }
                    _ => self.inv.apply(obs, self.now),
                }
            }
        }
    }

    /// Close the aggregation window and run the flush + detector, like the engine.
    fn tick(&mut self, at: i64) -> Vec<denis::model::Event> {
        self.now = at;
        self.inv.flush(&self.store).unwrap();
        let mut events = Vec::new();
        self.closed.extend(self.agg.take_if_due(at + 10));
        for b in self.closed.drain(..) {
            events.extend(self.det.ingest_flows(None, &b.flows, &self.store, at));
            events.extend(self.det.ingest_conversations(None, &b.convs, &self.store, at));
        }
        events
    }
}

#[test]
fn an_industrial_network_replayed_through_the_whole_pipeline() {
    let mut rig = Rig::new();
    // Make the PLCs recognisable as industrial by vendor (as the OUI lookup would).
    // (Roles learned from the wire do the same, but the vendor makes it independent of timing.)

    // ---- learning period: the HMI polls PLC1 over S7 (with the PLC answering) and reads PLC2 over Modbus
    rig.now = 10;
    rig.wire(&[
        tcp_frame(HMI, PLC1, 50_000, 102, &s7_job(0x04)),
        tcp_frame(PLC1, HMI, 102, 50_000, &s7_job(0x04)[..15]),
        tcp_frame(HMI, PLC2, 50_001, 502, &modbus(3)),
    ]);
    // a switch announces itself (LLDP: chassis id + system name + bridge capability)
    let mut lldp = vec![0x02, 0x07, 4, 0x00, 0x1b, 0x63, 0, 0, 0x50, 0x0a, 0x0b];
    lldp.extend(b"cell-sw-01\0"[..10].iter());
    lldp.extend([0x0e, 0x04, 0x00, 0x04, 0x00, 0x04, 0, 0]);
    rig.wire(&[ethernet([0x01, 0x80, 0xc2, 0, 0, 0x0e], SWITCH, 0x88cc, &lldp)]);
    let ev = rig.tick(20);
    assert!(ev.is_empty(), "everything seen while learning is silent: {ev:?}");

    // discovery results
    let plc1 = rig.store.find_asset(None, &Mac(PLC1)).unwrap().unwrap();
    assert!(plc1.fingerprint.ot["s7"].server, "PLC1 was seen answering S7");
    assert_eq!(plc1.device_type, "plc", "typed from the protocol role");
    let hmi = rig.store.find_asset(None, &Mac(HMI)).unwrap().unwrap();
    assert!(hmi.fingerprint.ot["s7"].client && hmi.fingerprint.ot["modbus"].client);
    assert_eq!(hmi.device_type, "hmi");
    let sw = rig.store.find_asset(None, &Mac(SWITCH)).unwrap().unwrap();
    assert_eq!(sw.hostnames, ["cell-sw-01"]);
    assert_eq!(sw.fingerprint.identity["lldp.system_name"], "cell-sw-01");

    // ---- after learning: the same HMI polls again (routine), a NEW laptop attacks the PLC
    rig.now = 3000;
    rig.wire(&[
        tcp_frame(HMI, PLC1, 50_000, 102, &s7_job(0x04)),
        tcp_frame(LAPTOP, PLC1, 51_000, 102, &s7_job(0x1a)), // program download
        tcp_frame(LAPTOP, PLC1, 51_000, 102, &s7_job(0x29)), // PLC stop
        tcp_frame(LAPTOP, PLC2, 51_001, 502, &modbus(16)),   // Modbus write
    ]);
    // ...and a PLC talks Modbus to the Internet
    rig.wire(&[tcp_frame(PLC1, [0, 0, 0, 0, 0, 0], 50_002, 502, &modbus(3))
        .iter().enumerate().map(|(i, b)| if (30..34).contains(&i) { [203u8, 0, 113, 9][i - 30] } else { *b }).collect()]);
    // the laptop must be a *stored* asset for the detector to see it; the flush in tick() does that
    let ev = rig.tick(3010);
    let by_kind = |k: &str| ev.iter().filter(|e| e.kind == k).collect::<Vec<_>>();

    // the routine HMI->PLC1 path raises nothing; the laptop's paths are new
    let new_paths = by_kind(RULE_OT_NEW_CONV);
    assert_eq!(new_paths.len(), 2, "laptop->PLC1 (s7) and laptop->PLC2 (modbus): {ev:#?}");
    assert!(new_paths.iter().all(|e| e.raw_details["client"]["mac"] == "3c:22:fb:00:00:02"));
    // the download+stop is a first-time control action: high
    let control = by_kind(RULE_OT_CONTROL);
    assert_eq!(control.len(), 1);
    assert_eq!((control[0].severity.as_str(), control[0].raw_details["protocol"].as_str()), ("high", Some("s7")));
    assert!(control[0].raw_details["summary"].as_str().unwrap().contains("program download"), "{}", control[0].raw_details["summary"]);
    // the write path is scored above a plain read path
    let write_path = new_paths.iter().find(|e| e.raw_details["protocol"] == "modbus").unwrap();
    assert!(write_path.raw_details["writes"].as_i64() == Some(1) && write_path.score >= 70, "{}", write_path.score);
    // Modbus towards the Internet is flagged by port alone
    let exposure = by_kind(RULE_OT_EXPOSURE);
    assert_eq!(exposure.len(), 1, "{ev:#?}");
    assert_eq!(exposure[0].raw_details["remote"], "203.0.113.9");

    // ---- persistence: flush the matrix and reload it in a fresh detector
    rig.det.flush(&rig.store).unwrap();
    let saved = rig.store.list_conversations().unwrap();
    assert_eq!(saved.len(), 4, "hmi->plc1, hmi->plc2, laptop->plc1, laptop->plc2");
    let stop_path = saved.iter().find(|c| c.controls > 0).unwrap();
    assert_eq!((stop_path.proto.as_str(), stop_path.controls, stop_path.note.as_deref()), ("s7", 2, Some("program download (0x1a)")));
}
