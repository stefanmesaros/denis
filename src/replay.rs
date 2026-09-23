//! Replay a packet capture through the same decoding, inventory and detection code the live collector uses, and say
//! what it found. For trying DENIS on someone else's capture (a public industrial-protocol sample, a file a colleague
//! sends) without a network: `denis replay capture.pcap`. Nothing is written anywhere.
//!
//! The capture must be Ethernet (link type 1). Every address is treated as local unless `--subnet` narrows it, because
//! industrial captures are usually taken inside one network and the decoders only look at traffic between local devices.

use std::path::Path;

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;

use crate::detect::{DetectConfig, Detector};
use crate::flow::FlowAgg;
use crate::inventory::Inventory;
use crate::model::{Asset, Conversation, Event, Mac, Observation};
use crate::parse::{parse_frame, Ctx};
use crate::store::sqlite::SqliteStore;
use crate::store::AssetStore;

#[derive(Debug)]
pub struct Replay {
    pub packets: usize,
    pub seconds: i64,
    /// Packets that were IPv4 between local devices and carried a decoded industrial message.
    pub decoded: usize,
    pub assets: Vec<Asset>,
    pub conversations: Vec<Conversation>,
    pub events: Vec<Event>,
}

pub fn run(path: &Path, subnet: Option<Ipv4Net>, learning_secs: i64) -> Result<Replay> {
    let mut cap = pcap::Capture::from_file(path).with_context(|| format!("opening {}", path.display()))?;
    if cap.get_datalink() != pcap::Linktype::ETHERNET {
        bail!("only Ethernet captures can be replayed (this one is link type {})", cap.get_datalink().0);
    }
    let ctx = Ctx { subnets: vec![subnet.unwrap_or_else(|| "0.0.0.0/0".parse().expect("literal"))], own_mac: Mac([0; 6]), own_ip: std::net::Ipv4Addr::UNSPECIFIED, flows: true, ot: true };
    let mut inv = Inventory::new(vec![], None, None);
    let mut agg: Option<FlowAgg> = None;
    let mut batches = Vec::new();
    let (mut packets, mut decoded) = (0usize, 0usize);
    let (mut first, mut last) = (0i64, 0i64);
    while let Ok(p) = cap.next_packet() {
        #[allow(clippy::unnecessary_cast)] // (the width of tv_sec differs between platforms)
        let ts = p.header.ts.tv_sec as i64;
        if packets == 0 {
            first = ts;
            agg = Some(FlowAgg::new(10, ts));
        }
        packets += 1;
        last = ts;
        let agg = agg.as_mut().expect("set with the first packet");
        for obs in parse_frame(&ctx, p.data) {
            match &obs {
                Observation::Ot(s) => {
                    decoded += 1;
                    agg.add_conv(s);
                }
                Observation::FlowSample(s) => agg.add(s),
                _ => {}
            }
            if !matches!(obs, Observation::FlowSample(_) | Observation::Flows(_)) {
                inv.apply(obs, ts);
            }
        }
        if let Some(b) = agg.take_if_due(ts) {
            batches.push(b);
        }
    }
    if let Some(mut agg) = agg {
        if let Some(b) = agg.take_if_due(last + 20) {
            batches.push(b);
        }
    }
    let store = SqliteStore::open_in_memory()?;
    inv.flush(&store)?;
    let cfg = DetectConfig { learning_secs, ..DetectConfig::default() };
    let mut det = Detector::new(cfg, vec![], first);
    let mut events = Vec::new();
    for b in &batches {
        events.extend(det.ingest_conversations(None, &b.convs, &store, b.convs.first().map_or(last, |c| c.window_start) + 1));
    }
    det.flush(&store)?;
    Ok(Replay { packets, seconds: last - first, decoded, assets: store.load_assets()?, conversations: store.list_conversations()?, events })
}

impl Replay {
    pub fn render(&self) -> String {
        let name = |id: i64| self.assets.iter().find(|a| a.id == id).map(|a| a.current_ip().map_or_else(|| a.mac.to_string(), |i| i.to_string())).unwrap_or_else(|| format!("#{id}"));
        let mut s = format!("{} packets over {} s; {} carried a decoded industrial message\n\nDevices ({}):\n", self.packets, self.seconds, self.decoded, self.assets.len());
        for a in &self.assets {
            let roles: Vec<String> = a.fingerprint.ot.iter().map(|(p, r)| format!("{p}:{}", if r.server && r.client { "server+client" } else if r.server { "server" } else { "client" })).collect();
            s.push_str(&format!("  {:<16} {:<19} {:<22} {}\n", a.current_ip().map_or("?".into(), |i| i.to_string()), a.mac, a.device_type, roles.join(" ")));
        }
        s.push_str(&format!("\nConversations ({}):\n", self.conversations.len()));
        for c in &self.conversations {
            let cmds: Vec<String> = c.commands.iter().map(|(k, n)| format!("{k} x{n}")).collect();
            s.push_str(&format!("  {} -> {} {}/{}  packets {}  reads {} writes {} controls {}{}\n", name(c.client_id), name(c.server_id), c.proto, c.port, c.packets, c.reads, c.writes, c.controls, if cmds.is_empty() { String::new() } else { format!("\n      {}", cmds.join("; ")) }));
        }
        s.push_str(&format!("\nAlerts ({}):\n", self.events.iter().filter(|e| e.severity != "info").count()));
        for e in self.events.iter().filter(|e| e.severity != "info") {
            s.push_str(&format!("  [{} {}] {}: {}\n", e.severity, e.score, e.kind, e.raw_details["summary"].as_str().unwrap_or("")));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(smac: [u8; 6], dmac: [u8; 6], sip: [u8; 4], dip: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend(sport.to_be_bytes());
        tcp.extend(dport.to_be_bytes());
        tcp.extend([0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend(payload);
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0];
        ip.extend(sip);
        ip.extend(dip);
        let total = (ip.len() + tcp.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        let mut f = dmac.to_vec();
        f.extend(smac);
        f.extend([8, 0]);
        f.extend(ip);
        f.extend(tcp);
        f
    }

    fn pcap(path: &Path, frames: &[(u32, Vec<u8>)]) {
        let mut b = Vec::new();
        b.extend(0xa1b2c3d4u32.to_le_bytes());
        b.extend([2, 0, 4, 0]);
        b.extend([0u8; 8]);
        b.extend(65535u32.to_le_bytes());
        b.extend(1u32.to_le_bytes());
        for (ts, f) in frames {
            b.extend(ts.to_le_bytes());
            b.extend(0u32.to_le_bytes());
            b.extend((f.len() as u32).to_le_bytes());
            b.extend((f.len() as u32).to_le_bytes());
            b.extend(f);
        }
        std::fs::write(path, b).unwrap();
    }

    #[test]
    fn a_capture_is_decoded_into_devices_conversations_and_alerts_and_a_non_ethernet_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (hmi, plc) = ([0x3c, 0x22, 0xfb, 1, 1, 1], [0x00, 0x1b, 0x1b, 2, 2, 2]);
        let read = [0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 10];
        let stop = [0, 2, 0, 0, 0, 6, 1, 8, 0, 4, 0, 0]; // Modbus diagnostics: force listen-only mode
        let frames = vec![
            (100, frame(hmi, plc, [10, 0, 0, 1], [10, 0, 0, 2], 50_000, 502, &read)),
            (101, frame(plc, hmi, [10, 0, 0, 2], [10, 0, 0, 1], 502, 50_000, &[0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 5])),
            (150, frame(hmi, plc, [10, 0, 0, 1], [10, 0, 0, 2], 50_000, 502, &stop)),
        ];
        let path = dir.path().join("t.pcap");
        pcap(&path, &frames);
        let r = run(&path, Some("10.0.0.0/24".parse().unwrap()), 0).unwrap();
        assert_eq!((r.packets, r.decoded, r.seconds), (3, 3, 50));
        assert_eq!(r.assets.len(), 2);
        assert_eq!(r.conversations.len(), 1);
        let c = &r.conversations[0];
        assert_eq!((c.proto.as_str(), c.port, c.reads, c.controls), ("modbus", 502, 1, 1));
        assert!(r.events.iter().any(|e| e.kind == "ot_control_command"), "{:?}", r.events);
        let text = r.render();
        assert!(text.contains("10.0.0.1 -> 10.0.0.2 modbus/502") && text.contains("Alerts (") && text.contains("plc"), "{text}");
        // addresses outside the chosen network are not local devices, so nothing is decoded
        assert_eq!(run(&path, Some("192.168.0.0/24".parse().unwrap()), 0).unwrap().decoded, 0);
        // not an Ethernet capture: refused with a clear reason; not a capture at all: an error, not a panic
        let mut raw = std::fs::read(&path).unwrap();
        raw[20..24].copy_from_slice(&101u32.to_le_bytes());
        std::fs::write(dir.path().join("raw.pcap"), &raw).unwrap();
        assert!(run(&dir.path().join("raw.pcap"), None, 0).unwrap_err().to_string().contains("Ethernet"));
        std::fs::write(dir.path().join("junk.pcap"), b"not a pcap").unwrap();
        assert!(run(&dir.path().join("junk.pcap"), None, 0).is_err());
        assert!(run(&dir.path().join("missing.pcap"), None, 0).is_err());
    }
}
