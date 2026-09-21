//! Passive capture: libpcap on a dedicated OS thread, feeding `Observation`s to
//! the aggregator over a channel.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use pcap::{Active, Capture, Linktype};
use tokio::sync::mpsc;

use crate::model::{Mac, Observation};
use crate::net::Iface;
use crate::flow::FlowAgg;
use crate::model::now_ts;
use crate::parse::{bpf_filter, parse_frame, Ctx};

/// Flow records are emitted (and, for a remote agent, reported) per window.
pub const FLOW_WINDOW_SECS: u32 = 10;

/// Chatty per-packet observations are forwarded at most this often per (MAC, kind).
const THROTTLE: Duration = Duration::from_secs(5);

/// Open the interface and install the kernel filter. Fails fast, with an
/// actionable hint, when the process lacks capture privileges.
pub fn open(iface: &Iface, flows: bool) -> Result<Capture<Active>> {
    let builder = || {
        Capture::from_device(iface.name.as_str()).map(|c| {
            c.snaplen(1600)
                .timeout(500)
                .immediate_mode(true)
        })
    };
    let first = builder()
        .and_then(|c| c.promisc(true).open());
    let mut cap = match first {
        Ok(c) => c,
        // Some drivers (notably macOS Wi-Fi) refuse promiscuous mode; that is
        // fine because we only need traffic addressed to or broadcast on the LAN.
        Err(e) if !is_permission_error(&e) => builder()
            .and_then(|c| c.promisc(false).open())
            .with_context(|| format!("opening {} for capture ({e})", iface.name))?,
        Err(e) => bail!("cannot open {} for capture: {e}\n{}", iface.name, permission_hint()),
    };
    if cap.get_datalink() != Linktype::ETHERNET {
        bail!(
            "{} is not an Ethernet-framed interface (link type {:?}); pick another with --iface",
            iface.name,
            cap.get_datalink()
        );
    }
    cap.filter(bpf_filter(flows), true)
        .context("installing BPF filter")?;
    Ok(cap)
}

fn is_permission_error(e: &pcap::Error) -> bool {
    let s = e.to_string().to_ascii_lowercase();
    s.contains("permission denied") || s.contains("operation not permitted")
}

pub fn permission_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS: packet capture needs read access to /dev/bpf*. Either run with sudo, or grant your user\n\
         access once via a launchd job that chmods /dev/bpf* (this is what Wireshark's \"ChmodBPF\" does)."
    } else {
        "Linux: packet capture needs CAP_NET_RAW. Run as root, or grant it to the binary once:\n\
         sudo setcap cap_net_raw,cap_net_admin=eip /path/to/denis"
    }
}

/// Handle to the capture thread.
pub struct CaptureThread {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl CaptureThread {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join(); // returns within one read timeout (500 ms)
        }
    }
}

pub fn spawn(
    mut cap: Capture<Active>,
    ctx: Ctx,
    tx: mpsc::Sender<Observation>,
    frames: Arc<AtomicU64>,
) -> CaptureThread {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = stop.clone();
    let handle = std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            let mut last_sent: HashMap<(Mac, u8), Instant> = HashMap::new();
            let mut agg = FlowAgg::new(FLOW_WINDOW_SECS, now_ts());
            while !stop_flag.load(Ordering::Relaxed) {
                if ctx.flows {
                    if let Some(batch) = agg.take_if_due(now_ts()) {
                        if tx.blocking_send(Observation::Flows(batch)).is_err() {
                            return;
                        }
                    }
                }
                let pkt = match cap.next_packet() {
                    Ok(p) => p,
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        tracing::error!("capture stopped: {e}");
                        return;
                    }
                };
                for obs in parse_frame(&ctx, pkt.data) {
                    if let Observation::FlowSample(s) = &obs {
                        agg.add(s);
                        continue;
                    }
                    // Every industrial message feeds the conversation matrix; only a
                    // throttled sample goes on to the inventory (roles, identity).
                    if let Observation::Ot(s) = &obs {
                        agg.add_conv(s);
                    }
                    frames.fetch_add(1, Ordering::Relaxed);
                    if let Some(key) = throttle_key(&obs) {
                        let now = Instant::now();
                        if last_sent.get(&key).is_some_and(|t| now.duration_since(*t) < THROTTLE) {
                            continue;
                        }
                        last_sent.insert(key, now);
                        if last_sent.len() > 20_000 {
                            last_sent.retain(|_, t| now.duration_since(*t) < THROTTLE);
                        }
                    }
                    if tx.blocking_send(obs).is_err() {
                        return; // aggregator is gone: shutting down
                    }
                }
            }
        })
        .expect("spawn capture thread");
    CaptureThread {
        stop,
        handle: Some(handle),
    }
}

/// Small stable code per protocol name, so throttling is per (device, protocol).
fn proto_code(name: &str) -> u8 {
    name.bytes().fold(0u8, |a, b| a.wrapping_mul(31).wrapping_add(b)) % 100
}

/// Only high-rate, low-information observations are throttled. DHCP/mDNS/SSDP
/// carry distinct content per packet and are rare, so they always pass.
fn throttle_key(obs: &Observation) -> Option<(Mac, u8)> {
    match obs {
        Observation::Arp { mac, .. } => Some((*mac, 0)),
        Observation::Tcp { mac, .. } => Some((*mac, 1)),
        Observation::Ttl { mac, .. } => Some((*mac, 2)),
        // DHCP-server sightings get their own slot so they never hide an ARP signal from the same device
        Observation::Signal(sig) => Some((sig.mac, if sig.kind == "dhcp_server" { 5 } else { 3 })),
        // Roles and identity change rarely: once per 5 s per (device, protocol) is plenty.
        Observation::Ot(s) => Some((s.src_mac, 100 + proto_code(s.pdu.proto))),
        Observation::Link(l) => Some((l.mac, 4)),
        _ => None,
    }
}
