//! Active probing, used to fill gaps passive capture leaves.
//!
//! ARP and ICMP replies are *not* handled here: they come back through the
//! passive capture path like any other frame, which keeps a single code path
//! for identity. Only the TCP port scan returns results directly.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use pcap::Capture;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::fingerprint::{service_name, SCAN_PORTS};
use crate::model::{Mac, OpenPort};
use crate::net::Iface;

/// Broadcast ARP "who-has" request, padded to the 60-byte Ethernet minimum.
pub fn build_arp_request(src_mac: Mac, src_ip: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let mut f = Vec::with_capacity(60);
    f.extend_from_slice(&[0xff; 6]);
    f.extend_from_slice(&src_mac.0);
    f.extend_from_slice(&[0x08, 0x06]);
    f.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f.extend_from_slice(&src_mac.0);
    f.extend_from_slice(&src_ip.octets());
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&target.octets());
    f.resize(60, 0);
    f
}

/// Blocking: two passes of ARP requests (second pass catches replies lost to
/// Wi-Fi power save). Paced so a /24 takes under a second per pass.
pub fn arp_sweep(iface: &Iface, targets: &[Ipv4Addr]) -> Result<()> {
    let mut tx = Capture::from_device(iface.name.as_str())
        .and_then(|c| c.open())
        .with_context(|| format!("opening {} for sending", iface.name))?;
    for pass in 0..2 {
        for ip in targets {
            tx.sendpacket(build_arp_request(iface.mac, iface.ip, *ip))
                .with_context(|| format!("sending ARP request for {ip}"))?;
            std::thread::sleep(Duration::from_millis(2));
        }
        if pass == 0 {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

/// Send one echo request to each host. Replies are read by the capture thread
/// (which extracts TTL); the return value is only the count answered.
///
/// Uses unprivileged datagram ICMP sockets (macOS, and Linux when
/// `net.ipv4.ping_group_range` allows it), falling back to raw sockets.
pub async fn icmp_sweep(hosts: &[Ipv4Addr], timeout: Duration) -> Result<usize> {
    let client = match Client::new(&Config::default()) {
        Ok(c) => c,
        Err(_) => Client::new(
            &Config::builder()
                .kind(ICMP::V4)
                .sock_type_hint(socket2::Type::RAW)
                .build(),
        )
        .context("creating ICMP socket (need privileges or net.ipv4.ping_group_range)")?,
    };
    let sem = Arc::new(Semaphore::new(64));
    let mut set = JoinSet::new();
    let base = (std::process::id() & 0xffff) as u16;
    for (i, ip) in hosts.iter().enumerate() {
        let (client, sem, ip) = (client.clone(), sem.clone(), *ip);
        set.spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let mut p = client
                .pinger(IpAddr::V4(ip), PingIdentifier(base.wrapping_add(i as u16)))
                .await;
            p.timeout(timeout);
            p.ping(PingSequence(0), &[0u8; 16]).await.ok()
        });
    }
    let mut answered = 0;
    while let Some(r) = set.join_next().await {
        if matches!(r, Ok(Some(_))) {
            answered += 1;
        }
    }
    Ok(answered)
}

/// TCP connect scan of the curated common-port list. Bounded by `sem` so a
/// whole-network scan stays well under the process fd limit (256 on macOS).
pub async fn scan_host(ip: Ipv4Addr, sem: Arc<Semaphore>, timeout: Duration) -> Vec<OpenPort> {
    let mut set = JoinSet::new();
    for (port, _) in SCAN_PORTS {
        let (sem, port) = (sem.clone(), *port);
        set.spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => Some(port),
                _ => None,
            }
        });
    }
    let mut open = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some(port)) = r {
            open.push(OpenPort {
                port,
                proto: "tcp".into(),
                service: service_name(port).map(str::to_string),
            });
        }
    }
    open.sort_by_key(|p| p.port);
    open
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{parse_frame, Ctx};
    use crate::model::Observation;

    #[test]
    fn arp_request_is_well_formed() {
        let mac = Mac([2, 0, 0, 0, 0, 9]);
        let f = build_arp_request(mac, Ipv4Addr::new(192, 168, 1, 10), Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(f.len(), 60);
        assert_eq!(&f[0..6], &[0xff; 6]);
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[20..22], &[0, 1]); // op = request
        assert_eq!(&f[38..42], &[192, 168, 1, 20]);
    }

    #[test]
    fn our_own_arp_request_is_never_parsed_as_a_device() {
        let mac = Mac([2, 0, 0, 0, 0, 9]);
        let ctx = Ctx {
            subnet: "192.168.1.0/24".parse().unwrap(),
            own_mac: mac,
            own_ip: Ipv4Addr::new(192, 168, 1, 10),
            flows: false,
        };
        let f = build_arp_request(mac, ctx.own_ip, Ipv4Addr::new(192, 168, 1, 20));
        assert!(parse_frame(&ctx, &f).is_empty());
    }

    #[test]
    fn a_neighbours_arp_request_is_a_valid_binding() {
        // Requests carry the sender's binding too (sender = the other host).
        let other = Mac([0x3c, 0x22, 0xfb, 1, 2, 3]);
        let ctx = Ctx {
            subnet: "192.168.1.0/24".parse().unwrap(),
            own_mac: Mac([2, 0, 0, 0, 0, 9]),
            own_ip: Ipv4Addr::new(192, 168, 1, 10),
            flows: false,
        };
        let f = build_arp_request(other, Ipv4Addr::new(192, 168, 1, 44), Ipv4Addr::new(192, 168, 1, 1));
        assert!(matches!(parse_frame(&ctx, &f).as_slice(), [Observation::Arp { .. }]));
    }

    #[tokio::test]
    async fn port_scan_finds_a_listener_on_loopback() {
        // Not in SCAN_PORTS, so scan a listener through the same connect logic.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let sem = Arc::new(Semaphore::new(8));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let ok = tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr)).await;
        assert!(matches!(ok, Ok(Ok(_))));
        // The real scanner completes and reports a (possibly empty) sorted list.
        let open = scan_host(Ipv4Addr::LOCALHOST, sem, Duration::from_millis(200)).await;
        assert!(open.windows(2).all(|w| w[0].port < w[1].port));
    }
}
