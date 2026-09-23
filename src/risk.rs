//! Per-device risk score: a transparent 0-100 number built from what we know
//! about the device (exposed services, how well it is identified) and what it
//! has recently done (open alerts).
//!
//! Derived on demand, never stored: it always reflects the current rules, and
//! every point comes with a reason so it can be argued with.

use serde::Serialize;

use crate::model::{Asset, Event};

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Risk {
    pub score: i32,
    /// `none`, `low`, `medium`, `high`
    pub level: &'static str,
    pub factors: Vec<String>,
}

pub fn level_for(score: i32) -> &'static str {
    match score {
        s if s >= 60 => "high",
        s if s >= 30 => "medium",
        s if s >= 10 => "low",
        _ => "none",
    }
}

/// Services that are risky merely by being reachable on a LAN device.
/// (port, points, why)
const EXPOSED: &[(u16, i32, &str)] = &[
    (23, 30, "Telnet is open (unencrypted remote login)"),
    (21, 15, "FTP is open (unencrypted file transfer)"),
    (3389, 20, "Remote Desktop (RDP) is open"),
    (5900, 20, "VNC remote screen is open"),
    (445, 10, "SMB file sharing is open"),
    (139, 5, "NetBIOS file sharing is open"),
    (3306, 15, "MySQL is reachable on the network"),
    (1883, 10, "MQTT (unauthenticated by default) is open"),
    (8291, 10, "MikroTik Winbox management is open"),
    (515, 5, "LPD print service is open"),
    (135, 15, "Windows RPC endpoint mapper is open"),
    (111, 10, "rpcbind is open"),
    (161, 10, "SNMP is open (a default or guessable community string can expose or change configuration)"),
    (1433, 15, "Microsoft SQL Server is reachable on the network"),
    (5432, 15, "PostgreSQL is reachable on the network"),
    (6379, 20, "Redis is reachable on the network (no password by default)"),
    (27017, 20, "MongoDB is reachable on the network (no password by default)"),
    (9200, 20, "Elasticsearch is reachable on the network (no password by default)"),
    (11211, 15, "Memcached is open (also abused for DDoS amplification)"),
    (2375, 25, "the Docker API is open without TLS (full control of the host)"),
    (5985, 15, "WinRM is open (remote PowerShell management)"),
    (10000, 15, "Webmin is open"),
    (512, 20, "rexec is open (unencrypted remote execution)"),
    (513, 20, "rlogin is open (unencrypted remote login)"),
    (514, 15, "rsh is open (unencrypted remote shell)"),
    (6667, 15, "IRC is open (a common indicator of a compromised device \"phoning home\")"),
    (6443, 15, "a Kubernetes API server is reachable on the network"),
    (10250, 20, "a Kubernetes kubelet API is reachable on the network"),
    (5672, 15, "RabbitMQ (AMQP) is reachable on the network"),
    (15672, 15, "the RabbitMQ management interface is reachable on the network"),
    (9092, 15, "Kafka is reachable on the network"),
    (1080, 10, "a SOCKS proxy is open"),
];

/// Every fixed phrase a risk factor can consist of (the rest is numbers and a device type), so the
/// translation catalogs can be checked against them.
pub fn texts() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = EXPOSED.iter().map(|(_, _, why)| *why).collect();
    v.extend(["device type could not be identified", "manufacturer not in the IEEE registry", "many open ports"]);
    v
}

/// `alerts` should be the device's *unacknowledged* alerts; acknowledged ones
/// are considered handled and do not count.
pub fn assess(a: &Asset, alerts: &[&Event], now: i64) -> Risk {
    assess_with(a, alerts, now, None)
}

/// Like `assess`, weighting alert impact by the owner-assigned criticality:
/// an alert on a `critical` asset counts 1.5x, on a `low` one 0.6x.
pub fn assess_with(a: &Asset, alerts: &[&Event], now: i64, criticality: Option<&str>) -> Risk {
    let crit = match criticality {
        Some("critical") => 1.5,
        Some("high") => 1.25,
        Some("low") => 0.6,
        _ => 1.0,
    };
    let mut score = 0.0f64;
    let mut factors = Vec::new();
    let mut add = |pts: f64, why: String| {
        score += pts;
        factors.push(format!("+{} {why}", pts.round() as i32));
    };

    let mut exposed = 0;
    for (port, pts, why) in EXPOSED {
        if a.open_ports.iter().any(|p| p.port == *port) && exposed < 40 {
            // File sharing is expected on computers and NAS boxes.
            let expected = matches!(*port, 445 | 139) && matches!(a.device_type.as_str(), "computer" | "nas" | "server");
            if !expected {
                add(*pts as f64, why.to_string());
                exposed += pts;
            }
        }
    }
    if a.device_type == "unknown" {
        add(10.0, "device type could not be identified".into());
    }
    if a.vendor.is_none() && !a.randomized_mac {
        add(5.0, "manufacturer not in the IEEE registry".into());
    }
    if matches!(a.device_type.as_str(), "iot" | "camera") {
        add(10.0, format!("{} devices are commonly left unpatched", a.device_type));
    }
    if a.open_ports.iter().filter(|p| p.proto == "tcp").count() >= 8 {
        add(5.0, "many open ports".into());
    }

    // Open alerts: recent and severe ones weigh most. Noisy kinds (a laptop
    // reaching a new CDN address) are capped low so they cannot make a device
    // "high" on their own; serious kinds (ARP conflicts, traffic spikes, new
    // ports, silence) can.
    let (mut noisy, mut serious) = (0.0f64, 0.0f64);
    let mut n_open = 0;
    for e in alerts.iter().filter(|e| !e.acked && e.severity != "info") {
        n_open += 1;
        let age_days = ((now - e.timestamp).max(0) as f64) / 86_400.0;
        let decay = (1.0 - age_days / 14.0).max(0.0);
        let (weight, bucket) = match e.kind.as_str() {
            "arp_conflict" | "arp_mismatch" => (0.6, &mut serious),
            "ot_control_command" | "ot_internet_exposure" | "threat_list_match" | "rogue_dhcp" => (0.6, &mut serious),
            "ot_purdue_skip" | "ot_unexpected_writer" => (0.4, &mut serious),
            "volume_anomaly" | "new_port" | "device_silent" | "agent_offline" | "ot_new_conversation" => (0.35, &mut serious),
            _ => (0.25, &mut noisy),
        };
        *bucket += e.score as f64 * weight * decay;
    }
    let alert_pts = ((noisy.min(30.0) + serious.min(60.0)) * crit).min(70.0);
    if alert_pts >= 1.0 {
        add(alert_pts, format!("{n_open} unacknowledged alert{} in the last two weeks", if n_open == 1 { "" } else { "s" }));
    }

    let score = (score.round() as i32).clamp(0, 100);
    Risk { score, level: level_for(score), factors }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mac, OpenPort};

    fn asset() -> Asset {
        let mut a = Asset::new(Mac([0x00, 0x1b, 0x63, 1, 2, 3]), 0);
        a.vendor = Some("Acme".into());
        a.device_type = "computer".into();
        a
    }

    fn port(p: u16) -> OpenPort {
        OpenPort { port: p, proto: "tcp".into(), service: None }
    }

    fn alert(kind: &str, score: i32, ts: i64, acked: bool) -> Event {
        Event {
            id: 1, agent_id: None, asset_id: 1, kind: kind.into(), timestamp: ts,
            severity: if score >= 30 { "medium".into() } else { "info".into() },
            score, acked, raw_details: serde_json::json!({}),
        }
    }

    #[test]
    fn a_clean_identified_device_scores_zero() {
        let r = assess(&asset(), &[], 0);
        assert_eq!((r.score, r.level), (0, "none"));
        assert!(r.factors.is_empty());
    }

    #[test]
    fn telnet_on_an_unidentified_iot_gadget_is_high_and_explained() {
        let mut a = asset();
        a.device_type = "iot".into();
        a.open_ports = vec![port(23), port(80)];
        let r = assess(&a, &[], 0);
        assert_eq!(r.score, 40); // telnet 30 + iot 10
        assert_eq!(r.level, "medium");
        assert!(r.factors[0].contains("Telnet"));
        a.device_type = "unknown".into();
        a.vendor = None;
        assert_eq!(assess(&a, &[], 0).score, 30 + 10 + 5);
    }

    #[test]
    fn smb_is_expected_on_a_nas_but_not_on_a_camera() {
        let mut a = asset();
        a.open_ports = vec![port(445)];
        a.device_type = "nas".into();
        assert_eq!(assess(&a, &[], 0).score, 0);
        a.device_type = "camera".into();
        assert_eq!(assess(&a, &[], 0).score, 10 + 10);
    }

    #[test]
    fn open_alerts_count_fade_with_age_and_vanish_when_acknowledged() {
        let a = asset();
        let now = 100 * 86_400;
        let fresh = alert("arp_conflict", 95, now, false);
        let r = assess(&a, &[&fresh], now);
        assert_eq!(r.score, 57); // 95 * 0.6
        assert!(r.factors[0].contains("1 unacknowledged alert"));
        let week_old = alert("arp_conflict", 95, now - 7 * 86_400, false);
        assert!((assess(&a, &[&week_old], now).score - 28).abs() <= 1); // half decayed
        let ancient = alert("arp_conflict", 95, now - 15 * 86_400, false);
        assert_eq!(assess(&a, &[&ancient], now).score, 0);
        let acked = alert("arp_conflict", 95, now, true);
        assert_eq!(assess(&a, &[&acked], now).score, 0);
    }

    #[test]
    fn alert_noise_alone_is_capped_below_high() {
        let a = asset();
        let now = 0;
        let many: Vec<Event> = (0..40).map(|_| alert("new_destination", 50, now, false)).collect();
        let refs: Vec<&Event> = many.iter().collect();
        let r = assess(&a, &refs, now);
        assert_eq!(r.score, 30, "noisy kinds are capped");
        assert_eq!(r.level, "medium");
        // ...but the same volume of serious alerts is not
        let serious: Vec<Event> = (0..40).map(|_| alert("volume_anomaly", 90, now, false)).collect();
        let refs: Vec<&Event> = serious.iter().collect();
        assert_eq!(assess(&a, &refs, now).level, "high");
    }

    #[test]
    fn criticality_scales_the_weight_of_alerts_not_of_static_findings() {
        let mut a = asset();
        a.open_ports = vec![port(23)];
        let e = alert("volume_anomaly", 80, 0, false);
        let base = assess_with(&a, &[&e], 0, None).score; // 30 (telnet) + 28 (80 * .35)
        assert_eq!(base, 58);
        assert_eq!(assess_with(&a, &[&e], 0, Some("critical")).score, 30 + 42);
        assert_eq!(assess_with(&a, &[&e], 0, Some("low")).score, 30 + 17);
        assert_eq!(assess_with(&a, &[&e], 0, Some("normal")).score, base);
        assert_eq!(assess_with(&a, &[], 0, Some("critical")).score, 30, "no alerts: criticality changes nothing");
    }

    #[test]
    fn levels_and_clamping() {
        assert_eq!(level_for(9), "none");
        assert_eq!(level_for(10), "low");
        assert_eq!(level_for(30), "medium");
        assert_eq!(level_for(60), "high");
        let mut a = asset();
        a.device_type = "iot".into();
        a.open_ports = vec![port(23), port(21), port(3389), port(5900), port(3306)];
        assert!(assess(&a, &[&alert("arp_conflict", 100, 0, false)], 0).score <= 100);
    }
}
