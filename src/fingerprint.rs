//! Device-type / OS guessing from collected evidence.
//!
//! Deliberately rule-based and explainable: every rule that fires contributes a
//! weighted vote and a human-readable reason, so a wrong guess can be traced
//! and tuned rather than argued with.

use std::collections::HashMap;

use crate::model::{Asset, Mac, TcpSig};

/// IEEE OUI vendor for a MAC. Randomised (locally administered) addresses have
/// no vendor by definition.
pub fn vendor_for(mac: &Mac) -> Option<String> {
    if mac.is_locally_administered() {
        return None;
    }
    oui_data::lookup(&mac.to_string()).map(|r| short_vendor(r.organization()))
}

/// "Apple, Inc." / "TP-LINK TECHNOLOGIES CO.,LTD." -> shorter display names.
fn short_vendor(org: &str) -> String {
    let mut s = org.trim().to_string();
    for suffix in [
        ", Inc.", " Inc.", " Inc", " CO.,LTD.", " CO., LTD.", " CO.,LTD", " Co., Ltd.", " Co.,Ltd.",
        " Company Limited", " Company, Limited", " Corporation", " CORPORATION", " LIMITED", " Limited", " LTD.", " Ltd.", " GmbH", " S.A.",
        " Technologies", " TECHNOLOGIES",
    ] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped.trim_end_matches(',').trim().to_string();
        }
    }
    s
}

/// Initial-TTL family from an observed TTL (packets lose one per hop).
pub fn initial_ttl(observed: u8) -> u8 {
    match observed {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

/// OS family from a TCP SYN/SYN-ACK signature: option *order* is the most
/// stable discriminator, TTL breaks ties.
pub fn os_from_tcp(sig: &TcpSig) -> Option<(&'static str, i32)> {
    let ttl = initial_ttl(sig.ttl);
    match (sig.options.as_str(), ttl) {
        ("MNWNNTSE", 64) => Some(("Apple (macOS/iOS)", 4)),
        ("MNWNNS", 128) => Some(("Windows", 4)),
        ("MSTNW", 64) => Some(("Linux", 4)),
        (_, 128) => Some(("Windows", 2)),
        (_, 255) => Some(("Embedded firmware (lwIP/RTOS)", 2)),
        (_, 64) => Some(("Unix-like", 1)),
        _ => None,
    }
}

pub struct Guess {
    pub device_type: String,
    pub os: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Default)]
struct Votes {
    types: HashMap<&'static str, i32>,
    os: HashMap<&'static str, i32>,
    reasons: Vec<String>,
}

impl Votes {
    fn ty(&mut self, t: &'static str, w: i32, why: impl Into<String>) {
        *self.types.entry(t).or_default() += w;
        self.reasons.push(format!("{t} +{w}: {}", why.into()));
    }
    fn os(&mut self, o: &'static str, w: i32, why: impl Into<String>) {
        *self.os.entry(o).or_default() += w;
        self.reasons.push(format!("os {o} +{w}: {}", why.into()));
    }
    fn both(&mut self, t: &'static str, o: &'static str, w: i32, why: impl Into<String> + Clone) {
        self.ty(t, w, why.clone());
        self.os(o, w, why);
    }
}

fn winner(map: &HashMap<&'static str, i32>) -> Option<&'static str> {
    // Ties broken alphabetically so results are deterministic.
    map.iter()
        .filter(|(_, w)| **w >= 2)
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(k, _)| *k)
}

pub fn guess(a: &Asset) -> Guess {
    let mut v = Votes::default();
    let fp = &a.fingerprint;

    if a.is_gateway {
        v.ty("router", 6, "default gateway");
    }

    // --- DHCP
    if let Some(vc) = &fp.dhcp_vendor_class {
        let l = vc.to_ascii_lowercase();
        if l.starts_with("msft") {
            v.both("computer", "Windows", 5, format!("DHCP vendor class {vc:?}"));
        } else if l.starts_with("android-dhcp") {
            v.both("phone", "Android", 5, format!("DHCP vendor class {vc:?}"));
        } else if l.starts_with("dhcpcd") || l.starts_with("udhcp") {
            v.os("Linux", 3, format!("DHCP vendor class {vc:?}"));
        }
    }

    // --- hostnames (DHCP option 12 and mDNS)
    for h in a.hostnames.iter().chain(fp.mdns_names.iter()) {
        let l = h.to_ascii_lowercase();
        if l.contains("iphone") {
            v.both("phone", "iOS", 5, format!("name {h:?}"));
        } else if l.contains("ipad") {
            v.both("tablet", "iPadOS", 5, format!("name {h:?}"));
        } else if l.contains("macbook") || l.contains("imac") || l.contains("mac-mini") || l.contains("macmini") || l.contains("mac-studio") {
            v.both("computer", "macOS", 5, format!("name {h:?}"));
        } else if l.starts_with("desktop-") || l.starts_with("laptop-") || l.starts_with("win-") {
            v.both("computer", "Windows", 4, format!("default Windows name {h:?}"));
        } else if l.starts_with("android-") || l.contains("galaxy") || l.contains("pixel") {
            v.both("phone", "Android", 4, format!("name {h:?}"));
        } else if l.contains("raspberrypi") {
            v.both("computer", "Linux", 5, format!("name {h:?}"));
        } else if l.contains("appletv") || l.contains("apple-tv") {
            v.ty("media device", 5, format!("name {h:?}"));
        } else if l.starts_with("esp") && l.len() <= 12 {
            v.ty("iot", 3, format!("name {h:?}"));
        }
    }

    // --- mDNS service types and models
    for s in &fp.mdns_services {
        match s.as_str() {
            "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" | "_scanner._tcp" => {
                v.ty("printer", 5, format!("mDNS {s}"))
            }
            "_googlecast._tcp" => v.ty("media device", 4, "mDNS _googlecast._tcp"),
            "_airplay._tcp" | "_raop._tcp" => v.os("Apple", 2, format!("mDNS {s}")),
            "_companion-link._tcp" | "_rdlink._tcp" | "_sleep-proxy._udp" => v.os("Apple", 3, format!("mDNS {s}")),
            "_apple-mobdev2._tcp" => v.both("phone", "iOS", 2, "mDNS _apple-mobdev2._tcp"),
            "_hap._tcp" | "_homekit._tcp" | "_matter._tcp" | "_meshcop._udp" => v.ty("iot", 3, format!("mDNS {s}")),
            "_spotify-connect._tcp" => v.ty("smart speaker", 2, "mDNS _spotify-connect._tcp"),
            "_smb._tcp" | "_afpovertcp._tcp" => v.ty("computer", 1, format!("mDNS {s}")),
            "_workstation._tcp" => v.both("computer", "Linux", 2, "mDNS _workstation._tcp (avahi)"),
            "_ssh._tcp" | "_sftp-ssh._tcp" => v.os("Unix-like", 1, format!("mDNS {s}")),
            "_nvstream._tcp" | "_amzn-wplay._tcp" => v.ty("media device", 3, format!("mDNS {s}")),
            _ => {}
        }
    }
    for m in &fp.mdns_models {
        let l = m.to_ascii_lowercase();
        if l.starts_with("macbook") || l.starts_with("imac") || l.starts_with("macmini") || l.starts_with("macpro") || l.starts_with("mac1") {
            v.both("computer", "macOS", 5, format!("model {m:?}"));
        } else if l.starts_with("appletv") {
            v.ty("media device", 5, format!("model {m:?}"));
        } else if l.starts_with("audioaccessory") {
            v.ty("smart speaker", 5, format!("model {m:?}"));
        } else if l.starts_with("iphone") {
            v.both("phone", "iOS", 5, format!("model {m:?}"));
        } else if l.starts_with("ipad") {
            v.both("tablet", "iPadOS", 5, format!("model {m:?}"));
        }
    }

    // --- SSDP
    if let Some(s) = &fp.ssdp_server {
        let l = s.to_ascii_lowercase();
        if l.contains("miniupnpd") || l.contains("igd") {
            v.ty("router", 3, format!("SSDP server {s:?}"));
        }
        if l.contains("microsoft-windows") || l.contains("windows/") {
            v.both("computer", "Windows", 4, format!("SSDP agent {s:?}"));
        }
        if l.contains("roku") {
            v.ty("media device", 5, format!("SSDP server {s:?}"));
        }
        if l.contains("sonos") {
            v.ty("smart speaker", 5, format!("SSDP server {s:?}"));
        }
        if l.contains("synology") || l.contains("qnap") {
            v.ty("nas", 5, format!("SSDP server {s:?}"));
        }
        if l.contains("tizen") || l.contains("webos") {
            v.ty("tv", 5, format!("SSDP server {s:?}"));
        }
    }
    for t in &fp.ssdp_types {
        let l = t.to_ascii_lowercase();
        if l.contains("internetgatewaydevice") || l.contains("wandevice") {
            v.ty("router", 4, "SSDP InternetGatewayDevice");
        } else if l.contains("mediarenderer") || l.contains("dial-multiscreen") {
            v.ty("media device", 3, format!("SSDP {t}"));
        } else if l.contains(":printer:") {
            v.ty("printer", 4, format!("SSDP {t}"));
        }
    }

    // --- OUI vendor: weak evidence (many vendors make many things)
    if let Some(vendor) = &a.vendor {
        let l = vendor.to_ascii_lowercase();
        let has = |ws: &[&str]| ws.iter().any(|w| l.contains(w));
        if has(&["ubiquiti", "cisco", "juniper", "mikrotik", "routerboard", "netgear", "d-link", "aruba", "ruckus", "zyxel", "fortinet", "sophos", "draytek", "avm", "fritz", "arris", "sagemcom", "technicolor", "huawei device"]) {
            v.ty("network device", 3, format!("vendor {vendor}"));
        }
        // "TP-Link Systems" is the Kasa/Tapo smart-home business; the older
        // "TP-LINK TECHNOLOGIES" OUIs are mostly routers/APs but also Tapo gear.
        if has(&["tp-link systems"]) {
            v.ty("iot", 3, format!("vendor {vendor} (Kasa/Tapo smart home)"));
        } else if has(&["tp-link"]) {
            v.ty("network device", 2, format!("vendor {vendor}"));
            v.ty("iot", 1, format!("vendor {vendor}"));
        }
        if has(&["canon", "epson", "brother", "xerox", "lexmark", "kyocera", "ricoh", "konica", "seiko epson", "hewlett", "hp inc"]) {
            v.ty("printer", 2, format!("vendor {vendor}"));
        }
        if has(&["synology", "qnap", "western digital", "asustor", "terramaster"]) {
            v.ty("nas", 3, format!("vendor {vendor}"));
        }
        if has(&["sonos", "bose"]) {
            v.ty("smart speaker", 4, format!("vendor {vendor}"));
        }
        if has(&["hikvision", "dahua", "axis comm", "reolink", "amcrest", "ring ", "arlo", "wyze"]) {
            v.ty("camera", 4, format!("vendor {vendor}"));
        }
        if has(&["espressif", "tuya", "shelly", "sonoff", "itead", "ecobee", "signify", "philips lighting", "nest labs", "lifx", "meross", "kasa"]) {
            v.ty("iot", 3, format!("vendor {vendor}"));
        }
        if has(&["raspberry"]) {
            v.both("computer", "Linux", 3, format!("vendor {vendor}"));
        }
        if has(&["roku", "vizio", "hisense", "tcl", "lg electronics", "sony interactive", "nintendo", "microsoft xbox"]) {
            v.ty("media device", 2, format!("vendor {vendor}"));
        }
        if has(&["amazon"]) {
            v.ty("iot", 2, format!("vendor {vendor}"));
        }
        if has(&["apple"]) {
            v.os("Apple", 1, format!("vendor {vendor}"));
        }
        if has(&["intel", "dell", "lenovo", "asustek", "gigabyte", "micro-star", "liteon", "azurewave", "hon hai", "foxconn", "quanta", "compal", "wistron"]) {
            v.ty("computer", 1, format!("vendor {vendor}"));
        }
        if has(&["xiaomi", "oppo", "vivo", "oneplus", "motorola", "samsung electronics", "google"]) {
            v.ty("phone", 1, format!("vendor {vendor}"));
        }
        if has(&["vmware", "parallels", "qemu", "xen", "virtualbox", "microsoft corporation"]) && a.vendor.is_some() {
            v.ty("virtual machine", 2, format!("vendor {vendor}"));
        }
    }
    if a.randomized_mac {
        // Private/randomised MACs are overwhelmingly phones, tablets and laptops.
        v.ty("phone", 1, "randomised (private) MAC address");
    }

    // --- open ports
    let ports: Vec<u16> = a.open_ports.iter().map(|p| p.port).collect();
    let has_port = |p: u16| ports.contains(&p);
    if has_port(9100) || has_port(515) || has_port(631) {
        v.ty("printer", 4, "printer ports (9100/515/631)");
    }
    if has_port(3389) {
        v.both("computer", "Windows", 4, "RDP (3389)");
    }
    if has_port(445) && has_port(139) {
        v.ty("computer", 1, "SMB (139+445)");
    }
    if has_port(62078) {
        v.both("phone", "iOS", 4, "iOS lockdown port (62078)");
    }
    if has_port(554) {
        v.ty("camera", 3, "RTSP (554)");
    }
    if has_port(8009) {
        v.ty("media device", 3, "Cast (8009)");
    }
    if has_port(7000) || has_port(7100) {
        v.os("Apple", 1, "AirPlay (7000/7100)");
    }
    if has_port(5000) || has_port(5001) {
        v.ty("nas", 1, "Synology DSM ports (5000/5001)");
    }
    if has_port(8291) {
        v.ty("router", 4, "MikroTik Winbox (8291)");
    }
    if has_port(548) {
        v.ty("nas", 1, "AFP (548)");
    }
    if has_port(8006) {
        v.both("server", "Linux", 3, "Proxmox UI (8006)");
    }
    if has_port(22) {
        v.os("Unix-like", 1, "SSH (22)");
    }
    if has_port(53) && (has_port(80) || has_port(443)) {
        v.ty("router", 1, "DNS + web admin");
    }
    if has_port(1883) {
        v.ty("iot", 1, "MQTT (1883)");
    }

    // --- passive TCP/IP fingerprint
    if let Some(sig) = &fp.tcp_sig {
        if let Some((os, w)) = os_from_tcp(sig) {
            v.os(os, w, format!("TCP SYN sig ttl={} win={} opts={}", sig.ttl, sig.window, sig.options));
        }
    } else if let Some(ttl) = fp.ttl {
        match initial_ttl(ttl) {
            128 => v.os("Windows", 2, format!("ICMP ttl {ttl}")),
            255 => v.ty("network device", 1, format!("ICMP ttl {ttl}")),
            64 => v.os("Unix-like", 1, format!("ICMP ttl {ttl}")),
            _ => {}
        }
    }

    if a.is_self {
        v.ty("computer", 10, "this scanner");
    }

    let device_type = winner(&v.types).unwrap_or("unknown").to_string();
    let os = winner(&v.os).map(str::to_string);
    Guess {
        device_type,
        os,
        reasons: v.reasons,
    }
}

/// Well-known TCP port -> service label (also the scan list).
pub const SCAN_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (443, "https"),
    (445, "smb"),
    (515, "lpd"),
    (548, "afp"),
    (554, "rtsp"),
    (631, "ipp"),
    (993, "imaps"),
    (1883, "mqtt"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5000, "upnp/dsm"),
    (5001, "dsm-https"),
    (5900, "vnc"),
    (7000, "airplay"),
    (8000, "http-alt"),
    (8006, "proxmox"),
    (8009, "cast"),
    (8080, "http-proxy"),
    (8291, "winbox"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9100, "jetdirect"),
    (32400, "plex"),
    (62078, "iphone-sync"),
];

pub fn service_name(port: u16) -> Option<&'static str> {
    SCAN_PORTS.iter().find(|(p, _)| *p == port).map(|(_, n)| *n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OpenPort;

    fn asset() -> Asset {
        Asset::new(Mac([0x00, 0x1b, 0x63, 1, 2, 3]), 0)
    }

    fn port(p: u16) -> OpenPort {
        OpenPort { port: p, proto: "tcp".into(), service: service_name(p).map(str::to_string) }
    }

    #[test]
    fn oui_lookup_and_private_mac() {
        // 00:00:0c is Cisco's, a long-stable registration.
        let v = vendor_for(&Mac([0x00, 0x00, 0x0c, 1, 2, 3])).unwrap();
        assert!(v.to_lowercase().contains("cisco"), "{v}");
        assert_eq!(vendor_for(&Mac([0x02, 0x00, 0x0c, 1, 2, 3])), None);
    }

    #[test]
    fn ttl_families() {
        assert_eq!(initial_ttl(57), 64);
        assert_eq!(initial_ttl(64), 64);
        assert_eq!(initial_ttl(127), 128);
        assert_eq!(initial_ttl(250), 255);
    }

    #[test]
    fn printer_from_mdns_and_ports() {
        let mut a = asset();
        a.fingerprint.mdns_services = vec!["_ipp._tcp".into()];
        a.open_ports = vec![port(9100), port(631)];
        let g = guess(&a);
        assert_eq!(g.device_type, "printer");
        assert!(!g.reasons.is_empty());
    }

    #[test]
    fn windows_from_dhcp_and_tcp() {
        let mut a = asset();
        a.fingerprint.dhcp_vendor_class = Some("MSFT 5.0".into());
        a.fingerprint.tcp_sig = Some(TcpSig { ttl: 128, window: 64240, options: "MNWNNS".into(), mss: Some(1460), wscale: Some(8) });
        let g = guess(&a);
        assert_eq!(g.os.as_deref(), Some("Windows"));
        assert_eq!(g.device_type, "computer");
    }

    #[test]
    fn iphone_from_hostname() {
        let mut a = asset();
        a.hostnames = vec!["Stefans-iPhone".into()];
        let g = guess(&a);
        assert_eq!(g.device_type, "phone");
        assert_eq!(g.os.as_deref(), Some("iOS"));
    }

    #[test]
    fn gateway_is_router_and_weak_evidence_is_unknown() {
        let mut a = asset();
        a.is_gateway = true;
        assert_eq!(guess(&a).device_type, "router");
        // A lone weak hint (ttl 64) must not invent a device type or OS.
        let mut b = asset();
        b.fingerprint.ttl = Some(64);
        let g = guess(&b);
        assert_eq!(g.device_type, "unknown");
        assert_eq!(g.os, None);
    }

    #[test]
    fn tp_link_systems_is_smart_home_but_tp_link_technologies_is_ambiguous() {
        let mut kasa = asset();
        kasa.vendor = Some("TP-Link Systems".into());
        assert_eq!(guess(&kasa).device_type, "iot");

        // With no other evidence the older OUI is a router-ish guess, but an
        // open smart-plug-style device (no DNS/web admin) is not forced to "router".
        let mut ap = asset();
        ap.vendor = Some("TP-LINK".into());
        assert_eq!(guess(&ap).device_type, "network device");
        ap.is_gateway = true;
        assert_eq!(guess(&ap).device_type, "router");
    }

    #[test]
    fn ttl_255_is_embedded_firmware_and_ttl_64_linux_options_are_linux() {
        // Linux never starts at TTL 255, so option order must not override it.
        for opts in ["MSTNW", "M"] {
            let sig = TcpSig { ttl: 255, window: 5744, options: opts.into(), mss: Some(1436), wscale: None };
            assert_eq!(os_from_tcp(&sig).unwrap().0, "Embedded firmware (lwIP/RTOS)");
        }
        let linux = TcpSig { ttl: 64, window: 14480, options: "MSTNW".into(), mss: Some(1460), wscale: Some(7) };
        assert_eq!(os_from_tcp(&linux).unwrap().0, "Linux");
    }

    #[test]
    fn apple_tcp_signature() {
        let sig = TcpSig { ttl: 64, window: 65535, options: "MNWNNTSE".into(), mss: Some(1460), wscale: Some(6) };
        assert_eq!(os_from_tcp(&sig).unwrap().0, "Apple (macOS/iOS)");
    }

    #[test]
    fn short_vendor_strips_suffixes() {
        assert_eq!(short_vendor("Apple, Inc."), "Apple");
        assert_eq!(short_vendor("TP-LINK TECHNOLOGIES CO.,LTD."), "TP-LINK");
        assert_eq!(short_vendor("Seongji Industry Company Limited"), "Seongji Industry");
    }
}
