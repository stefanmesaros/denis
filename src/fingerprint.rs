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

/// Device types that belong to industrial / building automation.
pub const OT_TYPES: &[&str] = &[
    "plc", "hmi", "rtu", "scada server", "engineering workstation", "historian", "industrial switch",
    "industrial gateway", "drive", "sensor", "building controller", "industrial device",
    "safety controller", "protection relay", "power meter", "remote io", "industrial pc", "cnc machine",
    "rfid reader", "robot", "pump", "valve", "motor",
];

/// Manufacturers whose products are (almost) exclusively industrial.
const ICS_VENDORS: &[&str] = &[
    "siemens", "rockwell", "allen-bradley", "schneider", "modicon", "abb ", "mitsubishi electric", "omron", "beckhoff",
    "wago", "phoenix contact", "moxa", "hirschmann", "belden", "honeywell", "emerson", "yokogawa", "advantech",
    "b&r", "festo", "pilz", "endress", "bosch rexroth", "turck", "lenze", "sick ag", "keyence", "fuji electric",
    "red lion", "prosoft", "hms industrial", "eaton", "danfoss", "sew-eurodrive", "pepperl", "weidmuller", "weidmüller",
    "brainboxes", "digi international", "lantronix", "opto 22", "unitronics", "delta electronics", "schweitzer",
];

/// Is this an industrial device? Then it is never port-scanned, and it is
/// treated as fragile: some PLC firmware crashes on unexpected connections.
pub fn is_ot_device(a: &Asset) -> bool {
    !a.fingerprint.ot.is_empty()
        || OT_TYPES.contains(&a.device_type.as_str())
        || a.vendor.as_deref().is_some_and(|v| {
            let l = v.to_ascii_lowercase();
            ICS_VENDORS.iter().any(|i| l.contains(i))
        })
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

/// Vote from a DHCP parameter request list such as `"1,121,3,6,15,119,252"`.
///
/// Only the option *sets* that are characteristic of a client family are used,
/// and each vote is deliberately modest (3–4): a list identifies software, not a
/// product, and other clients can copy it. The Apple pattern (options 121, 119
/// and 252 together) and the Windows pattern (249 with 31/33/43) come from the
/// widely published DHCP fingerprint databases and, for Apple, were confirmed on
/// a real macOS 15 client; the Android and Linux ones have not been checked
/// against real devices here.
fn dhcp_param_votes(v: &mut Votes, list: &str) {
    let opts: Vec<u8> = list.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    let has = |n: u8| opts.contains(&n);
    let why = || format!("DHCP option list {list}");
    if has(121) && has(119) && has(252) && !has(249) {
        // Apple: 95 (LDAP), 44/46 (NetBIOS) are only asked for by macOS.
        if has(95) || has(44) || has(46) {
            v.both("computer", "macOS", 4, format!("{} (Apple client that also asks for NetBIOS/LDAP: macOS)", why()));
        } else {
            v.os("iOS", 3, format!("{} (Apple client without NetBIOS/LDAP: iOS/iPadOS)", why()));
            v.ty("phone", 2, why());
        }
    } else if has(249) && has(252) && has(31) && has(33) {
        v.both("computer", "Windows", 4, format!("{} (Windows DHCP client)", why()));
    } else if has(26) && has(28) && has(51) && has(58) && has(59) && !has(121) {
        v.both("phone", "Android", 3, format!("{} (Android DHCP client)", why()));
    } else if opts.starts_with(&[1, 28, 2, 3, 15, 6]) && has(119) && has(12) {
        v.os("Linux", 3, format!("{} (dhclient / NetworkManager)", why()));
    } else if opts == [1, 3, 28, 6, 42] {
        // Seen on a Shelly plug (ESP32): a minimal embedded DHCP client.
        v.ty("iot", 2, format!("{} (minimal embedded DHCP client)", why()));
    }
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

    // --- DHCP option 55 (the list of options a client asks for). It identifies the
    // DHCP client software, and it is sent even by devices with no vendor class and
    // a private MAC (iPhones and Macs send no option 60 at all).
    if let Some(list) = &fp.dhcp_param_list {
        dhcp_param_votes(&mut v, list);
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
        } else if ["roomba", "irobot", "roborock", "dreame", "ecovacs", "deebot", "rockrobo"].iter().any(|w| l.contains(w)) {
            v.ty("robot vacuum", 5, format!("name {h:?}"));
        } else if ["automower", "husqvarna", "landroid", "mammotion"].iter().any(|w| l.contains(w)) {
            v.ty("robot lawn mower", 5, format!("name {h:?}"));
        } else if ["fridge", "refrigerator", "kuehlschrank", "familyhub", "family-hub"].iter().any(|w| l.contains(w)) {
            v.ty("smart refrigerator", 4, format!("name {h:?}"));
        } else if l.contains("dishwasher") || l.contains("geschirrspueler") {
            v.ty("dishwasher", 4, format!("name {h:?}"));
        } else if l.contains("washing") || l.contains("waschmaschine") || l.starts_with("washer") {
            v.ty("washing machine", 4, format!("name {h:?}"));
        } else if l.contains("kindle") {
            v.ty("e-reader", 5, format!("name {h:?}"));
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
            // Apple AirPort base stations announce themselves as `_airport._tcp`
            "_airport._tcp" | "_acp-sync._tcp" => v.ty("access point", 5, format!("mDNS {s} (AirPort base station)")),
            // Apple Continuity ("Nearby") beacons: an iPhone, iPad, Watch or Mac, often with a private MAC
            "_nearbypresence._tcp" => v.os("Apple", 3, "mDNS _nearbypresence._tcp (Apple Nearby)"),
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
        // "Unspecified, UPnP/1.0, Unspecified" is how ASUS (and similar) router firmware
        // introduces its UPnP gateway service.
        if l.starts_with("unspecified, upnp/1.0") {
            v.ty("router", 3, format!("SSDP server {s:?} (router UPnP service)"));
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
        if has(&["espressif", "tuya", "shelly", "sonoff", "itead", "ecobee", "signify", "philips lighting", "nest labs", "lifx", "meross", "kasa", "altobeam", "high-flying", "samjin"]) {
            v.ty("iot", 3, format!("vendor {vendor}"));
        }
        // robots, appliances, energy and other everyday devices (vendor evidence is weaker than a name)
        for (words, ty, w) in [
            (&["irobot", "roborock", "ecovacs", "dreame", "narwal"][..], "robot vacuum", 4),
            (&["husqvarna", "positec", "gardena"][..], "robot lawn mower", 3),
            (&["miele", "bsh hausger", "electrolux", "whirlpool", "liebherr", "smeg", "vorwerk"][..], "appliance", 3),
            (&["nespresso", "jura elektro", "delonghi", "de'longhi"][..], "coffee machine", 3),
            (&["sma solar", "fronius", "solaredge", "enphase", "growatt", "goodwe", "sungrow"][..], "solar inverter", 4),
            (&["wallbox", "easee", "keba"][..], "ev charger", 4),
            (&["denon", "marantz", "onkyo"][..], "av receiver", 3),
            (&["dji"][..], "drone", 4),
            (&["kobo"][..], "e-reader", 4),
            (&["garmin", "fitbit"][..], "wearable", 3),
            (&["rachio", "rain bird"][..], "irrigation controller", 3),
            (&["chamberlain", "myq"][..], "garage door opener", 4),
            (&["tado"][..], "thermostat", 3),
            (&["ajax systems"][..], "alarm panel", 3),
            (&["oculus", "meta platforms technologies", "facebook technologies"][..], "vr headset", 3),
            (&["dymo"][..], "label printer", 4),
        ] {
            if has(words) {
                v.ty(ty, w, format!("vendor {vendor}"));
            }
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

    // --- industrial protocols: who serves, who polls
    for (proto, role) in &fp.ot {
        let p = proto.as_str();
        match (p, role.server, role.client) {
            ("s7" | "enip", true, _) => v.ty("plc", 5, format!("serves {p} (a controller)")),
            ("modbus", true, _) => v.ty("plc", 4, "serves Modbus/TCP"),
            ("dnp3" | "iec104", true, _) => v.ty("rtu", 4, format!("serves {p} (an outstation)")),
            ("bacnet", true, _) => v.ty("building controller", 4, "serves BACnet"),
            ("opcua", true, _) => v.ty("industrial gateway", 3, "serves OPC UA"),
            (_, false, true) => v.ty("hmi", 2, format!("polls {p} devices")),
            _ => {}
        }
        if p == "s7" && role.client {
            v.os("Siemens engineering/HMI", 1, "speaks S7 as a client");
        }
    }
    if let Some(sys) = fp.identity.get("lldp.system_description").or_else(|| fp.identity.get("cdp.system_description")) {
        let l = sys.to_ascii_lowercase();
        if ["scalance", "hirschmann", "moxa", "stratix", "westermo", "ruggedcom", "industrial ethernet"].iter().any(|k| l.contains(k)) {
            v.ty("industrial switch", 5, format!("LLDP/CDP description {sys:?}"));
        }
    }
    for key in ["lldp.capabilities", "cdp.capabilities"] {
        if let Some(c) = fp.identity.get(key) {
            if c.contains("wlan-ap") {
                v.ty("access point", 5, format!("{key} = {c}"));
            } else if c.contains("router") {
                v.ty("router", 3, format!("{key} = {c}"));
            } else if c.contains("bridge") || c.contains("switch") {
                v.ty("network device", 4, format!("{key} = {c}"));
            }
        }
    }
    if let Some(role) = fp.identity.get("profinet.role") {
        if role.contains("io-controller") {
            v.ty("plc", 4, "PROFINET IO controller");
        } else if role.contains("io-device") {
            v.ty("industrial device", 3, "PROFINET IO device");
        }
    }
    if let Some(vendor) = &a.vendor {
        let l = vendor.to_ascii_lowercase();
        if ICS_VENDORS.iter().any(|i| l.contains(i)) {
            v.ty("industrial device", 2, format!("vendor {vendor} builds industrial equipment"));
        }
    }
    for h in a.hostnames.iter() {
        let l = h.to_ascii_lowercase();
        for (needle, ty) in [("plc", "plc"), ("hmi", "hmi"), ("rtu", "rtu"), ("scada", "scada server"), ("historian", "historian")] {
            if l.split(|c: char| !c.is_alphanumeric()).any(|t| t == needle || t.starts_with(needle) && t[needle.len()..].chars().all(|c| c.is_ascii_digit())) {
                v.ty(ty, 4, format!("name {h:?}"));
            }
        }
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

/// Device types the guesser can produce (and the edit form offers). Users may
/// also type their own via the override field.
pub const DEVICE_TYPES: &[&str] = &[
    "computer", "laptop", "server", "virtual machine", "phone", "tablet", "printer", "router", "network device",
    "access point", "nas", "camera", "media device", "smart speaker", "tv", "iot", "unknown",
    // more office / IT
    "thin client", "point of sale", "kiosk", "hypervisor", "database server", "storage array", "kvm", "pdu", "ups",
    "load balancer", "vpn gateway", "firewall", "security appliance", "modem", "mesh node", "wireless controller",
    "cloud service", "projector", "conference system", "voip phone", "3d printer", "scanner", "barcode scanner",
    // home, building and consumer
    "set-top box", "streaming stick", "game console", "wearable", "smart plug", "smart light", "smart lock", "doorbell",
    "badge reader", "alarm panel", "smoke detector", "thermostat", "hvac controller", "smart hub", "robot vacuum",
    "appliance", "medical device", "ev charger", "solar inverter", "vehicle",
    // robots, appliances, smart home, energy, office/IT extras
    "robot lawn mower", "drone", "irrigation controller", "smart refrigerator", "washing machine", "dishwasher", "oven",
    "coffee machine", "air purifier", "air conditioner", "heat pump", "water heater", "smart meter", "battery storage",
    "soundbar", "av receiver", "smart display", "vr headset", "e-reader", "baby monitor", "pet feeder", "smart scale",
    "garage door opener", "smart blinds", "intercom", "motion sensor", "door sensor", "leak sensor", "weather station",
    "nvr", "digital signage", "label printer", "time clock", "microcontroller", "mini pc", "management controller",
    "wireless bridge", "powerline adapter", "vending machine", "single-board computer",
    // operational technology
    "plc", "hmi", "rtu", "scada server", "engineering workstation", "historian", "industrial switch",
    "industrial gateway", "drive", "sensor", "building controller", "industrial device",
    "safety controller", "protection relay", "power meter", "remote io", "industrial pc", "cnc machine",
    "rfid reader", "robot", "pump", "valve", "motor",
];

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
        a.hostnames = vec!["Anns-iPhone".into()];
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
    fn industrial_roles_identity_and_names_type_ot_devices() {
        use crate::model::OtRole;
        let role = |server, client| OtRole { server, client, first_seen: 0, last_seen: 0 };
        let mut plc = asset();
        plc.fingerprint.ot.insert("s7".into(), role(true, false));
        assert_eq!(guess(&plc).device_type, "plc");
        assert!(is_ot_device(&plc));

        let mut hmi = asset();
        hmi.fingerprint.ot.insert("modbus".into(), role(false, true));
        assert_eq!(guess(&hmi).device_type, "hmi");

        let mut rtu = asset();
        rtu.fingerprint.ot.insert("dnp3".into(), role(true, false));
        assert_eq!(guess(&rtu).device_type, "rtu");

        let mut bms = asset();
        bms.fingerprint.ot.insert("bacnet".into(), role(true, false));
        assert_eq!(guess(&bms).device_type, "building controller");

        let mut sw = asset();
        sw.fingerprint.identity.insert("lldp.system_description".into(), "SCALANCE XC208 Industrial Ethernet switch".into());
        assert_eq!(guess(&sw).device_type, "industrial switch");
        let mut ap = asset();
        ap.fingerprint.identity.insert("lldp.capabilities".into(), "bridge,wlan-ap".into());
        assert_eq!(guess(&ap).device_type, "access point");

        // a vendor alone is weak evidence (2) but is enough for "industrial device"; names help too
        let mut v = asset();
        v.vendor = Some("Siemens AG".into());
        assert_eq!(guess(&v).device_type, "industrial device");
        assert!(is_ot_device(&v));
        let mut named = asset();
        named.hostnames = vec!["plc-line3".into()];
        assert_eq!(guess(&named).device_type, "plc");
        let mut not = asset();
        not.hostnames = vec!["couplet".into(), "plcx".into()]; // substrings must not match
        assert_eq!(guess(&not).device_type, "unknown");
        assert!(!is_ot_device(&not));
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

    #[test]
    fn dhcp_option_lists_identify_the_client_family_even_without_a_vendor_class() {
        let with = |list: &str| {
            let mut a = Asset::new(Mac([0x02, 0, 0, 0, 0, 9]), 0);
            a.fingerprint.dhcp_param_list = Some(list.into());
            a
        };
        // captured from a real Mac on the development network (hostname just "Mac")
        let g = guess(&with("1,121,3,6,15,108,114,119,162,252,95,44,46"));
        assert_eq!((g.device_type.as_str(), g.os.as_deref()), ("computer", Some("macOS")));
        assert!(g.reasons.iter().any(|r| r.contains("DHCP option list")));
        assert_eq!(guess(&with("1,121,3,6,15,119,252")).os.as_deref(), Some("iOS"));
        assert_eq!(guess(&with("1,3,6,15,31,33,43,44,46,47,119,121,249,252")).os.as_deref(), Some("Windows"));
        assert_eq!(guess(&with("1,3,6,15,26,28,51,58,59,43")).os.as_deref(), Some("Android"));
        assert_eq!(guess(&with("1,28,2,3,15,6,119,12,44,47,26,121,42")).os.as_deref(), Some("Linux"));
        // unknown or garbage lists vote for nothing
        for l in ["", "1,3,6", "abc,,999", "1,121"] {
            assert_eq!(guess(&with(l)).os, None, "{l:?}");
        }
    }

    #[test]
    fn devices_seen_on_a_real_home_network_that_used_to_stay_unknown() {
        let mut asus = Asset::new(Mac([0xc8, 0x7f, 0x54, 0x8f, 0x10, 0xa0]), 0);
        asus.vendor = Some("ASUSTek COMPUTER INC.".into());
        asus.fingerprint.ssdp_server = Some("Unspecified, UPnP/1.0, Unspecified".into());
        assert_eq!(guess(&asus).device_type, "router");

        let mut airport = Asset::new(Mac([0x90, 0x84, 0x0d, 0, 0, 1]), 0);
        airport.vendor = Some("Apple".into());
        airport.fingerprint.mdns_services = vec!["_airport._tcp".into(), "_raop._tcp".into(), "_acp-sync._tcp".into()];
        assert_eq!(guess(&airport).device_type, "access point");

        for vendor in ["AltoBeam", "Shanghai High-Flying Electronics\nTechnology Co., Ltd", "SAMJIN"] {
            let mut a = Asset::new(Mac([0x68, 0x3a, 0x48, 0, 0, 1]), 0);
            a.vendor = Some(vendor.into());
            assert_eq!(guess(&a).device_type, "iot", "{vendor}");
        }
        // a Windows PC's UPnP string must not be mistaken for a router
        let mut pc = Asset::new(Mac([0x00, 0x1b, 0x63, 0, 0, 2]), 0);
        pc.vendor = Some("ASUSTek COMPUTER INC.".into());
        pc.fingerprint.ssdp_server = Some("Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0".into());
        assert_eq!(guess(&pc).device_type, "computer");
    }

    #[test]
    fn robots_appliances_and_everyday_devices_are_recognised_by_name_or_vendor_and_every_type_is_a_known_one() {
        let named = |host: &str| {
            let mut a = asset();
            a.hostnames.push(host.into());
            guess(&a).device_type
        };
        for (host, ty) in [
            ("Roomba-3F2A", "robot vacuum"), ("roborock-s7", "robot vacuum"), ("Automower-430X", "robot lawn mower"),
            ("Samsung-Fridge", "smart refrigerator"), ("Miele-dishwasher-01", "dishwasher"), ("waschmaschine", "washing machine"), ("Kindle-Paperwhite", "e-reader"),
        ] {
            assert_eq!(named(host), ty, "{host}");
        }
        let vendor = |v: &str| {
            let mut a = asset();
            a.vendor = Some(v.into());
            guess(&a).device_type
        };
        for (v, ty) in [("iRobot Corporation", "robot vacuum"), ("Husqvarna Group", "robot lawn mower"), ("Fronius International GmbH", "solar inverter"), ("SZ DJI Technology Co.,Ltd", "drone"), ("Miele & Cie. KG", "appliance"), ("Dymo", "label printer")] {
            assert_eq!(vendor(v), ty, "{v}");
        }
        // every type the guesser can return is in the list the console offers
        let src = include_str!("fingerprint.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        for w in body.split("v.ty(\"").skip(1).chain(body.split("v.both(\"").skip(1)) {
            let ty = w.split('"').next().unwrap();
            assert!(DEVICE_TYPES.contains(&ty), "the guesser can return {ty:?} but the console does not list it");
        }
        for w in ["robot lawn mower", "smart refrigerator", "drone", "washing machine", "e-reader"] {
            assert!(DEVICE_TYPES.contains(&w));
        }
    }
}
