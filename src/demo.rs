//! Demo data: a fictional company ("Acme Manufacturing": an office, a production
//! hall with PLCs and HMIs, and a branch site) so a new user can explore every screen of
//! the console before pointing DENIS at a real network.
//!
//! Everything here is invented: made-up names, MAC addresses and private addresses. Demo
//! records are tagged (`AssetMeta::demo`, sites named `demo-…`) so they can be removed in
//! one step without touching real data, and the collector and detector ignore them (they must
//! not decide when learning ends, be judged "silent" or count in the trend charts).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::model::{AgentInfo, Asset, AssetMeta, Baseline, Conversation, DestStat, Event, IpRecord, Mac, Metric, OpenPort, OtRole};
use crate::store::{DEMO_SITE_PREFIX, Store};
use crate::tracking::apply_patch;

const HQ: &str = "demo-hq";
const BRANCH: &str = "demo-branch";
const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;

/// What loading created.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct Loaded {
    pub assets: usize,
    pub events: usize,
}

pub fn is_loaded(store: &dyn Store) -> Result<bool> {
    Ok(store.load_all_meta()?.values().any(|m| m.demo))
}

/// Remove every demo record. Returns how many devices went. Real data is untouched.
pub fn remove(store: &dyn Store) -> Result<usize> {
    let ids: Vec<i64> = store.load_all_meta()?.into_iter().filter(|(_, m)| m.demo).map(|(id, _)| id).collect();
    for id in &ids {
        store.delete_asset(*id)?;
    }
    for a in store.list_agents()? {
        if a.id.starts_with(DEMO_SITE_PREFIX) {
            store.delete_agent_data(&a.id)?;
        }
    }
    Ok(ids.len())
}

struct Builder<'a> {
    store: &'a dyn Store,
    now: i64,
    n: u32,
    ids: BTreeMap<&'static str, i64>,
}

fn date(now: i64, days: i64) -> String {
    crate::report::iso(now + days * DAY)[..10].to_string()
}

impl Builder<'_> {
    fn mac(&mut self, oui: [u8; 3]) -> Mac {
        self.n += 1;
        Mac([oui[0], oui[1], oui[2], (self.n >> 8) as u8, self.n as u8, (self.n * 7) as u8])
    }

    /// Add one device. `meta` is a JSON patch validated like any user edit.
    #[allow(clippy::too_many_arguments)]
    fn asset(&mut self, key: &'static str, site: &'static str, name: Option<&str>, ty: &str, vendor: Option<&str>, ip: [u8; 4], oui: [u8; 3],
             ports: &[u16], os: Option<&str>, opts: Opts, meta: Option<Value>) -> Result<i64> {
        let now = self.now;
        let mut a = Asset::new(self.mac(oui), now - opts.first_days * DAY);
        a.agent_id = Some(site.to_string());
        a.vendor = vendor.map(String::from);
        a.randomized_mac = opts.randomized;
        a.hostnames = name.map(|n| vec![n.to_string()]).unwrap_or_default();
        a.device_type = ty.to_string();
        a.os_guess = os.map(String::from);
        a.guess_reasons = opts.reasons.iter().map(|s| s.to_string()).collect();
        a.open_ports = ports.iter().map(|p| OpenPort { port: *p, proto: "tcp".into(), service: None }).collect();
        a.ports_scanned_at = (!ports.is_empty()).then_some(now - 3 * HOUR);
        a.is_gateway = opts.gateway;
        a.last_seen = now - opts.seen_secs;
        a.ip_history = vec![IpRecord { ip: Ipv4Addr::from(ip), first_seen: a.first_seen, last_seen: a.last_seen }];
        for (proto, server, client) in opts.ot {
            a.fingerprint.ot.insert(proto.to_string(), OtRole { server: *server, client: *client, first_seen: a.first_seen, last_seen: a.last_seen });
        }
        self.store.save_asset(&mut a)?;
        // reviewed unless it is one of the "new, nobody has looked" devices (meta None)
        if let Some(patch) = meta {
            let mut m = AssetMeta::default();
            apply_patch(&mut m, &patch).map_err(|e| anyhow::anyhow!("demo data: {e}"))?;
            m.reviewed = true;
            m.demo = true;
            self.store.save_meta(a.id, &m, "demo", now - 5 * DAY)?;
        } else {
            self.store.save_meta(a.id, &AssetMeta { demo: true, ..Default::default() }, "demo", now)?;
        }
        self.ids.insert(key, a.id);
        Ok(a.id)
    }

    fn id(&self, key: &str) -> i64 {
        self.ids[key]
    }

    /// What a device's services said about themselves when they were scanned (a version banner).
    fn banners(&self, key: &str, pairs: &[(&str, &str)]) -> Result<()> {
        let mut a = self.store.get_asset(self.ids[key])?.ok_or_else(|| anyhow::anyhow!("demo data: no device {key}"))?;
        for (k, v) in pairs {
            a.fingerprint.identity.insert(k.to_string(), v.to_string());
        }
        self.store.save_asset(&mut a)?;
        Ok(())
    }
}

#[derive(Default)]
struct Opts<'a> {
    first_days: i64,
    seen_secs: i64,
    gateway: bool,
    randomized: bool,
    reasons: &'a [&'a str],
    ot: &'a [(&'a str, bool, bool)],
}

fn o<'a>() -> Opts<'a> {
    Opts { first_days: 30, seen_secs: 60, ..Default::default() }
}

/// Create the demo data. Refuses to run twice.
pub fn load(store: &dyn Store, now: i64) -> Result<Loaded> {
    if is_loaded(store)? {
        bail!("the demo data is already loaded");
    }
    let mut b = Builder { store, now, n: 0, ids: BTreeMap::new() };
    for (id, name, site, subnet, seq) in [(HQ, "Headquarters", "Košice", "10.20.0.0/16", 412), (BRANCH, "Branch office", "Bratislava", "10.30.0.0/24", 88)] {
        store.upsert_agent(&AgentInfo { id: id.into(), name: name.into(), site: Some(site.into()), version: env!("CARGO_PKG_VERSION").into(), subnet: subnet.into(), first_seen: now - 20 * DAY, last_report_at: now - 40, last_run_id: "demo".into(), last_seq: seq })?;
    }
    let d = |days| date(now, days);

    // ------------------------------------------------------------ office network
    b.asset("router", HQ, Some("core-router"), "router", Some("Ubiquiti Inc"), [10, 20, 10, 1], [0x78, 0x45, 0x58], &[80, 443, 22], Some("Linux"), Opts { gateway: true, reasons: &["router +6: default gateway", "network device +3: vendor Ubiquiti Inc"], ..o() },
        Some(json!({"display_name": "Core router", "owner": "IT", "location": "Server room", "criticality": "critical", "serial_number": "UDM-88213", "asset_tag": "IT-0001", "icon": "router", "warranty_expires": d(400)})))?;
    b.asset("fw", HQ, Some("fw-edge"), "firewall", Some("Fortinet, Inc."), [10, 20, 10, 2], [0x00, 0x09, 0x0f], &[443, 22], Some("FortiOS"), o(),
        Some(json!({"display_name": "Edge firewall", "owner": "IT", "location": "Server room", "criticality": "critical", "serial_number": "FG100F-4471", "asset_tag": "IT-0002", "warranty_expires": d(45)})))?;
    b.asset("sw", HQ, Some("sw-office-1"), "network device", Some("Cisco Systems, Inc"), [10, 20, 10, 3], [0x00, 0x1b, 0x54], &[22, 443], None, o(),
        Some(json!({"display_name": "Office switch 1", "owner": "IT", "location": "Wiring closet A", "criticality": "high", "serial_number": "FCW2244A0XY", "asset_tag": "IT-0003"})))?;
    b.asset("ap", HQ, Some("ap-lobby"), "access point", Some("Ubiquiti Inc"), [10, 20, 10, 4], [0xfc, 0xec, 0xda], &[443], None, o(),
        Some(json!({"display_name": "Lobby access point", "owner": "IT", "location": "Lobby", "asset_tag": "IT-0004"})))?;
    b.asset("nas", HQ, Some("nas-finance"), "nas", Some("Synology Incorporated"), [10, 20, 10, 20], [0x00, 0x11, 0x32], &[445, 5000, 22], Some("Linux"), Opts { reasons: &["nas +5: vendor Synology", "nas +5: SSDP server 'Synology'"], ..o() },
        Some(json!({"display_name": "Finance file server", "owner": "Finance", "department": "Finance", "location": "Server room", "criticality": "high", "serial_number": "2170Q0N7F3", "asset_tag": "IT-0020", "tags": ["backup", "finance"], "warranty_expires": d(-30)})))?;
    b.banners("nas", &[("banner.ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"), ("banner.http", "Server: nginx/1.10.3 (Ubuntu)")])?;
    b.asset("dc", HQ, Some("srv-dc01"), "server", Some("Dell Inc."), [10, 20, 10, 10], [0xd4, 0xae, 0x52], &[53, 88, 135, 445, 3389], Some("Windows"), o(),
        Some(json!({"display_name": "Domain controller", "owner": "IT", "location": "Server room", "criticality": "critical", "serial_number": "7XK2Y13", "asset_tag": "IT-0010", "warranty_expires": d(200)})))?;
    b.asset("erp", HQ, Some("srv-erp"), "server", Some("Dell Inc."), [10, 20, 10, 11], [0xd4, 0xae, 0x53], &[22, 443, 1433], Some("Linux"), o(),
        Some(json!({"display_name": "ERP server", "owner": "Operations", "location": "Server room", "criticality": "critical", "serial_number": "8QN4T93", "asset_tag": "IT-0011"})))?;
    b.asset("p1", HQ, Some("printer-reception"), "printer", Some("HP Inc."), [10, 20, 10, 31], [0x3c, 0xd9, 0x2b], &[9100, 631, 80], None, o(),
        Some(json!({"display_name": "Reception printer", "owner": "Jana Nováková", "location": "Reception", "serial_number": "CNBK7H2201", "asset_tag": "OF-0031", "warranty_expires": d(20)})))?;
    b.banners("p1", &[("banner.http", "Server: Apache/2.4.49 (Unix)")])?;
    b.banners("erp", &[("banner.ssh", "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3")])?;
    b.banners("router", &[("banner.http", "Server: lighttpd/1.4.55")])?;
    b.asset("p2", HQ, Some("printer-hr"), "printer", Some("Brother Industries, Ltd."), [10, 20, 10, 32], [0x00, 0x80, 0x77], &[9100, 515], None, o(),
        Some(json!({"display_name": "HR printer", "owner": "HR", "location": "Office 2.14", "asset_tag": "OF-0032"})))?;
    b.asset("cam1", HQ, Some("cam-entrance"), "camera", Some("Hangzhou Hikvision Digital Technology"), [10, 20, 10, 41], [0xc0, 0x56, 0xe3], &[554, 80, 23], None, o(),
        Some(json!({"display_name": "Entrance camera", "owner": "Facilities", "location": "Main entrance", "criticality": "high", "serial_number": "DS-2CD-118834", "asset_tag": "FA-0041", "tags": ["security"]})))?;
    b.asset("cam2", HQ, Some("cam-warehouse"), "camera", Some("Zhejiang Dahua Technology"), [10, 20, 10, 42], [0x9c, 0x8e, 0xcd], &[554, 80], None, o(),
        Some(json!({"display_name": "Warehouse camera", "owner": "Facilities", "location": "Warehouse", "asset_tag": "FA-0042", "tags": ["security"]})))?;
    b.asset("l1", HQ, Some("lap-anna"), "computer", Some("Dell Inc."), [10, 20, 10, 101], [0xf8, 0xbc, 0x12], &[], Some("Windows"), Opts { first_days: 200, ..o() },
        Some(json!({"display_name": "Anna's laptop", "owner": "Anna Kováčová", "department": "Finance", "location": "Office 2.03", "serial_number": "5CG2110ABC", "asset_tag": "IT-0101", "warranty_expires": d(300)})))?;
    b.asset("l2", HQ, Some("lap-martin"), "computer", Some("LENOVO"), [10, 20, 10, 102], [0x54, 0xe1, 0xad], &[], Some("Windows"), o(),
        Some(json!({"display_name": "Martin's laptop", "owner": "Martin Horváth", "department": "Sales", "location": "Office 2.07", "serial_number": "PF3XYZ12", "asset_tag": "IT-0102"})))?;
    b.asset("d1", HQ, Some("desk-accounting"), "computer", Some("HP Inc."), [10, 20, 10, 110], [0x94, 0x57, 0xa5], &[135, 445, 3389], Some("Windows"), o(),
        Some(json!({"display_name": "Accounting desktop", "owner": "Finance", "department": "Finance", "location": "Office 2.04", "asset_tag": "IT-0110"})))?;
    b.asset("phone", HQ, Some("Janas-iPhone"), "phone", None, [10, 20, 10, 150], [0x3a, 0x11, 0x22], &[], Some("iOS"), Opts { randomized: true, seen_secs: 180, reasons: &["phone +5: name 'Janas-iPhone'", "os iOS +5: name 'Janas-iPhone'"], ..o() },
        Some(json!({"display_name": "Jana's iPhone", "owner": "Jana Nováková"})))?;
    b.asset("tv", HQ, Some("tv-boardroom"), "tv", Some("Samsung Electronics Co.,Ltd"), [10, 20, 10, 60], [0x84, 0x25, 0xdb], &[8001, 9197], None, o(),
        Some(json!({"display_name": "Boardroom TV", "owner": "Facilities", "location": "Boardroom", "asset_tag": "FA-0060"})))?;
    b.asset("speaker", HQ, Some("sonos-lobby"), "smart speaker", Some("Sonos, Inc."), [10, 20, 10, 61], [0xb8, 0xe9, 0x37], &[1400], None, o(),
        Some(json!({"display_name": "Lobby speaker", "location": "Lobby"})))?;
    b.asset("plug", HQ, Some("shelly-plug-1"), "iot", Some("Espressif Inc."), [10, 20, 10, 70], [0xe8, 0xdb, 0x84], &[80], None, o(),
        Some(json!({"display_name": "Coffee machine plug", "location": "Kitchen", "icon": "smart_plug"})))?;
    b.asset("thermo", HQ, Some("thermostat-office"), "thermostat", Some("ecobee Inc."), [10, 20, 10, 71], [0x44, 0x61, 0x32], &[], None, o(),
        Some(json!({"display_name": "Office thermostat", "location": "Floor 2", "icon": "thermostat"})))?;
    // new devices nobody has reviewed yet: they fill the review queue
    b.asset("new1", HQ, None, "unknown", None, [10, 20, 10, 199], [0x9e, 0x12, 0xaa], &[], None, Opts { first_days: 0, seen_secs: 120, randomized: true, reasons: &["phone +1: randomised (private) MAC address"], ..o() }, None)?;
    b.asset("new2", HQ, Some("ESP-4F8A21"), "iot", Some("Espressif Inc."), [10, 20, 10, 198], [0x24, 0x6f, 0x28], &[80], None, Opts { first_days: 0, seen_secs: 300, reasons: &["iot +3: name 'ESP-4F8A21'", "iot +3: vendor Espressif Inc."], ..o() }, None)?;
    b.asset("new3", HQ, Some("DESKTOP-K93LQ2"), "computer", Some("Intel Corporate"), [10, 20, 10, 197], [0xa4, 0xc3, 0xf0], &[445], Some("Windows"), Opts { first_days: 1, seen_secs: 900, reasons: &["computer +4: default Windows name 'DESKTOP-K93LQ2'"], ..o() }, None)?;

    // ------------------------------------------------------------ production hall (OT)
    let plc = |proto| [(proto, true, false)];
    b.asset("plc1", HQ, Some("plc-line1"), "plc", Some("Siemens AG"), [10, 20, 50, 11], [0x00, 0x1b, 0x1b], &[], None, Opts { ot: &plc("s7"), ..o() },
        Some(json!({"display_name": "PLC Line 1", "owner": "Production", "location": "Hall A, cabinet 3", "zone": "Line 1 cell", "purdue_level": "1", "criticality": "critical", "serial_number": "S7-1500-A1123", "asset_tag": "OT-0011", "warranty_expires": d(500)})))?;
    b.asset("plc2", HQ, Some("plc-line2"), "plc", Some("Rockwell Automation"), [10, 20, 50, 12], [0x00, 0x00, 0xbc], &[], None, Opts { ot: &plc("cip"), ..o() },
        Some(json!({"display_name": "PLC Line 2", "owner": "Production", "location": "Hall A, cabinet 5", "zone": "Line 2 cell", "purdue_level": "1", "criticality": "critical", "serial_number": "1756-L83E-77", "asset_tag": "OT-0012"})))?;
    b.asset("plc3", HQ, Some("plc-packaging"), "plc", Some("Schneider Electric"), [10, 20, 50, 13], [0x00, 0x80, 0xf4], &[], None, Opts { ot: &plc("modbus"), ..o() },
        Some(json!({"display_name": "PLC Packaging", "owner": "Production", "location": "Hall B", "zone": "Packaging cell", "purdue_level": "1", "criticality": "high", "asset_tag": "OT-0013"})))?;
    b.asset("hmi1", HQ, Some("hmi-line1"), "hmi", Some("Siemens AG"), [10, 20, 50, 21], [0x08, 0x00, 0x06], &[], None, Opts { ot: &[("s7", false, true)], ..o() },
        Some(json!({"display_name": "HMI Line 1", "owner": "Production", "location": "Hall A", "zone": "Line 1 cell", "purdue_level": "2", "criticality": "high", "asset_tag": "OT-0021"})))?;
    b.asset("hmi2", HQ, Some("hmi-line2"), "hmi", Some("Rockwell Automation"), [10, 20, 50, 22], [0x00, 0x00, 0xbd], &[], None, Opts { ot: &[("cip", false, true)], ..o() },
        Some(json!({"display_name": "HMI Line 2", "owner": "Production", "location": "Hall A", "zone": "Line 2 cell", "purdue_level": "2", "criticality": "high", "asset_tag": "OT-0022"})))?;
    b.asset("ews", HQ, Some("eng-ws"), "engineering workstation", Some("Dell Inc."), [10, 20, 50, 31], [0xd4, 0xae, 0x60], &[445, 3389], Some("Windows"), o(),
        Some(json!({"display_name": "Engineering workstation", "owner": "Engineering", "location": "Control room", "zone": "Supervisory", "purdue_level": "3", "criticality": "high", "asset_tag": "OT-0031", "type_override": "engineering workstation"})))?;
    b.asset("scada", HQ, Some("scada-srv"), "scada server", Some("Dell Inc."), [10, 20, 50, 32], [0xd4, 0xae, 0x61], &[443, 3389, 4840], Some("Windows"), Opts { ot: &[("opcua", true, true), ("modbus", false, true), ("dnp3", false, true)], ..o() },
        Some(json!({"display_name": "SCADA server", "owner": "Engineering", "location": "Control room", "zone": "Supervisory", "purdue_level": "3", "criticality": "critical", "asset_tag": "OT-0032", "type_override": "scada server"})))?;
    b.asset("hist", HQ, Some("historian"), "historian", Some("Dell Inc."), [10, 20, 50, 33], [0xd4, 0xae, 0x62], &[1433, 443], Some("Windows"), o(),
        Some(json!({"display_name": "Process historian", "owner": "Engineering", "location": "Control room", "zone": "Supervisory", "purdue_level": "3", "criticality": "high", "asset_tag": "OT-0033", "type_override": "historian"})))?;
    b.asset("drive", HQ, Some("drive-conveyor"), "drive", Some("ABB Ltd"), [10, 20, 50, 41], [0x00, 0x1b, 0xc5], &[], None, Opts { ot: &plc("enip"), ..o() },
        Some(json!({"display_name": "Conveyor drive", "owner": "Maintenance", "location": "Hall A", "zone": "Line 1 cell", "purdue_level": "1", "asset_tag": "OT-0041"})))?;
    b.asset("rio", HQ, Some("rio-cell3"), "remote io", Some("WAGO Kontakttechnik"), [10, 20, 50, 42], [0x00, 0x30, 0xde], &[], None, Opts { ot: &plc("modbus"), ..o() },
        Some(json!({"display_name": "Remote I/O cell 3", "owner": "Maintenance", "location": "Hall B", "zone": "Packaging cell", "purdue_level": "0", "asset_tag": "OT-0042", "type_override": "remote io"})))?;
    b.asset("psw", HQ, Some("sw-plant-1"), "industrial switch", Some("Hirschmann Automation and Control GmbH"), [10, 20, 50, 2], [0x00, 0x80, 0x63], &[443], None, o(),
        Some(json!({"display_name": "Plant switch 1", "owner": "Engineering", "location": "Hall A", "purdue_level": "2", "asset_tag": "OT-0002"})))?;
    b.asset("gwp", HQ, Some("gw-plant"), "industrial gateway", Some("Moxa Inc."), [10, 20, 50, 3], [0x00, 0x90, 0xe8], &[443, 22], None, o(),
        Some(json!({"display_name": "Plant gateway", "owner": "Engineering", "location": "Hall A", "purdue_level": "3.5", "asset_tag": "OT-0003", "criticality": "high"})))?;
    b.asset("rtu", HQ, Some("rtu-pump"), "rtu", Some("Emerson"), [10, 20, 50, 51], [0x00, 0x00, 0x4b], &[], None, Opts { ot: &plc("dnp3"), ..o() },
        Some(json!({"display_name": "Pump station RTU", "owner": "Utilities", "location": "Pump station", "zone": "Utilities", "purdue_level": "1", "criticality": "high", "asset_tag": "OT-0051"})))?;
    b.asset("pcam", HQ, Some("cam-hall-a"), "camera", Some("Axis Communications AB"), [10, 20, 50, 61], [0xac, 0xcc, 0x8e], &[554, 80], None, o(),
        Some(json!({"display_name": "Hall A camera", "owner": "Facilities", "location": "Hall A", "asset_tag": "FA-0061"})))?;

    // ------------------------------------------------------------ a device entered by hand
    let mut spare = Asset::new(crate::tracking::synthetic_mac(), now - 40 * DAY);
    spare.agent_id = Some(HQ.into());
    spare.device_type = "computer".into();
    spare.last_seen = 0;
    store.save_asset(&mut spare)?;
    let mut m = AssetMeta::default();
    apply_patch(&mut m, &json!({"display_name": "Spare laptop #2", "status": "spare", "location": "IT cupboard", "serial_number": "PF3ABC99", "asset_tag": "IT-0199"})).map_err(|e| anyhow::anyhow!(e))?;
    (m.manual, m.reviewed, m.demo) = (true, true, true);
    store.save_meta(spare.id, &m, "demo", now - 40 * DAY)?;

    // ------------------------------------------------------------ the branch site
    for (i, (name, ty, vendor, oui, ports, disp)) in [
        ("br-router", "router", "MikroTik", [0x64, 0xd1, 0x54], vec![8291u16, 80], "Branch router"), ("br-ap", "access point", "Ubiquiti Inc", [0x78, 0x8a, 0x20], vec![], "Branch access point"),
        ("br-nas", "nas", "QNAP Systems, Inc.", [0x24, 0x5e, 0xbe], vec![445, 8080], "Branch NAS"), ("br-printer", "printer", "Canon Inc.", [0x00, 0x1e, 0x8f], vec![9100], "Branch printer"),
        ("br-laptop", "computer", "Apple, Inc.", [0xf0, 0x18, 0x98], vec![], "Branch laptop"),
    ].into_iter().enumerate() {
        let key: &'static str = ["b0", "b1", "b2", "b3", "b4"][i];
        b.asset(key, BRANCH, Some(name), ty, Some(vendor), [10, 30, 0, [1, 4, 20, 31, 101][i]], oui, &ports, None, Opts { gateway: ty == "router", ..o() },
            Some(json!({"display_name": disp, "owner": "Branch manager", "location": "Bratislava"})))?;
    }

    // ------------------------------------------------------------ a learned traffic baseline
    let mut base = Baseline::new(b.id("nas"), now - 10 * DAY);
    for (ip, bytes) in [("52.98.10.4", 812_000_000u64), ("142.250.74.14", 96_000_000), ("13.107.42.14", 45_000_000), ("17.253.144.10", 8_000_000)] {
        base.typical_destinations.insert(ip.into(), DestStat { first_seen: now - 10 * DAY, last_seen: now - 600, bytes, bytes_out: bytes * 8 / 10, bytes_in: bytes * 2 / 10 });
    }
    base.typical_ports = [("tcp/443".to_string(), 2600u64), ("udp/443".into(), 900), ("tcp/22".into(), 40)].into();
    base.volume = crate::model::VolumeStats { n: 288, mean: 4_200_000.0, var: (4_200_000.0f64 * 0.3).powi(2) };
    base.active_hours = [2, 1, 1, 1, 2, 4, 40, 120, 220, 240, 230, 210, 190, 230, 240, 235, 200, 120, 40, 20, 10, 6, 4, 3];
    base.buckets = 2880;
    base.updated_at = now - 300;
    store.save_baseline(&base)?;

    // a few more devices' traffic, just enough for the Top talkers leaderboards to show a real
    // spread rather than one bar: the ERP server (mostly received, a nightly backup upstream),
    // the two cameras (upload-heavy: footage leaving toward an NVR outside this segment), two
    // laptops and the domain controller (a mix, dominated by video calls and cloud sync), the
    // boardroom TV (streaming, almost all received) and the reception printer (barely anything:
    // firmware check-ins)
    for (key, dests) in [
        ("erp", vec![("52.98.10.4", 41_000_000u64, 260_000_000u64), ("13.107.42.14", 22_000_000, 3_000_000)]),
        ("cam1", vec![("10.20.90.5", 480_000_000, 2_000_000)]),
        ("cam2", vec![("10.20.90.5", 410_000_000, 2_000_000)]),
        ("l1", vec![("142.250.74.14", 38_000_000, 61_000_000), ("52.98.10.4", 5_000_000, 9_000_000)]),
        ("l2", vec![("142.250.74.14", 21_000_000, 34_000_000), ("13.107.42.14", 4_000_000, 6_000_000)]),
        ("dc", vec![("52.98.10.4", 9_000_000, 51_000_000)]),
        ("tv", vec![("17.253.144.10", 3_000_000, 190_000_000)]),
        ("p1", vec![("13.107.42.14", 400_000, 900_000)]),
    ] {
        let mut b2 = Baseline::new(b.id(key), now - 6 * DAY);
        for (ip, out, inb) in dests {
            b2.typical_destinations.insert(ip.into(), DestStat { first_seen: now - 6 * DAY, last_seen: now - 600, bytes: out + inb, bytes_out: out, bytes_in: inb });
        }
        b2.buckets = 1728;
        b2.updated_at = now - 300;
        store.save_baseline(&b2)?;
    }

    // ------------------------------------------------------------ alerts
    let mut events = 0usize;
    let mut ev = |kind: &str, asset: &str, score: i32, ago_min: i64, summary: &str, reasons: &[&str], acked: bool, extra: Value| -> Result<()> {
        let mut details = json!({"summary": summary, "reasons": reasons});
        if let (Some(d), Some(x)) = (details.as_object_mut(), extra.as_object()) {
            d.extend(x.clone());
        }
        let mut e = Event { id: 0, agent_id: Some(HQ.into()), asset_id: b.id(asset), kind: kind.into(), timestamp: now - ago_min * 60, severity: crate::detect::severity_for(score, 30).into(), score, acked, raw_details: details };
        store.insert_event(&mut e)?;
        events += 1;
        Ok(())
    };
    ev("ot_control_command", "plc2", 95, 25, "Engineering workstation sent PLC stop (0x29) to PLC Line 2 (enip)", &["+85 PLC stop: first time this device has done so to this target", "+10 the target is an industrial controller/device"], false, json!({"command": "PLC stop"}))?;
    ev("arp_conflict", "l2", 70, 55, "02:00:5e:10:00:77 claimed 10.20.10.1 while Core router was still using it", &["+70 02:00:5e:10:00:77 claimed 10.20.10.1 while Core router was still using it", "+25 the contested address is the default gateway (classic man-in-the-middle position)"], false, json!({}))?;
    ev("rogue_dhcp", "new2", 70, 90, "New DHCP server: ESP-4F8A21 (10.20.10.198) is handing out addresses", &["+70 ESP-4F8A21 started answering DHCP requests, and was not doing so during the learning period"], false, json!({}))?;
    ev("threat_list_match", "cam1", 95, 140, "Entrance camera contacted known-bad address 185.220.101.7 (tcp port 4444)", &["+85 Entrance camera contacted 185.220.101.7, which is on your threat list", "+10 it sent 240 kB to it in one window"], false, json!({"remote": "185.220.101.7"}))?;
    ev("new_device", "new1", 75, 118, "New device: unidentified, private MAC address (10.20.10.199)", &["+50 a device not seen before joined the network", "+15 the device type could not be identified", "+10 manufacturer not in the IEEE registry", "-15 private MAC address (typical of phones/laptops rejoining)"], false, json!({}))?;
    ev("new_device_burst", "new3", 58, 180, "6 new devices joined within 10 minutes", &["+58 6 devices appeared within 10 minutes (at least 5 is unusual)"], false, json!({}))?;
    ev("volume_anomaly", "nas", 60, 300, "Finance file server sent 640 MB to the outside in 5 minutes (normal: 4 MB)", &["+40 z-score 9.3 against this device's own baseline", "+20 unusual hours"], false, json!({}))?;
    ev("new_port", "d1", 55, 420, "Accounting desktop used port 22 for the first time", &["+40 a service port this device has never used", "+15 remote-administration port"], false, json!({}))?;
    ev("ot_unexpected_writer", "plc3", 80, 600, "camera Hall A camera wrote to PLC Packaging over modbus", &["+65 Hall A camera is a camera, not an engineering or operator station, yet it sent write/control commands", "+15 including control commands (stop/start/download)"], false, json!({}))?;
    ev("ot_purdue_skip", "plc1", 65, 800, "Accounting desktop (L4) ↔ PLC Line 1 (L1) skip a level over s7", &["+50 Accounting desktop (Purdue level 4) talks directly to PLC Line 1 (level 1): 3 levels apart", "+15 the conversation includes write or control commands"], false, json!({}))?;
    ev("device_silent", "rtu", 60, 1300, "Pump station RTU has not been seen for 3 h (it is normally always online)", &["+45 a device that was online 98% of the past week is silent", "+15 an RTU", "+10 it was essentially never offline"], true, json!({}))?;
    ev("unusual_hours", "l1", 42, 2000, "Anna's laptop was active at 03:00, an hour it is almost never active in", &["+30 activity in an hour holding 0.4% of its history"], true, json!({}))?;
    ev("new_destination", "cam2", 48, 2600, "Warehouse camera contacted 203.0.113.44 for the first time", &["+35 first contact", "+15 no other device uses that address"], true, json!({}))?;

    // ------------------------------------------------------------ the OT communications matrix
    let mut convs = Vec::new();
    let mut conv = |c: &str, s: &str, proto: &str, port: u16, reads: i64, writes: i64, controls: i64, note: Option<&str>, first_days: i64| {
        convs.push(Conversation {
            client_id: b.id(c), server_id: b.id(s), proto: proto.into(), port, first_seen: now - first_days * DAY, last_seen: now - 40, packets: (reads + writes + controls) * 40,
            bytes: (reads + writes + controls) * 900, reads, writes, controls, note: note.map(String::from),
            commands: {
                // the functions a path of this protocol typically uses, so the Commands column and the watches have something to show
                let (read, write) = match proto {
                    "s7" => ("read variable (0x04)", "write variable (0x05)"),
                    "cip" | "enip" => ("CIP read (service 0x4c)", "CIP write (service 0x4d)"),
                    "modbus" => ("read holding registers (3)", "write multiple registers (16)"),
                    "dnp3" => ("read (1)", "write (2)"),
                    _ => ("read", "write"),
                };
                let mut m = std::collections::BTreeMap::new();
                if reads > 0 && proto != "opcua" {
                    m.insert(read.to_string(), reads);
                }
                if writes > 0 {
                    m.insert(write.to_string(), writes);
                }
                if let (Some(n), true) = (note, controls > 0) {
                    m.insert(n.to_string(), controls);
                }
                m
            },
        });
    };
    conv("hmi1", "plc1", "s7", 102, 850_000, 1_200, 0, None, 25);
    conv("hmi2", "plc2", "enip", 44818, 620_000, 800, 0, None, 25);
    conv("scada", "plc3", "modbus", 502, 1_400_000, 3_100, 0, None, 25);
    conv("scada", "rio", "modbus", 502, 900_000, 2_000, 0, None, 25);
    conv("scada", "rtu", "dnp3", 20000, 300_000, 450, 0, None, 25);
    conv("hist", "scada", "opcua", 4840, 2_300_000, 0, 0, None, 25);
    conv("hmi1", "drive", "enip", 44818, 120_000, 40, 0, None, 25);
    conv("ews", "plc1", "s7", 102, 4_000, 60, 3, Some("program download (0x1A)"), 25);
    conv("ews", "plc2", "enip", 44818, 300, 20, 1, Some("PLC stop (0x29)"), 1);
    conv("d1", "plc1", "s7", 102, 40, 18, 0, None, 1);
    conv("pcam", "plc3", "modbus", 502, 0, 12, 4, Some("write single coil"), 1);
    store.save_conversations(&convs)?;

    // ------------------------------------------------------------ three days of trends (deterministic)
    let mut metrics = Vec::new();
    let mut x = 12_345u64; // small LCG: the same pretty curves every time
    let mut rnd = || {
        x = x.wrapping_mul(6_364_136_223_846_793_221).wrapping_add(1_442_695_040_888_963_407);
        (x >> 33) as f64 / (1u64 << 31) as f64
    };
    for i in 0..72 * 12 {
        let ts = (now - i * 300) / 300 * 300;
        let hour = (ts / HOUR) % 24;
        let day = if (5..=18).contains(&hour) { 0.35 + 0.65 * (((hour - 5) as f64) / 13.0 * std::f64::consts::PI).sin().max(0.0) } else { 0.25 };
        let out = ((2.5e6 + 30e6 * day) * (0.7 + 0.6 * rnd())) as i64 * if i == 60 { 8 } else { 1 };
        let inn = (out as f64 * (2.5 + 1.5 * rnd())) as i64;
        metrics.push(Metric { ts, agent_id: HQ.into(), devices_total: 44, devices_online: (34.0 + 8.0 * day) as i64 + (rnd() * 2.0) as i64 - 1, bytes_out: out, bytes_in: inn, alerts: (rnd() < 0.04) as i64 });
        metrics.push(Metric { ts, agent_id: BRANCH.into(), devices_total: 5, devices_online: if (6..20).contains(&hour) { 5 } else { 4 }, bytes_out: out / 12, bytes_in: inn / 12, alerts: 0 });
    }
    store.insert_metrics(&metrics)?;

    // ------------------------------------------------------------ one accepted risk, so the Findings page shows how they look
    store.add_risk_acceptance(&crate::model::RiskAcceptance {
        id: 0, finding_id: "rdp_open".into(), asset_id: b.id("dc"),
        reason: "Remote Desktop is only reachable from the management VLAN through the jump host; the vendor needs it for maintenance. Reviewed with IT security.".into(),
        accepted_by: "admin".into(), accepted_at: now - 12 * DAY, expires_at: Some(now + 78 * DAY), revoked_at: None, revoked_by: None,
    })?;

    Ok(Loaded { assets: b.ids.len() + 1, events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AdminStore;
    use crate::store::AssetStore;
    use crate::store::AuthStore;
    use crate::store::EventStore;
    use crate::store::MetricStore;
    use crate::store::SettingsStore;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn demo_data_loads_once_is_complete_and_removes_cleanly_without_touching_real_data() {
        let s = SqliteStore::open_in_memory().unwrap();
        let now = 1_800_000_000;
        // a real device that must survive
        let mut real = Asset::new(Mac([0x00, 0x11, 0x22, 3, 3, 3]), now - 100);
        real.last_seen = now;
        s.save_asset(&mut real).unwrap();
        s.set_setting("branding", b"{}", 1).unwrap();
        s.add_audit(now, "anna", "auth.login", None, &json!({})).unwrap();

        assert!(!is_loaded(&s).unwrap());
        let l = load(&s, now).unwrap();
        assert!(l.assets == 42 && l.events == 13, "{l:?}");
        assert!(is_loaded(&s).unwrap());
        assert!(load(&s, now).is_err(), "loading twice is refused");
        // it feeds every screen
        let metas = s.load_all_meta().unwrap();
        assert!(metas.values().filter(|m| m.demo).count() == 42);
        assert!(!s.list_conversations().unwrap().is_empty() && !s.list_metrics(0, i64::MAX, None).unwrap().is_empty());
        assert_eq!(s.list_agents().unwrap().len(), 2);
        assert_eq!(metas.values().filter(|m| m.demo && !m.reviewed).count(), 3, "three devices wait in the review queue");
        // the collector and detector do not see demo devices
        let seen: Vec<_> = crate::store::real_assets(&s).unwrap().into_iter().map(|a| a.id).collect();
        assert_eq!(seen, vec![real.id]);
        // findings and compliance can be computed from it
        let assets = s.load_assets().unwrap();
        let f = crate::findings::compute(&assets, &metas, now);
        assert!(!f.is_empty());
        // the demo shows what software versions can reveal: a known-exploited range and a version past its support
        assert!(f.iter().any(|x| x.id == "kev_software" && !x.evidence.is_empty()) && f.iter().any(|x| x.id == "eol_software" && !x.evidence.is_empty()), "{f:?}");

        assert_eq!(remove(&s).unwrap(), 42);
        assert!(!is_loaded(&s).unwrap());
        assert_eq!(s.load_assets().unwrap().len(), 1, "only the real device is left");
        assert!(s.list_agents().unwrap().is_empty());
        assert!(s.list_metrics(0, i64::MAX, None).unwrap().is_empty());
        assert!(s.list_conversations().unwrap().is_empty());
        assert!(s.list_events(&crate::store::EventQuery { limit: 100, ..Default::default() }).unwrap().is_empty());
        assert_eq!(s.get_setting("branding").unwrap().as_deref(), Some(&b"{}"[..]), "settings untouched");
        assert_eq!(s.list_audit(None, 10).unwrap().len(), 1, "the audit log is untouched");
        // and it can be loaded again
        load(&s, now).unwrap();
    }

    #[test]
    fn erasing_the_inventory_keeps_users_settings_and_the_audit_log() {
        let s = SqliteStore::open_in_memory().unwrap();
        load(&s, 1_800_000_000).unwrap();
        s.create_user("anna", "hash", "admin", false, 1).unwrap();
        s.set_setting("channels", b"[]", 1).unwrap();
        s.set_setting("dhcp_servers", b"[]", 1).unwrap();
        s.add_audit(1, "anna", "x", None, &json!({})).unwrap();
        s.erase_inventory().unwrap();
        assert!(s.load_assets().unwrap().is_empty() && s.list_agents().unwrap().is_empty());
        assert!(s.load_all_meta().unwrap().is_empty() && s.list_conversations().unwrap().is_empty());
        assert!(s.list_metrics(0, i64::MAX, None).unwrap().is_empty() && s.load_baselines().unwrap().is_empty());
        assert_eq!(s.list_users().unwrap().len(), 1);
        assert!(s.get_setting("channels").unwrap().is_some() && s.get_setting("dhcp_servers").unwrap().is_none());
        assert_eq!(s.list_audit(None, 10).unwrap().len(), 1);
    }
}
