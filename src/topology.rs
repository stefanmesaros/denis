//! The physical network: what switches say about themselves and their neighbours, read over SNMP (v2c).
//!
//! For each switch an administrator adds, DENIS reads (read-only, never SET):
//! * **IF-MIB**: the ports (name, alias, up/down, speed);
//! * **LLDP-MIB** (`lldpRemTable`): which device each port sees on the other end of the cable, as that device
//!   announces itself (chassis, port, name, description): switch-to-switch links and access points;
//! * **Q-BRIDGE-MIB / BRIDGE-MIB** (the forwarding table): which MAC address was learned on which port,
//!   i.e. what is plugged in where.
//!
//! [`build`] then joins that with the device register: a device is "connected to" the port where its MAC is
//! learned, preferring an access port over an uplink (a port that leads to another polled switch, or that has
//! very many MACs behind it, only says "somewhere further down").

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Asset, Mac};
use crate::snmp::{oid, Client, Oid, Value};

/// More MACs than this behind one port and it is treated as an uplink even without an LLDP neighbour.
const UPLINK_MACS: usize = 24;
/// What one switch may contribute (a hostile or huge device cannot fill the database).
const MAX_FDB: usize = 20_000;
const MAX_LLDP: usize = 1_000;
const MAX_PORTS: usize = 2_000;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Port {
    pub index: u32,
    pub name: String,
    pub alias: String,
    pub up: Option<bool>,
    pub speed_mbps: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Neighbor {
    /// The port of *this* switch the neighbour is seen on.
    pub local_port: String,
    /// The neighbour's chassis: a MAC address when it announced one, else what it said.
    pub chassis: String,
    pub port: String,
    pub port_desc: String,
    pub sys_name: String,
    pub sys_desc: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FdbEntry {
    pub mac: Mac,
    pub port: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub sys_name: String,
    pub sys_descr: String,
    /// The switch's own chassis MAC (LLDP), if it says.
    pub chassis: String,
    pub polled_at: i64,
    pub ports: Vec<Port>,
    pub lldp: Vec<Neighbor>,
    pub fdb: Vec<FdbEntry>,
}

// ------------------------------------------------------------------------------------------ reading

fn suffix<'a>(name: &'a [u32], prefix: &[u32]) -> Option<&'a [u32]> {
    name.strip_prefix(prefix)
}

fn mac_text(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

/// Walk a column; a failure or an empty column is "not offered", not an error (switches differ in what they implement).
async fn column(c: &mut Client, prefix: &str) -> Vec<(Oid, Value)> {
    c.walk(&oid(prefix)).await.unwrap_or_default()
}

/// Read one switch. Fails only when the switch does not answer at all.
pub async fn poll(addr: SocketAddr, community: &str, timeout: Duration, now: i64) -> Result<Snapshot> {
    let mut c = Client::new(addr, community, timeout).await?;
    let sys = c.get(&[oid("1.3.6.1.2.1.1.1.0"), oid("1.3.6.1.2.1.1.5.0"), oid("1.0.8802.1.1.2.1.3.2.0")]).await?;
    let text = |i: usize| sys.get(i).and_then(|(_, v)| v.as_str()).unwrap_or_default();
    let mut snap = Snapshot { sys_descr: text(0), sys_name: text(1), polled_at: now, ..Default::default() };
    if let Some((_, Value::Str(b))) = sys.get(2) {
        snap.chassis = if b.len() == 6 { mac_text(b) } else { crate::snmp::printable(b) };
    }
    if sys.iter().all(|(_, v)| v.is_missing()) {
        bail!("the device answered but does not look like a managed switch (nothing under system)");
    }

    // ---- ports (IF-MIB)
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    for (n, v) in column(&mut c, "1.3.6.1.2.1.31.1.1.1.1").await {
        if let (Some(&i), Some(s)) = (n.last(), v.as_str()) {
            names.insert(i, s);
        }
    }
    if names.is_empty() {
        for (n, v) in column(&mut c, "1.3.6.1.2.1.2.2.1.2").await {
            if let (Some(&i), Some(s)) = (n.last(), v.as_str()) {
                names.insert(i, s);
            }
        }
    }
    let by_index = |rows: Vec<(Oid, Value)>| -> HashMap<u32, Value> { rows.into_iter().filter_map(|(n, v)| Some((*n.last()?, v))).collect() };
    let alias = by_index(column(&mut c, "1.3.6.1.2.1.31.1.1.1.18").await);
    let oper = by_index(column(&mut c, "1.3.6.1.2.1.2.2.1.8").await);
    let speed = by_index(column(&mut c, "1.3.6.1.2.1.31.1.1.1.15").await);
    for (i, name) in names.iter().take(MAX_PORTS) {
        snap.ports.push(Port {
            index: *i,
            name: name.clone(),
            alias: alias.get(i).and_then(Value::as_str).unwrap_or_default(),
            up: oper.get(i).and_then(Value::as_i64).map(|s| s == 1),
            speed_mbps: speed.get(i).and_then(Value::as_i64).filter(|s| *s > 0).map(|s| s as u64),
        });
    }
    let port_name = |ifindex: u32| names.get(&ifindex).cloned().unwrap_or_else(|| format!("port {ifindex}"));

    // ---- what each switch port sees on the other end (LLDP-MIB)
    let mut loc_desc: HashMap<u32, String> = HashMap::new();
    for (n, v) in column(&mut c, "1.0.8802.1.1.2.1.3.7.1.4").await {
        if let (Some(&i), Some(s)) = (n.last(), v.as_str()) {
            loc_desc.insert(i, s);
        }
    }
    let rem = "1.0.8802.1.1.2.1.4.1.1";
    let mut rows: BTreeMap<(u32, u32, u32), Neighbor> = BTreeMap::new();
    let mut chassis_subtype: HashMap<(u32, u32, u32), i64> = HashMap::new();
    let mut port_subtype: HashMap<(u32, u32, u32), i64> = HashMap::new();
    for col in [4u32, 5, 6, 7, 8, 9, 10] {
        let prefix: Vec<u32> = oid(rem).into_iter().chain([col]).collect();
        for (n, v) in column(&mut c, &format!("{rem}.{col}")).await {
            let Some(rest) = suffix(&n, &prefix) else { continue };
            let [time_mark, local, idx] = rest else { continue };
            let key = (*time_mark, *local, *idx);
            if rows.len() >= MAX_LLDP && !rows.contains_key(&key) {
                continue;
            }
            let local_name = loc_desc.get(local).cloned().filter(|s| !s.is_empty()).unwrap_or_else(|| port_name(*local));
            let e = rows.entry(key).or_insert_with(|| Neighbor { local_port: local_name, ..Default::default() });
            match col {
                4 => { chassis_subtype.insert(key, v.as_i64().unwrap_or(0)); }
                6 => { port_subtype.insert(key, v.as_i64().unwrap_or(0)); }
                5 => e.chassis = v.as_bytes().map(|b| if chassis_subtype.get(&key) == Some(&4) || b.len() == 6 { mac_text(b) } else { crate::snmp::printable(b) }).unwrap_or_default(),
                7 => e.port = v.as_bytes().map(|b| if port_subtype.get(&key) == Some(&3) { mac_text(b) } else { crate::snmp::printable(b) }).unwrap_or_default(),
                8 => e.port_desc = v.as_str().unwrap_or_default(),
                9 => e.sys_name = v.as_str().unwrap_or_default(),
                _ => e.sys_desc = v.as_str().unwrap_or_default(),
            }
        }
    }
    snap.lldp = rows.into_values().collect();

    // ---- what is learned where (Q-BRIDGE-MIB, else BRIDGE-MIB)
    let mut bridge_ifindex: HashMap<u32, u32> = HashMap::new();
    for (n, v) in column(&mut c, "1.3.6.1.2.1.17.1.4.1.2").await {
        if let (Some(&bp), Some(i)) = (n.last(), v.as_i64()) {
            bridge_ifindex.insert(bp, i as u32);
        }
    }
    let mut fdb: Vec<(Mac, u32)> = Vec::new();
    let q = column(&mut c, "1.3.6.1.2.1.17.7.1.2.2.1.2").await;
    let (rows, skip) = if q.is_empty() { (column(&mut c, "1.3.6.1.2.1.17.4.3.1.2").await, oid("1.3.6.1.2.1.17.4.3.1.2").len()) } else { (q, oid("1.3.6.1.2.1.17.7.1.2.2.1.2").len() + 1) };
    for (n, v) in rows {
        // the index ends in the six bytes of the MAC (Q-BRIDGE puts the VLAN in front of them)
        if n.len() < skip + 6 || n.len() > skip + 6 {
            continue;
        }
        let m = &n[n.len() - 6..];
        if m.iter().any(|x| *x > 255) {
            continue;
        }
        let mac = Mac([m[0] as u8, m[1] as u8, m[2] as u8, m[3] as u8, m[4] as u8, m[5] as u8]);
        let Some(bp) = v.as_i64().filter(|p| *p > 0) else { continue }; // port 0 = the switch itself
        if !mac.is_valid() {
            continue;
        }
        fdb.push((mac, bp as u32));
        if fdb.len() >= MAX_FDB {
            break;
        }
    }
    let mut seen: HashSet<(Mac, String)> = HashSet::new();
    for (mac, bp) in fdb {
        let name = port_name(*bridge_ifindex.get(&bp).unwrap_or(&bp));
        if seen.insert((mac, name.clone())) {
            snap.fdb.push(FdbEntry { mac, port: name });
        }
    }
    Ok(snap)
}

// ------------------------------------------------------------------------------------------ joining

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SwitchView {
    pub id: String,
    pub name: String,
    pub address: String,
    pub sys_name: String,
    pub sys_descr: String,
    pub ports_total: usize,
    pub ports_up: usize,
    pub macs: usize,
    pub last_ok: Option<i64>,
    pub error: Option<String>,
    /// Every port IF-MIB reports (name, alias, up/down, speed), whether or not anything was
    /// learned on it — some switches (cheap "smart" models especially) answer IF-MIB fully but
    /// do not implement the forwarding table at all, so this is worth showing on its own.
    pub ports: Vec<Port>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Link {
    pub a_switch: String,
    pub a_port: String,
    /// The switch at the other end when it is one of ours, else `None` and `remote_name` says what it announced.
    pub b_switch: Option<String>,
    pub b_port: String,
    pub remote_name: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Attachment {
    pub switch: String,
    pub port: String,
    pub port_alias: String,
    pub mac: String,
    pub asset_id: Option<i64>,
    /// `fdb` (its MAC was learned on the port) or `lldp` (it announced itself on the port).
    pub via: &'static str,
    /// What it announced, for `lldp`.
    pub name: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Default)]
pub struct Topology {
    pub switches: Vec<SwitchView>,
    pub links: Vec<Link>,
    pub attachments: Vec<Attachment>,
    /// MACs seen on access ports that are not (yet) in the register.
    pub unknown_macs: usize,
}

/// One polled switch as stored.
pub struct Polled {
    pub id: String,
    pub name: String,
    pub address: String,
    pub last_ok: Option<i64>,
    pub error: Option<String>,
    pub snapshot: Option<Snapshot>,
}

pub fn build(polled: &[Polled], assets: &[Asset]) -> Topology {
    let by_mac: HashMap<Mac, i64> = assets.iter().map(|a| (a.mac, a.id)).collect();
    let mut topo = Topology::default();

    // who is who: a switch is known by its LLDP chassis MAC and by its system name
    let mut chassis_owner: HashMap<String, &str> = HashMap::new();
    let mut name_owner: HashMap<String, &str> = HashMap::new();
    for p in polled {
        if let Some(s) = &p.snapshot {
            if !s.chassis.is_empty() {
                chassis_owner.insert(s.chassis.to_lowercase(), &p.id);
            }
            if !s.sys_name.is_empty() {
                name_owner.insert(s.sys_name.to_lowercase(), &p.id);
            }
        }
    }
    let neighbour_switch = |n: &Neighbor| -> Option<&str> {
        chassis_owner.get(&n.chassis.to_lowercase()).or_else(|| (!n.sys_name.is_empty()).then(|| name_owner.get(&n.sys_name.to_lowercase())).flatten()).copied()
    };

    // ports that lead to another of our switches: what they learn is "somewhere further down"
    let mut uplinks: HashSet<(&str, &str)> = HashSet::new();
    let mut linked: HashSet<((String, String), (String, String))> = HashSet::new();
    for p in polled {
        let Some(s) = &p.snapshot else { continue };
        for n in &s.lldp {
            if let Some(other) = neighbour_switch(n).filter(|o| *o != p.id) {
                uplinks.insert((&p.id, &n.local_port));
                let (a, b) = ((p.id.clone(), n.local_port.clone()), (other.to_string(), n.port.clone()));
                // one link per cable: both ends report it
                let key = if a <= b { (a.clone(), b.clone()) } else { (b.clone(), a.clone()) };
                if linked.insert(key) {
                    topo.links.push(Link { a_switch: a.0, a_port: a.1, b_switch: Some(b.0), b_port: b.1, remote_name: n.sys_name.clone() });
                }
            }
        }
    }

    // MACs per port, to tell an access port from a trunk
    let mut per_port: HashMap<(&str, &str), usize> = HashMap::new();
    for p in polled {
        if let Some(s) = &p.snapshot {
            for e in &s.fdb {
                *per_port.entry((&p.id, &e.port)).or_default() += 1;
            }
        }
    }
    let own: HashSet<Mac> = polled.iter().filter_map(|p| p.snapshot.as_ref()).filter_map(|s| s.chassis.parse::<Mac>().ok()).collect();

    // the best place for each MAC: the port with the fewest others behind it, never an uplink
    let mut best: HashMap<Mac, (usize, &str, &str)> = HashMap::new();
    for p in polled {
        let Some(s) = &p.snapshot else { continue };
        for e in &s.fdb {
            let n = per_port[&(p.id.as_str(), e.port.as_str())];
            if uplinks.contains(&(p.id.as_str(), e.port.as_str())) || n > UPLINK_MACS || own.contains(&e.mac) {
                continue;
            }
            if best.get(&e.mac).is_none_or(|(bn, _, _)| n < *bn) {
                best.insert(e.mac, (n, &p.id, &e.port));
            }
        }
    }
    let alias = |sw: &str, port: &str| -> String {
        polled.iter().find(|p| p.id == sw).and_then(|p| p.snapshot.as_ref()).and_then(|s| s.ports.iter().find(|x| x.name == port)).map(|x| x.alias.clone()).unwrap_or_default()
    };
    let mut announced: HashSet<Mac> = HashSet::new();
    for p in polled {
        let Some(s) = &p.snapshot else { continue };
        for n in &s.lldp {
            if neighbour_switch(n).is_some() {
                continue;
            }
            let mac = n.chassis.parse::<Mac>().ok();
            topo.links.push(Link { a_switch: p.id.clone(), a_port: n.local_port.clone(), b_switch: None, b_port: n.port.clone(), remote_name: if n.sys_name.is_empty() { n.chassis.clone() } else { n.sys_name.clone() } });
            topo.attachments.push(Attachment {
                switch: p.id.clone(), port: n.local_port.clone(), port_alias: alias(&p.id, &n.local_port), mac: n.chassis.clone(),
                asset_id: mac.and_then(|m| by_mac.get(&m).copied()), via: "lldp", name: n.sys_name.clone(),
            });
            if let Some(m) = mac {
                announced.insert(m);
            }
        }
    }
    let mut unknown = 0;
    let mut placed: Vec<(Mac, &str, &str)> = best.iter().map(|(m, (_, s, p))| (*m, *s, *p)).collect();
    placed.sort();
    for (mac, sw, port) in placed {
        if announced.contains(&mac) {
            continue; // already shown with what it said about itself
        }
        match by_mac.get(&mac) {
            Some(id) => topo.attachments.push(Attachment { switch: sw.into(), port: port.into(), port_alias: alias(sw, port), mac: mac.to_string(), asset_id: Some(*id), via: "fdb", name: String::new() }),
            None => unknown += 1,
        }
    }
    topo.unknown_macs = unknown;

    for p in polled {
        let s = p.snapshot.as_ref();
        topo.switches.push(SwitchView {
            id: p.id.clone(),
            name: p.name.clone(),
            address: p.address.clone(),
            sys_name: s.map(|s| s.sys_name.clone()).unwrap_or_default(),
            sys_descr: s.map(|s| s.sys_descr.clone()).unwrap_or_default(),
            ports_total: s.map_or(0, |s| s.ports.len()),
            ports_up: s.map_or(0, |s| s.ports.iter().filter(|x| x.up == Some(true)).count()),
            macs: s.map_or(0, |s| s.fdb.len()),
            last_ok: p.last_ok,
            error: p.error.clone(),
            ports: s.map(|s| s.ports.clone()).unwrap_or_default(),
        });
    }
    topo
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snmp::agent;

    fn s(v: &str) -> Value {
        Value::Str(v.as_bytes().to_vec())
    }

    /// A switch with `ports` named Gi1/0/N, LLDP neighbours `(local ifIndex, chassis mac bytes, port id, sysname)` and
    /// forwarding entries `(mac, ifIndex)` (learned through the bridge-port map: bridge port = ifIndex + 100).
    fn switch_mib(name: &str, chassis: [u8; 6], ports: u32, lldp: &[(u32, [u8; 6], &str, &str)], fdb: &[([u8; 6], u32)]) -> BTreeMap<Oid, Value> {
        let mut t = BTreeMap::new();
        let mut put = |k: String, v: Value| { t.insert(oid(&k), v); };
        put("1.3.6.1.2.1.1.1.0".into(), s(&format!("Acme managed switch {name}")));
        put("1.3.6.1.2.1.1.5.0".into(), s(name));
        put("1.0.8802.1.1.2.1.3.2.0".into(), Value::Str(chassis.to_vec()));
        for i in 1..=ports {
            put(format!("1.3.6.1.2.1.31.1.1.1.1.{i}"), s(&format!("Gi1/0/{i}")));
            put(format!("1.3.6.1.2.1.31.1.1.1.18.{i}"), s(if i == 1 { "uplink to core" } else { "" }));
            put(format!("1.3.6.1.2.1.2.2.1.8.{i}"), Value::Int(if i <= 2 { 1 } else { 2 }));
            put(format!("1.3.6.1.2.1.31.1.1.1.15.{i}"), Value::Uint(1000));
            put(format!("1.3.6.1.2.1.17.1.4.1.2.{}", 100 + i), Value::Int(i as i64));
            put(format!("1.0.8802.1.1.2.1.3.7.1.4.{i}"), s(&format!("Gi1/0/{i}")));
        }
        for (i, (local, mac, port, sysname)) in lldp.iter().enumerate() {
            let idx = format!("{}.{}.{}", 5000 + i, local, 1);
            put(format!("1.0.8802.1.1.2.1.4.1.1.4.{idx}"), Value::Int(4));
            put(format!("1.0.8802.1.1.2.1.4.1.1.5.{idx}"), Value::Str(mac.to_vec()));
            put(format!("1.0.8802.1.1.2.1.4.1.1.6.{idx}"), Value::Int(5));
            put(format!("1.0.8802.1.1.2.1.4.1.1.7.{idx}"), s(port));
            put(format!("1.0.8802.1.1.2.1.4.1.1.9.{idx}"), s(sysname));
        }
        for (mac, ifindex) in fdb {
            let m = mac.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(".");
            put(format!("1.3.6.1.2.1.17.7.1.2.2.1.2.1.{m}"), Value::Int(100 + *ifindex as i64));
        }
        t
    }

    #[tokio::test]
    async fn a_switch_is_read_port_by_port_with_its_neighbours_and_forwarding_table() {
        let core = [0x00, 0x1b, 0x63, 0, 0, 1];
        let mib = switch_mib("access-1", [0x00, 0x1b, 0x63, 0, 0, 2], 4, &[(1, core, "Gi0/24", "core-sw")], &[([0xaa, 0, 0, 0, 0, 1], 3), ([0xaa, 0, 0, 0, 0, 2], 1)]);
        let a = agent::start("ro", mib, false);
        let snap = poll(a.addr, "ro", Duration::from_millis(500), 1000).await.unwrap();
        assert_eq!((snap.sys_name.as_str(), snap.chassis.as_str()), ("access-1", "00:1b:63:00:00:02"));
        assert_eq!(snap.ports.len(), 4);
        assert_eq!((snap.ports[0].name.as_str(), snap.ports[0].alias.as_str(), snap.ports[0].up, snap.ports[0].speed_mbps), ("Gi1/0/1", "uplink to core", Some(true), Some(1000)));
        assert_eq!(snap.ports[3].up, Some(false));
        assert_eq!(snap.lldp, vec![Neighbor { local_port: "Gi1/0/1".into(), chassis: "00:1b:63:00:00:01".into(), port: "Gi0/24".into(), port_desc: String::new(), sys_name: "core-sw".into(), sys_desc: String::new() }]);
        let mut fdb: Vec<(String, String)> = snap.fdb.iter().map(|e| (e.mac.to_string(), e.port.clone())).collect();
        fdb.sort();
        assert_eq!(fdb, vec![("aa:00:00:00:00:01".to_string(), "Gi1/0/3".to_string()), ("aa:00:00:00:00:02".to_string(), "Gi1/0/1".to_string())], "bridge ports are mapped to interface names");
    }

    #[tokio::test]
    async fn the_older_bridge_table_is_used_when_there_is_no_q_bridge_one_and_a_silent_device_is_an_error() {
        let mut mib = switch_mib("old-sw", [0, 1, 2, 3, 4, 5], 2, &[], &[]);
        mib.insert(oid("1.3.6.1.2.1.17.4.3.1.2.170.0.0.0.0.9"), Value::Int(102));
        mib.insert(oid("1.3.6.1.2.1.17.4.3.1.2.170.0.0.0.0.10"), Value::Int(0)); // the switch's own
        let a = agent::start("ro", mib, true); // and no GETBULK either
        let snap = poll(a.addr, "ro", Duration::from_millis(500), 1).await.unwrap();
        assert_eq!(snap.fdb, vec![FdbEntry { mac: "aa:00:00:00:00:09".parse().unwrap(), port: "Gi1/0/2".into() }]);
        let e = poll(a.addr, "wrong", Duration::from_millis(100), 1).await.unwrap_err().to_string();
        assert!(e.contains("no answer"), "{e}");
        let empty = agent::start("ro", BTreeMap::new(), false);
        assert!(poll(empty.addr, "ro", Duration::from_millis(300), 1).await.unwrap_err().to_string().contains("does not look like a managed switch"));
    }

    fn snapshot(name: &str, chassis: &str, lldp: Vec<Neighbor>, fdb: &[(&str, &str)]) -> Snapshot {
        Snapshot {
            sys_name: name.into(), chassis: chassis.into(), polled_at: 1,
            ports: (1..=24).map(|i| Port { index: i, name: format!("Gi1/0/{i}"), ..Default::default() }).collect(),
            lldp,
            fdb: fdb.iter().map(|(m, p)| FdbEntry { mac: m.parse().unwrap(), port: (*p).into() }).collect(),
            ..Default::default()
        }
    }

    fn polled(id: &str, snap: Snapshot) -> Polled {
        Polled { id: id.into(), name: id.into(), address: "10.0.0.1".into(), last_ok: Some(1), error: None, snapshot: Some(snap) }
    }

    fn asset(id: i64, mac: &str) -> Asset {
        let mut a = Asset::new(mac.parse().unwrap(), 0);
        a.id = id;
        a
    }

    fn nb(local: &str, chassis: &str, port: &str, name: &str) -> Neighbor {
        Neighbor { local_port: local.into(), chassis: chassis.into(), port: port.into(), sys_name: name.into(), ..Default::default() }
    }

    #[test]
    fn a_device_is_attached_to_the_access_port_not_the_uplink_and_switch_links_are_found_once() {
        let core = snapshot("core", "00:00:00:00:00:c0", vec![nb("Gi1/0/24", "00:00:00:00:00:a1", "Gi1/0/1", "access")], &[("aa:00:00:00:00:01", "Gi1/0/24"), ("aa:00:00:00:00:02", "Gi1/0/24"), ("aa:00:00:00:00:03", "Gi1/0/7")]);
        let access = snapshot("access", "00:00:00:00:00:a1", vec![nb("Gi1/0/1", "00:00:00:00:00:c0", "Gi1/0/24", "core")], &[("aa:00:00:00:00:01", "Gi1/0/5"), ("aa:00:00:00:00:02", "Gi1/0/6"), ("aa:00:00:00:00:03", "Gi1/0/1"), ("aa:00:00:00:00:99", "Gi1/0/8")]);
        let assets = vec![asset(1, "aa:00:00:00:00:01"), asset(2, "aa:00:00:00:00:02"), asset(3, "aa:00:00:00:00:03")];
        let t = build(&[polled("core", core), polled("access", access)], &assets);
        assert_eq!(t.links.len(), 1, "both switches report the cable, it is one link: {:?}", t.links);
        let l = &t.links[0];
        assert!(l.b_switch.is_some() && [&l.a_switch, l.b_switch.as_ref().unwrap()].contains(&&"core".to_string()));
        let at = |id: i64| t.attachments.iter().find(|a| a.asset_id == Some(id)).unwrap_or_else(|| panic!("no attachment for {id}"));
        assert_eq!((at(1).switch.as_str(), at(1).port.as_str(), at(1).via), ("access", "Gi1/0/5", "fdb"), "not the core's uplink port");
        assert_eq!((at(2).switch.as_str(), at(2).port.as_str()), ("access", "Gi1/0/6"));
        assert_eq!((at(3).switch.as_str(), at(3).port.as_str()), ("core", "Gi1/0/7"), "device 3 sits on the core itself");
        assert_eq!(t.unknown_macs, 1, "one MAC on an access port is not in the register");
        assert_eq!(t.attachments.len(), 3);
    }

    #[test]
    fn a_port_with_very_many_macs_is_a_trunk_and_an_lldp_neighbour_is_shown_with_what_it_says() {
        let many: Vec<(String, &str)> = (0..30).map(|i| (format!("bb:00:00:00:00:{i:02x}"), "Gi1/0/2")).collect();
        let refs: Vec<(&str, &str)> = many.iter().map(|(m, p)| (m.as_str(), *p)).collect();
        let mut fdb = refs.clone();
        fdb.push(("aa:00:00:00:00:01", "Gi1/0/2")); // also behind the busy port ...
        fdb.push(("aa:00:00:00:00:01", "Gi1/0/9")); // ... but learned on a quiet one too
        let sw = snapshot("sw", "00:00:00:00:00:01", vec![nb("Gi1/0/12", "aa:00:00:00:00:77", "eth0", "ap-hall")], &fdb);
        let assets = vec![asset(1, "aa:00:00:00:00:01"), asset(7, "aa:00:00:00:00:77")];
        let t = build(&[polled("sw", sw)], &assets);
        let a1 = t.attachments.iter().find(|a| a.asset_id == Some(1)).unwrap();
        assert_eq!(a1.port, "Gi1/0/9");
        assert!(t.attachments.iter().all(|a| a.port != "Gi1/0/2"), "nothing is claimed to be on the trunk");
        let ap = t.attachments.iter().find(|a| a.via == "lldp").unwrap();
        assert_eq!((ap.asset_id, ap.name.as_str(), ap.port.as_str()), (Some(7), "ap-hall", "Gi1/0/12"));
        assert!(t.links.iter().any(|l| l.b_switch.is_none() && l.remote_name == "ap-hall"), "an unmanaged neighbour is a link to nowhere we poll");
        assert_eq!(t.unknown_macs, 0, "the 30 unknown MACs are behind the trunk: not counted as plugged in here");
    }

    #[test]
    fn a_switch_that_could_not_be_read_is_listed_with_its_error() {
        let bad = Polled { id: "x".into(), name: "Down".into(), address: "10.0.0.9".into(), last_ok: None, error: Some("no answer from the device".into()), snapshot: None };
        let t = build(&[bad], &[]);
        assert_eq!((t.switches.len(), t.switches[0].error.as_deref(), t.switches[0].ports_total), (1, Some("no answer from the device"), 0));
        assert!(t.links.is_empty() && t.attachments.is_empty());
    }
}
