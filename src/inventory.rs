//! In-memory asset table: folds `Observation`s into `Asset`s, re-derives the
//! device-type guess, and flushes changes to a `Store`.
//!
//! Assets are keyed by MAC (the only stable L2 identity); IPs are history.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::Result;

use crate::fingerprint::{guess, vendor_for};
use crate::model::{Asset, IpRecord, LinkInfo, Mac, Observation, OtRole, OtSample, Signal};
use crate::store::Store;

const MAX_IP_HISTORY: usize = 20;
const MAX_HOSTNAMES: usize = 8;
const MAX_TAGS: usize = 16;
/// An address re-claimed by a different MAC within this long of the previous
/// holder being seen on it is a conflict; later than that it is an ordinary
/// DHCP hand-over.
const CONFLICT_WINDOW_SECS: i64 = 300;
const MAX_SIGNALS: usize = 1000;
/// `last_seen`-only updates are persisted at most this often per asset.
const TOUCH_PERSIST_SECS: i64 = 30;

pub struct Inventory {
    assets: HashMap<Mac, Asset>,
    by_ip: HashMap<Ipv4Addr, Mac>,
    dirty: HashSet<Mac>,
    last_persisted: HashMap<Mac, i64>,
    new_devices: Vec<Mac>,
    gateway: Option<Ipv4Addr>,
    agent_id: Option<String>,
    /// Bumped on every mutation; lets a remote agent ask "what changed since N".
    rev: u64,
    asset_rev: HashMap<Mac, u64>,
    signals: Vec<Signal>,
}

/// A host worth probing, with what the scan policy needs to know about it.
#[derive(Debug, PartialEq)]
pub struct LiveHost {
    pub ip: Ipv4Addr,
    pub ports_scanned_at: Option<i64>,
    /// Industrial device: never port-scanned (fragile firmware).
    pub ot: bool,
}

/// What a flush hands to the detector.
#[derive(Default)]
pub struct Flushed {
    /// Assets first seen since the last flush (already stored, with ids).
    pub new_assets: Vec<Asset>,
    pub signals: Vec<Signal>,
}

impl Flushed {
    pub fn is_empty(&self) -> bool {
        self.new_assets.is_empty() && self.signals.is_empty()
    }
}

impl Inventory {
    /// Forget everything (the stored data was erased): devices are rediscovered from scratch.
    pub fn clear(&mut self) {
        self.assets.clear();
        self.by_ip.clear();
        self.dirty.clear();
        self.last_persisted.clear();
        self.new_devices.clear();
        self.asset_rev.clear();
        self.signals.clear();
        self.rev += 1;
    }

    pub fn new(loaded: Vec<Asset>, gateway: Option<Ipv4Addr>, agent_id: Option<String>) -> Self {
        let mut inv = Inventory {
            assets: HashMap::new(),
            by_ip: HashMap::new(),
            dirty: HashSet::new(),
            last_persisted: HashMap::new(),
            new_devices: Vec::new(),
            gateway,
            agent_id,
            // Revisions start at 1 so "0" can mean "nothing synced yet" and
            // assets loaded from disk (rev 1) are part of a first full sync.
            rev: 1,
            asset_rev: HashMap::new(),
            signals: Vec::new(),
        };
        // Oldest first so the most recent holder of an IP wins the index.
        let mut loaded = loaded;
        loaded.sort_by_key(|a| a.last_seen);
        for mut a in loaded {
            a.is_self = false; // re-established by the SelfHost observation
            if let Some(cur) = a.current_ip() {
                inv.by_ip.insert(cur, a.mac);
            }
            inv.last_persisted.insert(a.mac, a.last_seen);
            // Rules improve between releases; don't leave stale guesses in the DB.
            let g = guess(&a);
            if g.device_type != a.device_type || g.os != a.os_guess || g.reasons != a.guess_reasons {
                a.device_type = g.device_type;
                a.os_guess = g.os;
                a.guess_reasons = g.reasons;
                inv.dirty.insert(a.mac);
            }
            inv.asset_rev.insert(a.mac, 1);
            inv.assets.insert(a.mac, a);
        }
        inv
    }

    /// Assets modified after `rev`, and the revision to pass next time.
    /// Starting from 0 yields everything (a full sync).
    pub fn changed_since(&self, rev: u64) -> (Vec<Asset>, u64) {
        let assets = self
            .asset_rev
            .iter()
            .filter(|(_, r)| **r > rev)
            .filter_map(|(m, _)| self.assets.get(m).cloned())
            .collect();
        (assets, self.rev)
    }

    pub fn len(&self) -> usize {
        self.assets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    pub fn get(&self, mac: &Mac) -> Option<&Asset> {
        self.assets.get(mac)
    }

    pub fn by_ip(&self, ip: Ipv4Addr) -> Option<&Asset> {
        self.by_ip.get(&ip).and_then(|m| self.assets.get(m))
    }

    /// Hosts whose current IP was seen at or after `since`, with the time of
    /// their last port scan. This is the work list for active scanning.
    pub fn live_hosts(&self, since: i64) -> Vec<LiveHost> {
        self.assets
            .values()
            .filter(|a| a.last_seen >= since && !a.is_self)
            .filter_map(|a| {
                a.current_ip().map(|ip| LiveHost { ip, ports_scanned_at: a.ports_scanned_at, ot: crate::fingerprint::is_ot_device(a) })
            })
            .collect()
    }

    pub fn apply(&mut self, obs: Observation, now: i64) {
        match obs {
            Observation::SelfHost { mac, ip, hostname } => {
                let a = self.entry(mac, now);
                a.is_self = true;
                let mut changed = true; // is_self feeds the guess
                if let Some(h) = hostname {
                    changed |= add_hostname(a, h);
                }
                self.finish(mac, Some(ip), changed, now);
            }
            Observation::Arp { mac, ip } => {
                self.check_conflict(mac, ip, now);
                self.entry(mac, now);
                self.finish(mac, Some(ip), false, now);
            }
            Observation::Dhcp {
                mac,
                ip,
                hostname,
                vendor_class,
                param_list,
            } => {
                let a = self.entry(mac, now);
                let mut changed = false;
                if let Some(h) = hostname {
                    changed |= add_hostname(a, h);
                }
                changed |= set_if_some(&mut a.fingerprint.dhcp_vendor_class, vendor_class);
                changed |= set_if_some(&mut a.fingerprint.dhcp_param_list, param_list);
                self.finish(mac, ip, changed, now);
            }
            Observation::Mdns {
                mac,
                ip,
                hostnames,
                services,
                names,
                models,
            } => {
                let a = self.entry(mac, now);
                let mut changed = false;
                for h in hostnames {
                    changed |= add_hostname(a, h);
                }
                changed |= push_all(&mut a.fingerprint.mdns_services, services);
                changed |= push_all(&mut a.fingerprint.mdns_names, names);
                changed |= push_all(&mut a.fingerprint.mdns_models, models);
                self.finish(mac, Some(ip), changed, now);
            }
            Observation::Ssdp {
                mac,
                ip,
                server,
                types,
            } => {
                let a = self.entry(mac, now);
                let mut changed = set_if_some(&mut a.fingerprint.ssdp_server, server);
                changed |= push_all(&mut a.fingerprint.ssdp_types, types);
                self.finish(mac, Some(ip), changed, now);
            }
            Observation::Tcp { mac, ip, sig } => {
                let a = self.entry(mac, now);
                let mut changed = a.fingerprint.ttl != Some(sig.ttl);
                a.fingerprint.ttl = Some(sig.ttl);
                if a.fingerprint.tcp_sig.as_ref() != Some(&sig) {
                    a.fingerprint.tcp_sig = Some(sig);
                    changed = true;
                }
                self.finish(mac, Some(ip), changed, now);
            }
            Observation::Ttl { mac, ip, ttl } => {
                let a = self.entry(mac, now);
                let changed = a.fingerprint.ttl != Some(ttl);
                a.fingerprint.ttl = Some(ttl);
                self.finish(mac, Some(ip), changed, now);
            }
            Observation::Ports { ip, open } => {
                let Some(mac) = self.by_ip.get(&ip).copied() else {
                    return; // host vanished/renumbered between scan start and result
                };
                let a = self.assets.get_mut(&mac).expect("indexed");
                a.open_ports = open;
                a.ports_scanned_at = Some(now);
                self.finish(mac, None, true, now);
            }
            Observation::Ot(s) => self.apply_ot(&s, now),
            Observation::Link(l) => self.apply_link(l, now),
            Observation::Signal(mut sig) => {
                sig.ts = now;
                sig.gateway = Some(sig.ip) == self.gateway;
                self.push_signal(sig);
            }
            // Traffic accounting is handled before the inventory (capture thread
            // -> aggregator -> detector); nothing here.
            Observation::FlowSample(_) | Observation::Flows(_) => {}
        }
    }

    /// An industrial message between two local devices: record each side's role
    /// in that protocol, and any identity the message announced.
    fn apply_ot(&mut self, s: &OtSample, now: i64) {
        let proto = s.pdu.proto.to_string();
        // (mac, ip, is this side the server?)
        let sides = [(s.src_mac, s.src_ip, s.pdu.server_is_src), (s.dst_mac, s.dst_ip, !s.pdu.server_is_src)];
        for (mac, ip, is_server) in sides {
            if !mac.is_valid() {
                continue;
            }
            let a = self.entry(mac, now);
            let role = a.fingerprint.ot.entry(proto.clone()).or_insert_with(|| OtRole { first_seen: now, ..Default::default() });
            let before = (role.server, role.client);
            if is_server { role.server = true } else { role.client = true }
            role.last_seen = now;
            let mut changed = before != (role.server, role.client);
            if is_server {
                for (k, v) in &s.pdu.identity {
                    changed |= a.fingerprint.identity.insert(format!("{proto}.{k}"), v.clone()).as_ref() != Some(v);
                }
            }
            self.finish(mac, Some(ip), changed, now);
        }
    }

    /// Identity from LLDP / CDP / PROFINET: the announcing device's own words.
    fn apply_link(&mut self, l: LinkInfo, now: i64) {
        let a = self.entry(l.mac, now);
        let mut changed = false;
        for (k, v) in &l.fields {
            let old = a.fingerprint.identity.insert(format!("{}.{k}", l.source), v.clone());
            changed |= old.as_ref() != Some(v);
        }
        // Devices name themselves: use it as a hostname too (fed to the guesser).
        for key in ["system_name", "station_name"] {
            if let Some(n) = l.fields.get(key) {
                changed |= add_hostname(a, n.clone());
            }
        }
        self.finish(l.mac, l.ip, changed, now);
    }

    fn push_signal(&mut self, s: Signal) {
        if self.signals.len() < MAX_SIGNALS {
            self.signals.push(s);
        }
    }

    /// `ip` is being claimed by `mac`. If another MAC was using it moments ago
    /// (and still is, as far as we know), two devices are fighting over one
    /// address: an IP conflict at best, ARP poisoning at worst.
    fn check_conflict(&mut self, mac: Mac, ip: Ipv4Addr, now: i64) {
        let Some(prev_mac) = self.by_ip.get(&ip).copied().filter(|m| *m != mac) else {
            return;
        };
        let Some(prev) = self.assets.get(&prev_mac) else {
            return;
        };
        let recent = prev
            .ip_history
            .iter()
            .find(|r| r.ip == ip)
            .is_some_and(|r| now - r.last_seen < CONFLICT_WINDOW_SECS);
        // If the previous holder has since moved to another address it simply
        // released this one.
        if prev.current_ip() != Some(ip) || !recent {
            return;
        }
        self.push_signal(Signal {
            kind: "arp_conflict".into(),
            ts: now,
            mac,
            ip,
            other_mac: Some(prev_mac),
            gateway: Some(ip) == self.gateway,
        });
    }

    fn entry(&mut self, mac: Mac, now: i64) -> &mut Asset {
        let agent_id = self.agent_id.clone();
        let new_devices = &mut self.new_devices;
        self.assets.entry(mac).or_insert_with(|| {
            let mut a = Asset::new(mac, now);
            a.agent_id = agent_id;
            a.vendor = vendor_for(&mac);
            new_devices.push(mac);
            a
        })
    }

    /// Common tail of every observation: record the IP, bump `last_seen`,
    /// re-derive the guess and decide whether the change needs persisting.
    fn finish(&mut self, mac: Mac, ip: Option<Ipv4Addr>, mut changed: bool, now: i64) {
        let gateway = self.gateway;
        self.rev += 1;
        self.asset_rev.insert(mac, self.rev);
        let a = self.assets.get_mut(&mac).expect("entry() ran first");
        if let Some(ip) = ip {
            changed |= note_ip(a, ip, now);
            self.by_ip.insert(ip, mac);
            if Some(ip) == gateway && !a.is_gateway {
                a.is_gateway = true;
                changed = true;
            }
        }
        a.last_seen = a.last_seen.max(now);
        if changed || self.new_devices.contains(&mac) {
            let g = guess(a);
            a.device_type = g.device_type;
            a.os_guess = g.os;
            a.guess_reasons = g.reasons;
            self.dirty.insert(mac);
        } else if now - self.last_persisted.get(&mac).copied().unwrap_or(0) >= TOUCH_PERSIST_SECS {
            self.dirty.insert(mac);
        }
    }

    /// Persist everything that changed. Returns the assets first seen and the
    /// signals raised since the last successful flush, for the detector to
    /// judge. On error the dirty set is kept so the next flush retries.
    pub fn flush(&mut self, store: &dyn Store) -> Result<Flushed> {
        let macs: Vec<Mac> = self.dirty.iter().copied().collect();
        for mac in macs {
            let a = self.assets.get_mut(&mac).expect("dirty implies present");
            store.save_asset(a)?;
            self.last_persisted.insert(mac, a.last_seen);
            self.dirty.remove(&mac);
        }
        Ok(Flushed {
            new_assets: std::mem::take(&mut self.new_devices)
                .iter()
                .filter_map(|m| self.assets.get(m).cloned())
                .collect(),
            signals: std::mem::take(&mut self.signals),
        })
    }

    pub fn flush_now(&mut self, store: &dyn Store) -> Flushed {
        self.flush(store).unwrap_or_else(|e| {
            tracing::error!("database write failed: {e:#}");
            Flushed::default()
        })
    }
}

fn note_ip(a: &mut Asset, ip: Ipv4Addr, now: i64) -> bool {
    let current = a.current_ip();
    if let Some(r) = a.ip_history.iter_mut().find(|r| r.ip == ip) {
        r.last_seen = now;
        return current != Some(ip); // becoming the current IP again is a real change
    }
    a.ip_history.push(IpRecord {
        ip,
        first_seen: now,
        last_seen: now,
    });
    if a.ip_history.len() > MAX_IP_HISTORY {
        a.ip_history.sort_by_key(|r| r.last_seen);
        a.ip_history.remove(0);
    }
    true
}

fn add_hostname(a: &mut Asset, h: String) -> bool {
    if a.hostnames.contains(&h) || a.hostnames.len() >= MAX_HOSTNAMES {
        return false;
    }
    a.hostnames.push(h);
    true
}

fn set_if_some(slot: &mut Option<String>, v: Option<String>) -> bool {
    match v {
        Some(v) if slot.as_ref() != Some(&v) => {
            *slot = Some(v);
            true
        }
        _ => false,
    }
}

fn push_all(dst: &mut Vec<String>, src: Vec<String>) -> bool {
    let mut changed = false;
    for s in src {
        if dst.len() < MAX_TAGS && !dst.contains(&s) {
            dst.push(s);
            changed = true;
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OpenPort, TcpSig};
    use crate::store::sqlite::SqliteStore;

    const A: Mac = Mac([0x3c, 0x22, 0xfb, 1, 2, 3]);
    const B: Mac = Mac([0x00, 0x1b, 0x63, 9, 9, 9]);

    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, n)
    }

    #[test]
    fn arp_creates_asset_with_vendor_and_new_device_event() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 101);
        let new = inv.flush(&store).unwrap().new_assets;

        let a = inv.get(&A).unwrap();
        assert!(a.id > 0);
        assert_eq!(a.current_ip(), Some(ip(5)));
        assert_eq!(a.first_seen, 100);
        assert_eq!(a.last_seen, 101);
        assert!(a.vendor.is_some());
        // The new device is reported once, already carrying its database id.
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].id, a.id);

        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 102);
        assert!(inv.flush(&store).unwrap().is_empty());
    }

    fn signals(inv: &mut Inventory) -> Vec<Signal> {
        inv.flush(&SqliteStore::open_in_memory().unwrap()).unwrap().signals
    }

    #[test]
    fn a_second_mac_claiming_a_live_address_is_a_conflict() {
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 150);
        assert!(signals(&mut inv).is_empty(), "the holder re-announcing itself is normal");
        inv.apply(Observation::Arp { mac: B, ip: ip(5) }, 160);
        let s = signals(&mut inv);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].kind.as_str(), s[0].mac, s[0].other_mac, s[0].ip, s[0].ts, s[0].gateway), ("arp_conflict", B, Some(A), ip(5), 160, false));
        assert!(signals(&mut inv).is_empty(), "drained once");
    }

    #[test]
    fn dhcp_handovers_and_moves_are_not_conflicts() {
        // the old holder was last seen on the address long ago
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Arp { mac: B, ip: ip(5) }, 100 + CONFLICT_WINDOW_SECS + 1);
        assert!(signals(&mut inv).is_empty());
        // the old holder already moved to another address
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Arp { mac: A, ip: ip(6) }, 110);
        inv.apply(Observation::Arp { mac: B, ip: ip(5) }, 120);
        assert!(signals(&mut inv).is_empty());
        // a confirmed DHCP lease re-assigns without a conflict, and the later ARP agrees
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Dhcp { mac: B, ip: Some(ip(5)), hostname: None, vendor_class: None, param_list: None }, 110);
        inv.apply(Observation::Arp { mac: B, ip: ip(5) }, 111);
        assert!(signals(&mut inv).is_empty());
    }

    #[test]
    fn claiming_the_gateway_address_is_flagged_as_such() {
        let mut inv = Inventory::new(vec![], Some(ip(1)), None);
        inv.apply(Observation::Arp { mac: A, ip: ip(1) }, 100);
        inv.apply(Observation::Arp { mac: B, ip: ip(1) }, 101);
        let s = signals(&mut inv);
        assert!(s[0].gateway && s[0].mac == B);
        // wire-level mismatch signals are stamped and gateway-tagged too
        inv.apply(Observation::Signal(Signal { kind: "arp_mismatch".into(), ts: 0, mac: B, ip: ip(1), other_mac: Some(A), gateway: false }), 500);
        let s = signals(&mut inv);
        assert_eq!((s[0].ts, s[0].gateway), (500, true));
    }

    #[test]
    fn industrial_traffic_sets_roles_and_identity_and_lldp_names_devices() {
        use crate::model::{OtClass, OtPdu};
        let mk = |server_is_src: bool, identity: &[(&str, &str)]| OtSample {
            src_mac: A, dst_mac: B, src_ip: ip(5), dst_ip: ip(6), bytes: 60,
            pdu: OtPdu {
                proto: "modbus", server_is_src, class: OtClass::Read, detail: "read".into(), port: 502,
                identity: identity.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            },
        };
        let mut inv = Inventory::new(vec![], None, None);
        // A polls B: A is the client, B the server
        inv.apply(Observation::Ot(mk(false, &[])), 100);
        let (a, b) = (inv.get(&A).unwrap(), inv.get(&B).unwrap());
        assert_eq!((a.fingerprint.ot["modbus"].client, a.fingerprint.ot["modbus"].server), (true, false));
        assert_eq!((b.fingerprint.ot["modbus"].client, b.fingerprint.ot["modbus"].server), (false, true));
        assert_eq!(b.current_ip(), Some(ip(6)), "both ends are bound to their addresses");
        // the response from B announces its identity, which attaches to B (the source)
        inv.apply(Observation::Ot(OtSample { src_mac: B, dst_mac: A, src_ip: ip(6), dst_ip: ip(5), ..mk(true, &[("product_name", "CPU 315")]) }), 101);
        assert_eq!(inv.get(&B).unwrap().fingerprint.identity["modbus.product_name"], "CPU 315");

        let mut fields = std::collections::BTreeMap::new();
        fields.insert("system_name".to_string(), "core-sw".to_string());
        fields.insert("capabilities".to_string(), "bridge".to_string());
        inv.apply(Observation::Link(LinkInfo { mac: Mac([0x00, 0x1b, 0x63, 7, 7, 7]), source: "lldp", ip: Some(ip(9)), fields }), 102);
        let sw = inv.get(&Mac([0x00, 0x1b, 0x63, 7, 7, 7])).unwrap();
        assert_eq!(sw.hostnames, ["core-sw"]);
        assert_eq!(sw.fingerprint.identity["lldp.capabilities"], "bridge");
        assert_eq!(sw.current_ip(), Some(ip(9)));
    }

    #[test]
    fn changed_since_supports_incremental_and_full_sync() {
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Arp { mac: B, ip: ip(6) }, 100);
        let (all, rev) = inv.changed_since(0);
        assert_eq!(all.len(), 2);
        assert!(inv.changed_since(rev).0.is_empty());
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 101);
        let (delta, rev2) = inv.changed_since(rev);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].mac, A);
        assert!(rev2 > rev);

        // Assets loaded from disk are part of a full sync too.
        let store = SqliteStore::open_in_memory().unwrap();
        inv.flush(&store).unwrap();
        let reloaded = Inventory::new(store.load_assets().unwrap(), None, None);
        assert_eq!(reloaded.changed_since(0).0.len(), 2);
        assert!(reloaded.changed_since(reloaded.changed_since(0).1).0.is_empty());
    }

    #[test]
    fn ip_change_keeps_history_and_reindexes() {
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Arp { mac: A, ip: ip(6) }, 200);
        let a = inv.get(&A).unwrap();
        assert_eq!(a.ip_history.len(), 2);
        assert_eq!(a.current_ip(), Some(ip(6)));
        assert_eq!(inv.by_ip(ip(6)).unwrap().mac, A);
    }

    #[test]
    fn evidence_accumulates_into_a_guess() {
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(
            Observation::Dhcp {
                mac: B,
                ip: Some(ip(7)),
                hostname: Some("DESKTOP-AB12".into()),
                vendor_class: Some("MSFT 5.0".into()),
                param_list: Some("1,3,6".into()),
            },
            100,
        );
        inv.apply(
            Observation::Tcp {
                mac: B,
                ip: ip(7),
                sig: TcpSig { ttl: 128, window: 64240, options: "MNWNNS".into(), mss: Some(1460), wscale: Some(8) },
            },
            110,
        );
        let a = inv.get(&B).unwrap();
        assert_eq!(a.os_guess.as_deref(), Some("Windows"));
        assert_eq!(a.device_type, "computer");
        assert_eq!(a.hostnames, ["DESKTOP-AB12"]);
        assert!(!a.guess_reasons.is_empty());
    }

    #[test]
    fn port_scan_resolves_by_ip_and_unknown_ip_is_dropped() {
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        let open = vec![OpenPort { port: 9100, proto: "tcp".into(), service: Some("jetdirect".into()) }];
        inv.apply(Observation::Ports { ip: ip(5), open: open.clone() }, 120);
        inv.apply(Observation::Ports { ip: ip(99), open: open.clone() }, 120);
        let a = inv.get(&A).unwrap();
        assert_eq!(a.open_ports, open);
        assert_eq!(a.ports_scanned_at, Some(120));
        assert_eq!(a.device_type, "printer");
        assert_eq!(inv.len(), 1);
    }

    #[test]
    fn gateway_is_flagged_as_router() {
        let mut inv = Inventory::new(vec![], Some(ip(1)), None);
        inv.apply(Observation::Arp { mac: B, ip: ip(1) }, 100);
        let a = inv.get(&B).unwrap();
        assert!(a.is_gateway);
        assert_eq!(a.device_type, "router");
    }

    #[test]
    fn last_seen_only_updates_are_rate_limited_for_persistence() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.flush(&store).unwrap();
        assert!(inv.dirty.is_empty());
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 110);
        assert!(inv.dirty.is_empty(), "10s later: in-memory only");
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 131);
        assert_eq!(inv.dirty.len(), 1, "30s+ later: persisted");
    }

    #[test]
    fn reload_restores_state_and_index() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.flush(&store).unwrap();
        let inv2 = Inventory::new(store.load_assets().unwrap(), None, None);
        assert_eq!(inv2.len(), 1);
        assert_eq!(inv2.by_ip(ip(5)).unwrap().mac, A);
    }

    #[test]
    fn stale_guesses_are_rederived_on_load() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut a = Asset::new(B, 100);
        a.fingerprint.dhcp_vendor_class = Some("MSFT 5.0".into());
        a.device_type = "unknown".into(); // as written by an older ruleset
        store.save_asset(&mut a).unwrap();

        let mut inv = Inventory::new(store.load_assets().unwrap(), None, None);
        assert_eq!(inv.get(&B).unwrap().device_type, "computer");
        assert_eq!(inv.dirty.len(), 1);
        inv.flush(&store).unwrap();
        assert_eq!(store.get_asset(a.id).unwrap().unwrap().device_type, "computer");
    }

    #[test]
    fn live_hosts_excludes_stale_and_self() {
        let mut inv = Inventory::new(vec![], None, None);
        inv.apply(Observation::SelfHost { mac: Mac([2, 0, 0, 0, 0, 1]), ip: ip(2), hostname: Some("me".into()) }, 500);
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Arp { mac: B, ip: ip(6) }, 400);
        let live = inv.live_hosts(300);
        assert_eq!(live, vec![LiveHost { ip: ip(6), ports_scanned_at: None, ot: false }]);
    }
}
