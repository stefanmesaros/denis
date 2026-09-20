//! In-memory asset table: folds `Observation`s into `Asset`s, re-derives the
//! device-type guess, and flushes changes to a `Store`.
//!
//! Assets are keyed by MAC (the only stable L2 identity); IPs are history.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::Result;

use crate::fingerprint::{guess, vendor_for};
use crate::model::{Asset, IpRecord, Mac, Observation};
use crate::store::Store;

const MAX_IP_HISTORY: usize = 20;
const MAX_HOSTNAMES: usize = 8;
const MAX_TAGS: usize = 16;
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
}

impl Inventory {
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
    pub fn live_hosts(&self, since: i64) -> Vec<(Ipv4Addr, Option<i64>)> {
        self.assets
            .values()
            .filter(|a| a.last_seen >= since && !a.is_self)
            .filter_map(|a| a.current_ip().map(|ip| (ip, a.ports_scanned_at)))
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
            // Traffic accounting is handled before the inventory (capture thread
            // -> aggregator -> detector); nothing here.
            Observation::FlowSample(_) | Observation::Flows(_) => {}
        }
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

    /// Persist everything that changed. Returns the assets first seen since
    /// the last successful flush (with database ids), for the detector to judge.
    /// On error the dirty set is kept so the next flush retries.
    pub fn flush(&mut self, store: &dyn Store) -> Result<Vec<Asset>> {
        let macs: Vec<Mac> = self.dirty.iter().copied().collect();
        for mac in macs {
            let a = self.assets.get_mut(&mac).expect("dirty implies present");
            store.save_asset(a)?;
            self.last_persisted.insert(mac, a.last_seen);
            self.dirty.remove(&mac);
        }
        Ok(std::mem::take(&mut self.new_devices)
            .iter()
            .filter_map(|m| self.assets.get(m).cloned())
            .collect())
    }

    pub fn flush_now(&mut self, store: &dyn Store) -> Vec<Asset> {
        self.flush(store).unwrap_or_else(|e| {
            tracing::error!("database write failed: {e:#}");
            Vec::new()
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
        let new = inv.flush(&store).unwrap();

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
        assert_eq!(live, vec![(ip(6), None)]);
    }
}
