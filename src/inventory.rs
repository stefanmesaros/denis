//! In-memory asset table: folds `Observation`s into `Asset`s, re-derives the
//! device-type guess, and flushes changes to a `Store`.
//!
//! Assets are keyed by MAC (the only stable L2 identity); IPs are history.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::Result;

use crate::fingerprint::{guess, vendor_for};
use crate::model::{Asset, IpRecord, LinkInfo, Mac, Observation, OtRole, OtSample, Signal, SignalV6};
use crate::store::{Store};

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
    /// The IPv6 analogue of `signals` (IPV6.md item 3), same discipline.
    signals_v6: Vec<SignalV6>,
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
    /// The IPv6 analogue of `signals` (IPV6.md item 3), same discipline.
    pub signals_v6: Vec<SignalV6>,
}

impl Flushed {
    pub fn is_empty(&self) -> bool {
        self.new_assets.is_empty() && self.signals.is_empty() && self.signals_v6.is_empty()
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
        self.signals_v6.clear();
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
            signals_v6: Vec::new(),
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

    /// Global (non-link-local) IPv6 addresses worth an active liveness check (`--ipv6`, opt-in):
    /// every one of them was already learned passively (see `note_ipv6`), so this only refreshes
    /// staleness, it never discovers a brand-new address — a deliberate, smaller first step than a
    /// real IPv6 active-discovery mechanism (joining solicited-node multicast groups), see IPV6.md.
    /// Link-local addresses are skipped: routing one needs an interface scope id, a portability
    /// question this does not need to take on for the global-address case to already be useful.
    /// Industrial devices are never pinged, same rule as `live_hosts`.
    pub fn live_hosts_v6(&self, since: i64) -> Vec<std::net::Ipv6Addr> {
        self.assets
            .values()
            .filter(|a| a.last_seen >= since && !a.is_self && !crate::fingerprint::is_ot_device(a))
            .flat_map(|a| a.ipv6_history.iter().filter(|r| !r.link_local).map(|r| r.ip))
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
            Observation::Ndp { mac, ip, link_local } => {
                self.entry(mac, now);
                let a = self.assets.get_mut(&mac).expect("entry() ran first");
                let changed = note_ipv6(a, ip, link_local, now);
                self.finish(mac, None, changed, now);
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
            Observation::Banners { ip, fields } => {
                let Some(mac) = self.by_ip.get(&ip).copied() else { return };
                let a = self.assets.get_mut(&mac).expect("indexed");
                let before = a.fingerprint.identity.clone();
                a.fingerprint.identity.retain(|k, _| !k.starts_with("banner."));
                for (k, v) in fields.into_iter().filter(|(k, _)| k.starts_with("banner.")) {
                    a.fingerprint.identity.insert(k, v);
                }
                let changed = a.fingerprint.identity != before;
                self.finish(mac, None, changed, now);
            }
            Observation::Ot(s) => self.apply_ot(&s, now),
            Observation::Link(l) => self.apply_link(l, now),
            Observation::Signal(mut sig) => {
                sig.ts = now;
                sig.gateway = Some(sig.ip) == self.gateway;
                self.push_signal(sig);
            }
            Observation::SignalV6(mut sig) => {
                sig.ts = now;
                self.push_signal_v6(sig);
            }
            // Traffic accounting is handled before the inventory (capture thread
            // -> aggregator -> detector); nothing here.
            Observation::FlowSample(_) | Observation::FlowSampleV6(_) | Observation::Flows(_) => {}
        }
    }

    /// An industrial message between two local devices: record each side's role
    /// in that protocol, and any identity the message announced.
    fn apply_ot(&mut self, s: &OtSample, now: i64) {
        let proto = s.pdu.proto.to_string();
        // a path whose content is not read says nothing about what either device is
        if s.pdu.class == crate::model::OtClass::Opaque {
            // Unread content is a path, not evidence about what either device is, beyond one
            // exception: identity the message's own sender announced about *itself* (a TLS
            // ClientHello/ServerHello's JA3/JA3S fingerprint), same as LLDP or EtherNet/IP.
            for (mac, ip) in [(s.src_mac, s.src_ip), (s.dst_mac, s.dst_ip)] {
                if !mac.is_valid() {
                    continue;
                }
                let a = self.entry(mac, now);
                let mut changed = false;
                if mac == s.src_mac {
                    for (k, v) in &s.pdu.identity {
                        changed |= a.fingerprint.identity.insert(format!("{proto}.{k}"), v.clone()).as_ref() != Some(v);
                    }
                }
                self.finish(mac, Some(ip), changed, now);
            }
            return;
        }
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

    fn push_signal_v6(&mut self, s: SignalV6) {
        if self.signals_v6.len() < MAX_SIGNALS {
            self.signals_v6.push(s);
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
            signals_v6: std::mem::take(&mut self.signals_v6),
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

/// The IPv6 analogue of `note_ip`. Unlike an IPv4 address there is no single "current" one to
/// compare against — a device normally holds a permanent link-local address *and* one or more
/// global ones at once (see `model::Ipv6Record`'s own doc) — so this only ever tracks presence
/// in the list, not a "did the current address change" signal the way `note_ip` does.
fn note_ipv6(a: &mut Asset, ip: std::net::Ipv6Addr, link_local: bool, now: i64) -> bool {
    if let Some(r) = a.ipv6_history.iter_mut().find(|r| r.ip == ip) {
        r.last_seen = now;
        return false; // already known: seeing it again is not itself a change worth persisting early
    }
    a.ipv6_history.push(crate::model::Ipv6Record { ip, link_local, first_seen: now, last_seen: now });
    if a.ipv6_history.len() > MAX_IP_HISTORY {
        a.ipv6_history.sort_by_key(|r| r.last_seen);
        a.ipv6_history.remove(0);
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

/// Merges a joined agent's reported view of a device into the target site's own row
/// (MULTI_AGENT_DEDUP.md's "join" design). `stored` is always the survivor - the site's own row,
/// whose id every alert/exception/audit entry already points at - and this function only ever
/// fills its gaps, never overwrites a value it already has. `is_self` is deliberately not merged:
/// it belongs to `asset_sightings` per collector, not to the shared row (a device can be one
/// collector's own host and another's ordinary neighbour at the same time). `vendor` and
/// `randomized_mac` are not merged either - identical by construction, since both sides describe
/// the same MAC. `device_type`/`os_guess`/`guess_reasons` are re-derived from the merged
/// fingerprint at the end, the same way every other mutation to a stored asset already does.
pub fn merge_observed(stored: &mut Asset, incoming: &Asset) {
    stored.first_seen = stored.first_seen.min(incoming.first_seen);
    stored.last_seen = stored.last_seen.max(incoming.last_seen);

    for r in &incoming.ip_history {
        match stored.ip_history.iter_mut().find(|s| s.ip == r.ip) {
            Some(s) => {
                s.first_seen = s.first_seen.min(r.first_seen);
                s.last_seen = s.last_seen.max(r.last_seen);
            }
            None => stored.ip_history.push(r.clone()),
        }
    }
    if stored.ip_history.len() > MAX_IP_HISTORY {
        stored.ip_history.sort_by_key(|r| r.last_seen);
        let extra = stored.ip_history.len() - MAX_IP_HISTORY;
        stored.ip_history.drain(0..extra);
    }

    for r in &incoming.ipv6_history {
        match stored.ipv6_history.iter_mut().find(|s| s.ip == r.ip) {
            Some(s) => {
                s.first_seen = s.first_seen.min(r.first_seen);
                s.last_seen = s.last_seen.max(r.last_seen);
            }
            None => stored.ipv6_history.push(r.clone()),
        }
    }
    if stored.ipv6_history.len() > MAX_IP_HISTORY {
        stored.ipv6_history.sort_by_key(|r| r.last_seen);
        let extra = stored.ipv6_history.len() - MAX_IP_HISTORY;
        stored.ipv6_history.drain(0..extra);
    }

    for h in &incoming.hostnames {
        if !stored.hostnames.contains(h) && stored.hostnames.len() < MAX_HOSTNAMES {
            stored.hostnames.push(h.clone());
        }
    }

    // A port scan is a snapshot, not history: a union would resurrect ports the fresher side has
    // since seen closed. Whichever side scanned more recently wins outright, ports included.
    if incoming.ports_scanned_at > stored.ports_scanned_at {
        stored.open_ports = incoming.open_ports.clone();
        stored.ports_scanned_at = incoming.ports_scanned_at;
    }

    let f = &mut stored.fingerprint;
    let i = &incoming.fingerprint;
    if f.dhcp_vendor_class.is_none() {
        f.dhcp_vendor_class = i.dhcp_vendor_class.clone();
    }
    if f.dhcp_param_list.is_none() {
        f.dhcp_param_list = i.dhcp_param_list.clone();
    }
    if f.ssdp_server.is_none() {
        f.ssdp_server = i.ssdp_server.clone();
    }
    if f.tcp_sig.is_none() {
        f.tcp_sig = i.tcp_sig.clone();
    }
    if f.ttl.is_none() {
        f.ttl = i.ttl;
    }
    push_all(&mut f.mdns_services, i.mdns_services.clone());
    push_all(&mut f.mdns_names, i.mdns_names.clone());
    push_all(&mut f.mdns_models, i.mdns_models.clone());
    push_all(&mut f.ssdp_types, i.ssdp_types.clone());
    for (k, v) in &i.identity {
        f.identity.entry(k.clone()).or_insert_with(|| v.clone());
    }
    for (k, v) in &i.ot {
        f.ot
            .entry(k.clone())
            .and_modify(|r| {
                r.server |= v.server;
                r.client |= v.client;
                r.first_seen = r.first_seen.min(v.first_seen);
                r.last_seen = r.last_seen.max(v.last_seen);
            })
            .or_insert_with(|| v.clone());
    }

    stored.is_gateway |= incoming.is_gateway;

    let g = guess(stored);
    stored.device_type = g.device_type;
    stored.os_guess = g.os;
    stored.guess_reasons = g.reasons;
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
    use crate::store::AssetStore;
    use crate::model::{OpenPort, TcpSig};
    use crate::store::sqlite::SqliteStore;

    const A: Mac = Mac([0x3c, 0x22, 0xfb, 1, 2, 3]);
    const B: Mac = Mac([0x00, 0x1b, 0x63, 9, 9, 9]);

    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, n)
    }

    #[test]
    fn merge_observed_never_overwrites_a_value_the_stored_row_already_has() {
        // MULTI_AGENT_DEDUP.md: the site's own row is always the survivor, and only ever has its
        // gaps filled - a value it already carries must never be replaced by the incoming side.
        let mut stored = Asset::new(A, 100);
        stored.hostnames.push("kept".into());
        stored.fingerprint.ttl = Some(64);
        stored.is_gateway = false;

        let mut incoming = Asset::new(A, 50);
        incoming.hostnames.push("kept".into()); // same value: must not duplicate
        incoming.hostnames.push("also-incoming".into());
        incoming.fingerprint.ttl = Some(128); // stored already has one: must not overwrite
        incoming.is_gateway = true; // OR'd in, never cleared once true

        merge_observed(&mut stored, &incoming);

        assert_eq!(stored.hostnames, vec!["kept".to_string(), "also-incoming".to_string()]);
        assert_eq!(stored.fingerprint.ttl, Some(64), "stored's own value wins");
        assert!(stored.is_gateway, "OR, never cleared");
    }

    #[test]
    fn merge_observed_takes_the_widest_first_and_last_seen_across_both_sides() {
        let mut stored = Asset::new(A, 200);
        stored.last_seen = 300;
        let mut incoming = Asset::new(A, 100); // earlier first_seen
        incoming.last_seen = 500; // later last_seen

        merge_observed(&mut stored, &incoming);

        assert_eq!(stored.first_seen, 100);
        assert_eq!(stored.last_seen, 500);
    }

    #[test]
    fn merge_observed_unions_ip_history_by_address_and_widens_each_records_range() {
        let mut stored = Asset::new(A, 0);
        stored.ip_history.push(IpRecord { ip: ip(5), first_seen: 100, last_seen: 200 });
        let mut incoming = Asset::new(A, 0);
        incoming.ip_history.push(IpRecord { ip: ip(5), first_seen: 50, last_seen: 300 }); // same ip: widen
        incoming.ip_history.push(IpRecord { ip: ip(9), first_seen: 10, last_seen: 20 }); // new ip: added

        merge_observed(&mut stored, &incoming);

        let a = stored.ip_history.iter().find(|r| r.ip == ip(5)).unwrap();
        assert_eq!((a.first_seen, a.last_seen), (50, 300));
        assert!(stored.ip_history.iter().any(|r| r.ip == ip(9)));
        assert_eq!(stored.ip_history.len(), 2);
    }

    #[test]
    fn merge_observed_open_ports_take_whichever_side_scanned_more_recently_never_a_union() {
        // a port scan is a snapshot, not history: a union would resurrect a port the fresher side
        // has since seen closed.
        let mut stored = Asset::new(A, 0);
        stored.open_ports.push(OpenPort { port: 22, proto: "tcp".into(), service: None });
        stored.ports_scanned_at = Some(100);
        let mut incoming = Asset::new(A, 0);
        incoming.open_ports.push(OpenPort { port: 443, proto: "tcp".into(), service: None });
        incoming.ports_scanned_at = Some(200); // newer: wins outright

        merge_observed(&mut stored, &incoming);

        assert_eq!(stored.ports_scanned_at, Some(200));
        assert_eq!(stored.open_ports, vec![OpenPort { port: 443, proto: "tcp".into(), service: None }], "replaced, not unioned");
    }

    #[test]
    fn merge_observed_reports_open_ports_are_kept_when_stored_scanned_more_recently() {
        let mut stored = Asset::new(A, 0);
        stored.open_ports.push(OpenPort { port: 22, proto: "tcp".into(), service: None });
        stored.ports_scanned_at = Some(500);
        let mut incoming = Asset::new(A, 0);
        incoming.open_ports.push(OpenPort { port: 443, proto: "tcp".into(), service: None });
        incoming.ports_scanned_at = Some(100); // older: stored wins

        merge_observed(&mut stored, &incoming);

        assert_eq!(stored.ports_scanned_at, Some(500));
        assert_eq!(stored.open_ports, vec![OpenPort { port: 22, proto: "tcp".into(), service: None }]);
    }

    #[test]
    fn merge_observed_fingerprint_lists_union_and_maps_union_keeping_stored_on_conflict() {
        let mut stored = Asset::new(A, 0);
        stored.fingerprint.mdns_services.push("_ssh._tcp".into());
        stored.fingerprint.identity.insert("lldp.system_name".into(), "stored-name".into());
        stored.fingerprint.tcp_sig = Some(TcpSig { window: 1, ttl: 64, options: "mss".into(), mss: None, wscale: None });

        let mut incoming = Asset::new(A, 0);
        incoming.fingerprint.mdns_services.push("_http._tcp".into());
        incoming.fingerprint.identity.insert("lldp.system_name".into(), "incoming-name".into()); // conflict: stored wins
        incoming.fingerprint.identity.insert("enip.product_name".into(), "plc".into()); // new key: added
        incoming.fingerprint.tcp_sig = Some(TcpSig { window: 2, ttl: 128, options: "sack".into(), mss: None, wscale: None }); // stored already has one

        merge_observed(&mut stored, &incoming);

        assert_eq!(stored.fingerprint.mdns_services, vec!["_ssh._tcp".to_string(), "_http._tcp".to_string()]);
        assert_eq!(stored.fingerprint.identity.get("lldp.system_name"), Some(&"stored-name".to_string()));
        assert_eq!(stored.fingerprint.identity.get("enip.product_name"), Some(&"plc".to_string()));
        assert_eq!(stored.fingerprint.tcp_sig, Some(TcpSig { window: 1, ttl: 64, options: "mss".into(), mss: None, wscale: None }), "stored's own tcp_sig wins");
    }

    #[test]
    fn merge_observed_re_derives_device_type_and_os_guess_from_the_merged_fingerprint() {
        let mut stored = Asset::new(A, 0);
        let mut incoming = Asset::new(A, 0);
        incoming.fingerprint.ssdp_server = Some("Linux/3.14 UPnP/1.0 MiniUPnPd/2.0".into());
        incoming.fingerprint.ssdp_types.push("urn:schemas-upnp-org:device:InternetGatewayDevice:1".into());

        merge_observed(&mut stored, &incoming);

        // re-derivation actually ran off the merged data, not the stored side's (empty) original
        assert_ne!(stored.device_type, "unknown");
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

    #[test]
    fn ndp_folds_into_ipv6_history_alongside_the_ipv4_one_never_replacing_it() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut inv = Inventory::new(vec![], None, None);
        let global: std::net::Ipv6Addr = "2001:db8::42".parse().unwrap();
        let link_local: std::net::Ipv6Addr = "fe80::42".parse().unwrap();
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 100);
        inv.apply(Observation::Ndp { mac: A, ip: global, link_local: false }, 100);
        inv.apply(Observation::Ndp { mac: A, ip: link_local, link_local: true }, 101);
        inv.flush(&store).unwrap();

        let a = inv.get(&A).unwrap();
        // a device normally holds a permanent link-local address *and* a global one at once - both
        // are kept, unlike ip_history's single "current" IPv4 address
        assert_eq!(a.current_ip(), Some(ip(5)), "the IPv4 binding is untouched by IPv6 observations");
        assert_eq!(a.ipv6_history.len(), 2);
        assert!(a.ipv6_history.iter().any(|r| r.ip == global && !r.link_local));
        assert!(a.ipv6_history.iter().any(|r| r.ip == link_local && r.link_local));

        // seeing the same address again just touches last_seen, no duplicate entry
        inv.apply(Observation::Ndp { mac: A, ip: global, link_local: false }, 200);
        assert_eq!(inv.get(&A).unwrap().ipv6_history.len(), 2);
        assert_eq!(inv.get(&A).unwrap().ipv6_history.iter().find(|r| r.ip == global).unwrap().last_seen, 200);
    }

    #[test]
    fn live_hosts_v6_skips_link_local_stale_and_self_but_keeps_every_global_address() {
        let mut inv = Inventory::new(vec![], None, None);
        let (global1, global2, link_local): (std::net::Ipv6Addr, std::net::Ipv6Addr, std::net::Ipv6Addr) =
            ("2001:db8::1".parse().unwrap(), "2001:db8::2".parse().unwrap(), "fe80::1".parse().unwrap());
        inv.apply(Observation::Arp { mac: A, ip: ip(5) }, 200);
        inv.apply(Observation::Ndp { mac: A, ip: global1, link_local: false }, 200);
        inv.apply(Observation::Ndp { mac: A, ip: link_local, link_local: true }, 200);
        // a stale device: last seen well before the cutoff below
        inv.apply(Observation::Arp { mac: B, ip: ip(6) }, 100);
        inv.apply(Observation::Ndp { mac: B, ip: global2, link_local: false }, 100);
        // our own address is never a probe target, regardless of how recently it was "seen"
        inv.apply(Observation::SelfHost { mac: Mac([9, 9, 9, 9, 9, 9]), ip: ip(9), hostname: None }, 200);
        inv.apply(Observation::Ndp { mac: Mac([9, 9, 9, 9, 9, 9]), ip: "2001:db8::9".parse().unwrap(), link_local: false }, 200);

        let live = inv.live_hosts_v6(150);
        assert_eq!(live, vec![global1], "link-local skipped, self skipped, and B is stale (last_seen 100 < since 150)");

        // once B is seen more recently it becomes eligible too
        inv.apply(Observation::Arp { mac: B, ip: ip(6) }, 300);
        let mut live = inv.live_hosts_v6(150);
        live.sort();
        let mut want = vec![global1, global2];
        want.sort();
        assert_eq!(live, want);
    }

    fn signals(inv: &mut Inventory) -> Vec<Signal> {
        inv.flush(&SqliteStore::open_in_memory().unwrap()).unwrap().signals
    }

    fn signals_v6(inv: &mut Inventory) -> Vec<SignalV6> {
        inv.flush(&SqliteStore::open_in_memory().unwrap()).unwrap().signals_v6
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
    fn ndp_mismatch_signals_are_stamped_and_flushed_separately_from_ipv4_ones() {
        let mut inv = Inventory::new(vec![], Some(ip(1)), None);
        let target: std::net::Ipv6Addr = "2001:db8::42".parse().unwrap();
        inv.apply(Observation::SignalV6(SignalV6 { kind: "ndp_mismatch".into(), ts: 0, mac: B, ip: target, other_mac: Some(A) }), 700);
        let s = signals_v6(&mut inv);
        assert_eq!((s.len(), s[0].ts, s[0].kind.as_str()), (1, 700, "ndp_mismatch"));
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

    #[test]
    fn banners_replace_the_earlier_ones_and_a_silent_service_loses_its_banner() {
        let mut inv = Inventory::new(vec![], None, None);
        let mac = Mac([2, 0, 0, 0, 0, 7]);
        inv.apply(Observation::Arp { mac, ip: ip(7) }, 100);
        let banners = |pairs: &[(&str, &str)]| Observation::Banners { ip: ip(7), fields: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() };
        inv.apply(banners(&[("banner.ssh", "SSH-2.0-OpenSSH_7.4"), ("banner.http", "Server: nginx/1.10.3")]), 110);
        let id = |inv: &Inventory| inv.assets[&mac].fingerprint.identity.clone();
        assert_eq!(id(&inv).len(), 2);
        // the web server went away: only what is announced now is kept; other identity (LLDP...) is left alone
        inv.apply(Observation::Link(LinkInfo { mac, source: "lldp", ip: Some(ip(7)), fields: [("system_name".to_string(), "sw".to_string())].into_iter().collect() }), 115);
        inv.apply(banners(&[("banner.ssh", "SSH-2.0-OpenSSH_8.9p1")]), 120);
        let now = id(&inv);
        assert_eq!(now.get("banner.ssh").map(String::as_str), Some("SSH-2.0-OpenSSH_8.9p1"));
        assert!(!now.contains_key("banner.http") && now.contains_key("lldp.system_name"), "{now:?}");
        // something that is not a banner cannot be smuggled in, and an unknown address is ignored
        inv.apply(banners(&[("lldp.system_name", "spoof")]), 130);
        assert_eq!(id(&inv).get("lldp.system_name").map(String::as_str), Some("sw"));
        inv.apply(Observation::Banners { ip: ip(99), fields: Default::default() }, 140);
    }
}
