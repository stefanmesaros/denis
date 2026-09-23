//! The switches DENIS reads over SNMP: who they are (an administrator's list), when they are polled, and what the
//! last poll found. The community string is a secret: it is stored with the list, never sent back by the API
//! (a blank one on save means "keep the one I have"), and never written to a log or the audit trail.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::store::Store;
use crate::topology::{self, Polled, Snapshot};

pub const KEY: &str = "switches";
pub const MAX_SWITCHES: usize = 50;
pub const DEFAULT_INTERVAL: u64 = 300;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Target {
    /// Chosen by the console; lower-case letters and digits.
    pub id: String,
    pub name: String,
    /// An IP address, or `address:port` (default 161).
    pub address: String,
    #[serde(default)]
    pub community: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub interval_secs: u64,
    pub targets: Vec<Target>,
}

impl Default for Config {
    fn default() -> Self {
        Config { interval_secs: DEFAULT_INTERVAL, targets: Vec::new() }
    }
}

pub fn load(store: &dyn Store) -> Result<Config> {
    Ok(store.get_setting(KEY)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default())
}

pub fn save(store: &dyn Store, c: &Config, now: i64) -> Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(c)?, now)
}

/// `192.0.2.1` or `192.0.2.1:1161`.
pub fn socket_addr(address: &str) -> Option<SocketAddr> {
    let a = address.trim();
    a.parse::<SocketAddr>().ok().or_else(|| a.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 161)))
}

impl Target {
    /// Validate and normalise what came in.
    pub fn check(&self) -> Result<Target, String> {
        let id = self.id.trim().to_string();
        if id.is_empty() || id.len() > 16 || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            return Err("a switch needs an id of up to 16 lower-case letters and digits".into());
        }
        let name = self.name.trim().to_string();
        if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
            return Err("a switch needs a name of at most 60 characters".into());
        }
        let Some(addr) = socket_addr(&self.address) else { return Err("the address must be an IP address like 192.168.1.2 (or 192.168.1.2:161)".into()) };
        if addr.ip().is_unspecified() || addr.ip().is_multicast() || addr.port() == 0 {
            return Err("the address must be the switch's own address".into());
        }
        let community = self.community.trim().to_string();
        if community.chars().count() > 64 || community.chars().any(|c| c.is_control()) {
            return Err("the community is at most 64 characters".into());
        }
        Ok(Target { id, name, address: if addr.port() == 161 { addr.ip().to_string() } else { addr.to_string() }, community, enabled: self.enabled })
    }
}

impl Config {
    /// Apply what the console sends. A blank community keeps the one already stored for that switch; a new switch needs one.
    pub fn update(&mut self, interval: Option<u64>, incoming: &[Target]) -> Result<(), String> {
        if incoming.len() > MAX_SWITCHES {
            return Err(format!("at most {MAX_SWITCHES} switches"));
        }
        if let Some(i) = interval {
            if !(60..=3600).contains(&i) {
                return Err("poll every 60 to 3600 seconds".into());
            }
        }
        let mut next = Vec::new();
        for t in incoming {
            let mut c = t.check()?;
            if c.community.is_empty() {
                match self.targets.iter().find(|o| o.id == c.id) {
                    Some(old) => c.community = old.community.clone(),
                    None => return Err("a switch needs its SNMP community (a read-only one)".into()),
                }
            }
            next.push(c);
        }
        let mut ids: Vec<&str> = next.iter().map(|t| t.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != next.len() {
            return Err("switch ids must be unique".into());
        }
        self.targets = next;
        if let Some(i) = interval {
            self.interval_secs = i;
        }
        Ok(())
    }
}

/// Poll one switch now and keep the outcome. Returns the snapshot, or the (already stored) error text.
pub async fn poll_and_store(store: &Arc<dyn Store>, t: &Target, now: i64) -> Result<Snapshot, String> {
    let Some(addr) = socket_addr(&t.address) else { return Err("bad address".into()) };
    let result = topology::poll(addr, &t.community, Duration::from_secs(2), now).await.map_err(|e| format!("{e:#}"));
    let s = store.clone();
    let id = t.id.clone();
    let stored = match &result {
        Ok(snap) => serde_json::to_string(snap).map_err(|e| e.to_string()).map(|j| (j, None)),
        Err(e) => Ok((String::new(), Some(e.clone()))),
    };
    if let Ok((json, err)) = stored {
        let _ = tokio::task::spawn_blocking(move || match &err {
            None => s.save_topo(&id, now, Ok(&json)),
            Some(e) => s.save_topo(&id, now, Err(e)),
        })
        .await;
    }
    result
}

/// The stored polls joined with the list, in the list's order (a switch never polled yet is listed too).
pub fn polled(store: &dyn Store, cfg: &Config) -> Result<Vec<Polled>> {
    let rows = store.list_topo()?;
    Ok(cfg
        .targets
        .iter()
        .map(|t| {
            let row = rows.iter().find(|r| r.id == t.id);
            Polled {
                id: t.id.clone(),
                name: t.name.clone(),
                address: t.address.clone(),
                last_ok: row.and_then(|r| r.last_ok),
                error: row.and_then(|r| r.error.clone()),
                snapshot: row.and_then(|r| r.snapshot.as_deref()).and_then(|j| serde_json::from_str(j).ok()),
            }
        })
        .collect())
}

/// Background task: poll each enabled switch when it is due.
pub async fn run(store: Arc<dyn Store>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tokio::time::sleep(Duration::from_secs(45)).await;
    loop {
        tick.tick().await;
        let s = store.clone();
        let Ok(Ok((cfg, rows))) = tokio::task::spawn_blocking(move || -> Result<_> { Ok((load(&*s)?, s.list_topo()?)) }).await else { continue };
        let now = crate::model::now_ts();
        for t in cfg.targets.iter().filter(|t| t.enabled) {
            let last = rows.iter().find(|r| r.id == t.id).map_or(0, |r| r.last_poll);
            if now - last >= cfg.interval_secs as i64 {
                if let Err(e) = poll_and_store(&store, t, now).await {
                    tracing::debug!("polling switch {} failed: {e}", t.name);
                }
            }
        }
        // forget the polls of switches that were removed from the list
        let known: std::collections::HashSet<&str> = cfg.targets.iter().map(|t| t.id.as_str()).collect();
        for r in rows.iter().filter(|r| !known.contains(r.id.as_str())) {
            let (s, id) = (store.clone(), r.id.clone());
            let _ = tokio::task::spawn_blocking(move || s.delete_topo(&id)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(id: &str, community: &str) -> Target {
        Target { id: id.into(), name: " Core ".into(), address: "192.0.2.10".into(), community: community.into(), enabled: true }
    }

    #[test]
    fn a_switch_is_checked_and_a_blank_community_keeps_the_stored_one() {
        assert_eq!(t("core1", " s3cret ").check().unwrap().name, "Core");
        assert_eq!(t("core1", "x").check().unwrap().community, "x");
        assert_eq!(Target { address: "192.0.2.10:1161".into(), ..t("a", "x") }.check().unwrap().address, "192.0.2.10:1161");
        assert_eq!(Target { address: "192.0.2.10:161".into(), ..t("a", "x") }.check().unwrap().address, "192.0.2.10", "the default port is not spelled out");
        for bad in [Target { id: "Has Space".into(), ..t("a", "x") }, Target { name: "".into(), ..t("a", "x") }, Target { address: "switch.example".into(), ..t("a", "x") },
            Target { address: "0.0.0.0".into(), ..t("a", "x") }, Target { address: "224.0.0.1".into(), ..t("a", "x") }, Target { community: "a".repeat(65), ..t("a", "x") }] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        let mut c = Config::default();
        assert!(c.update(None, &[t("core1", "")]).is_err(), "a new switch needs a community");
        c.update(Some(120), &[t("core1", "s3cret")]).unwrap();
        assert_eq!((c.interval_secs, c.targets[0].community.as_str()), (120, "s3cret"));
        c.update(None, &[Target { name: "Renamed".into(), ..t("core1", "") }, t("core2", "other")]).unwrap();
        assert_eq!((c.targets[0].name.as_str(), c.targets[0].community.as_str(), c.targets.len()), ("Renamed", "s3cret", 2), "blank keeps the old secret");
        let before = c.clone();
        assert!(c.update(None, &[t("core1", "x"), t("core1", "y")]).is_err(), "ids must be unique");
        assert!(c.update(Some(5), &[]).is_err() && c.update(Some(99_999), &[]).is_err());
        assert!(c.update(None, &(0..51).map(|i| t(&format!("s{i}"), "x")).collect::<Vec<_>>()).is_err());
        assert_eq!(c, before, "a refused change leaves everything as it was");
    }

    #[tokio::test]
    async fn a_poll_is_stored_and_a_failed_one_keeps_the_last_good_answer() {
        use crate::snmp::{agent, oid, Value};
        use crate::store::sqlite::SqliteStore;
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut mib = std::collections::BTreeMap::new();
        mib.insert(oid("1.3.6.1.2.1.1.5.0"), Value::Str(b"sw1".to_vec()));
        mib.insert(oid("1.3.6.1.2.1.1.1.0"), Value::Str(b"Acme".to_vec()));
        mib.insert(oid("1.3.6.1.2.1.31.1.1.1.1.1"), Value::Str(b"Gi1".to_vec()));
        let a = agent::start("ro", mib, false);
        let good = Target { address: a.addr.to_string(), ..t("sw1", "ro") };
        let snap = poll_and_store(&store, &good, 100).await.unwrap();
        assert_eq!((snap.sys_name.as_str(), snap.ports.len()), ("sw1", 1));
        let cfg = Config { interval_secs: 300, targets: vec![good.clone()] };
        let p = polled(&*store, &cfg).unwrap();
        assert_eq!((p[0].last_ok, p[0].error.clone(), p[0].snapshot.as_ref().map(|s| s.sys_name.clone())), (Some(100), None, Some("sw1".into())));
        // the switch stops answering (wrong community now): the error is kept beside the old snapshot
        let bad = Target { community: "wrong".into(), ..good };
        let e = poll_and_store(&store, &bad, 200).await.unwrap_err();
        assert!(e.contains("no answer"), "{e}");
        let p = polled(&*store, &cfg).unwrap();
        assert_eq!((p[0].last_ok, p[0].snapshot.is_some()), (Some(100), true));
        assert!(p[0].error.as_deref().unwrap().contains("no answer"));
        // a switch never polled is still listed
        let both = Config { targets: vec![cfg.targets[0].clone(), t("core2", "x")], ..cfg };
        assert_eq!(polled(&*store, &both).unwrap().len(), 2);
        store.delete_topo("sw1").unwrap();
        assert!(store.list_topo().unwrap().is_empty());
    }
}
