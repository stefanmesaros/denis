//! The capture interface(s) and the agent ingest listener, settable from Settings instead of only
//! via `--iface`/`--mirror-iface`/`--ingest-listen` on the command line.
//!
//! Like a pasted license, a GUI-set value here takes priority over the
//! matching CLI flag, so a systemd unit's flags stay a sensible bootstrap
//! default while the console remains the place to actually change it. Unlike
//! a license, though, a change here only takes effect after DENIS restarts:
//! capture is opened once, at start-up, and there is no live hand-off between
//! `pcap` handles — the console says so. The ingest listener is bound once at
//! start-up too (whether this process is "standalone" or "master" is decided
//! then, and a fair amount downstream assumes it does not change mid-run),
//! so it follows the exact same restart-required convention as the
//! interfaces above it, not the "takes effect within seconds" one most other
//! settings in this codebase have.
//!
//! There is always at most one **discovery** interface (`iface`): it is the
//! one place ARP sweeps, port scans and the sweep target range come from, so
//! more than one would mean more than one notion of "the subnet", which the
//! inventory does not support (that is what remote agents are for). There can
//! be any number of **mirror** interfaces (`mirror_ifaces`): each is opened
//! capture-only, on the same footing, feeding the same flow accounting — one
//! switch mirror/SPAN port per VLAN, say, all on one box, no agent needed.

use std::net::SocketAddr;

use crate::store::Store;

pub const IFACE_KEY: &str = "capture.iface";
pub const MIRROR_KEY: &str = "capture.mirror_ifaces";
pub const INGEST_LISTEN_KEY: &str = "capture.ingest_listen";

/// The GUI-configured interfaces, if any were set.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Configured {
    pub iface: Option<String>,
    /// `None` = no GUI override (fall back to the CLI/env value); `Some(v)` overrides it, even
    /// with `v` empty (explicitly "no mirror interfaces").
    pub mirror_ifaces: Option<Vec<String>>,
}

pub fn load(store: &dyn Store) -> Configured {
    Configured {
        iface: get_str(store, IFACE_KEY),
        mirror_ifaces: get_list(store, MIRROR_KEY),
    }
}

/// Persist the GUI's choice. `iface: None` clears that override, falling back to the
/// CLI/auto-detected value again. `mirror_ifaces: None` likewise clears the override; `Some(&[])`
/// is a deliberate override to "no mirror interfaces" (distinct from never having set one).
pub fn save(store: &dyn Store, iface: Option<&str>, mirror_ifaces: Option<&[String]>, now: i64) -> anyhow::Result<()> {
    match iface.filter(|s| !s.is_empty()) {
        Some(v) => store.set_setting(IFACE_KEY, v.as_bytes(), now)?,
        None => {
            store.delete_setting(IFACE_KEY)?;
        }
    }
    match mirror_ifaces {
        Some(list) => store.set_setting(MIRROR_KEY, serde_json::to_string(list)?.as_bytes(), now)?,
        None => {
            store.delete_setting(MIRROR_KEY)?;
        }
    }
    Ok(())
}

/// A GUI-set value wins over the CLI/env value; otherwise the CLI/env value (which may itself be
/// empty/`None`, meaning auto-detect / no mirrors) is kept.
pub fn effective(store: &dyn Store, cli_iface: Option<String>, cli_mirrors: Vec<String>) -> (Option<String>, Vec<String>) {
    let c = load(store);
    (c.iface.or(cli_iface), c.mirror_ifaces.unwrap_or(cli_mirrors))
}

/// The GUI-configured ingest listener, if any override was saved: `None` = no override (fall
/// back to the CLI/env value); `Some(None)` = a deliberate override to "no ingest listener"
/// (standalone), distinct from never having set one; `Some(Some(addr))` = a deliberate address,
/// same three-state shape `mirror_ifaces` already uses above.
pub fn ingest_listen_override(store: &dyn Store) -> Option<Option<SocketAddr>> {
    let raw = store.get_setting(INGEST_LISTEN_KEY).ok().flatten()?;
    let s = String::from_utf8_lossy(&raw);
    if s.is_empty() {
        return Some(None);
    }
    s.parse().ok().map(Some)
}

/// Persist the GUI's choice. `addr: None` clears the override, falling back to the CLI/env value
/// again; `Some(None)` is a deliberate override to "no ingest listener"; `Some(Some(a))` sets one.
pub fn save_ingest_listen(store: &dyn Store, addr: Option<Option<SocketAddr>>, now: i64) -> anyhow::Result<()> {
    match addr {
        None => {
            store.delete_setting(INGEST_LISTEN_KEY)?;
        }
        Some(None) => store.set_setting(INGEST_LISTEN_KEY, b"", now)?,
        Some(Some(a)) => store.set_setting(INGEST_LISTEN_KEY, a.to_string().as_bytes(), now)?,
    }
    Ok(())
}

/// A GUI-set value wins over the CLI/env value, even a deliberate "off"; otherwise the CLI/env
/// value (which may itself be `None`, meaning standalone) is kept.
pub fn effective_ingest_listen(store: &dyn Store, cli: Option<SocketAddr>) -> Option<SocketAddr> {
    ingest_listen_override(store).unwrap_or(cli)
}

fn get_str(store: &dyn Store, key: &str) -> Option<String> {
    store
        .get_setting(key)
        .ok()
        .flatten()
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .filter(|s| !s.is_empty())
}

fn get_list(store: &dyn Store, key: &str) -> Option<Vec<String>> {
    store.get_setting(key).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    fn mem() -> SqliteStore {
        SqliteStore::open_in_memory().unwrap()
    }

    #[test]
    fn no_override_falls_back_to_the_cli_values() {
        let s = mem();
        assert_eq!(effective(&s, Some("eth0".into()), vec![]), (Some("eth0".into()), vec![]));
        assert_eq!(effective(&s, None, vec!["eth1".into()]), (None, vec!["eth1".into()]));
    }

    #[test]
    fn a_saved_override_wins_over_the_cli_value_and_can_be_cleared() {
        let s = mem();
        save(&s, Some("eth1"), Some(&["eth2".into(), "eth3".into()]), 1).unwrap();
        assert_eq!(effective(&s, Some("eth0".into()), vec![]), (Some("eth1".into()), vec!["eth2".into(), "eth3".into()]));

        // an explicit empty override means "no mirrors", distinct from "not configured"
        save(&s, None, Some(&[]), 2).unwrap();
        assert_eq!(effective(&s, Some("eth0".into()), vec!["eth9".into()]), (Some("eth0".into()), vec![]));

        // clearing the override (None) falls back to the CLI list again
        save(&s, None, None, 3).unwrap();
        assert_eq!(effective(&s, Some("eth0".into()), vec!["eth9".into()]), (Some("eth0".into()), vec!["eth9".into()]));
    }

    #[test]
    fn an_empty_string_clears_the_iface_override_just_like_none() {
        let s = mem();
        save(&s, Some("eth1"), None, 1).unwrap();
        save(&s, Some(""), None, 2).unwrap();
        assert_eq!(effective(&s, Some("eth0".into()), vec![]), (Some("eth0".into()), vec![]));
    }

    #[test]
    fn ingest_listen_has_no_override_falls_back_to_cli_by_default() {
        let s = mem();
        let cli: std::net::SocketAddr = "127.0.0.1:8081".parse().unwrap();
        assert_eq!(effective_ingest_listen(&s, Some(cli)), Some(cli));
        assert_eq!(effective_ingest_listen(&s, None), None);
    }

    #[test]
    fn a_saved_ingest_listen_address_wins_over_cli_and_can_be_cleared() {
        let s = mem();
        let gui: std::net::SocketAddr = "0.0.0.0:8081".parse().unwrap();
        let cli: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        save_ingest_listen(&s, Some(Some(gui)), 1).unwrap();
        assert_eq!(effective_ingest_listen(&s, Some(cli)), Some(gui));
        assert_eq!(effective_ingest_listen(&s, None), Some(gui), "wins even when the CLI had none at all");

        // clearing the override (None) falls back to the CLI value again
        save_ingest_listen(&s, None, 2).unwrap();
        assert_eq!(effective_ingest_listen(&s, Some(cli)), Some(cli));
    }

    #[test]
    fn an_explicit_off_override_wins_even_over_a_cli_address() {
        let s = mem();
        let cli: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        save_ingest_listen(&s, Some(None), 1).unwrap();
        assert_eq!(effective_ingest_listen(&s, Some(cli)), None, "a deliberate override to off beats a CLI flag that turned it on");
    }
}
