//! The capture interface(s), settable from Settings instead of only via
//! `--iface`/`--mirror-iface` on the command line.
//!
//! Like a pasted license, a GUI-set value here takes priority over the
//! matching CLI flag, so a systemd unit's flags stay a sensible bootstrap
//! default while the console remains the place to actually change it. Unlike
//! a license, though, a change here only takes effect after DENIS restarts:
//! capture is opened once, at start-up, and there is no live hand-off between
//! `pcap` handles — the console says so.
//!
//! There is always at most one **discovery** interface (`iface`): it is the
//! one place ARP sweeps, port scans and the sweep target range come from, so
//! more than one would mean more than one notion of "the subnet", which the
//! inventory does not support (that is what remote agents are for). There can
//! be any number of **mirror** interfaces (`mirror_ifaces`): each is opened
//! capture-only, on the same footing, feeding the same flow accounting — one
//! switch mirror/SPAN port per VLAN, say, all on one box, no agent needed.

use crate::store::Store;

pub const IFACE_KEY: &str = "capture.iface";
pub const MIRROR_KEY: &str = "capture.mirror_ifaces";

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
}
