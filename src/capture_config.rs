//! The capture interface(s), settable from Settings instead of only via
//! `--iface`/`--mirror-iface` on the command line.
//!
//! Like a pasted license, a GUI-set value here takes priority over the
//! matching CLI flag, so a systemd unit's flags stay a sensible bootstrap
//! default while the console remains the place to actually change it. Unlike
//! a license, though, a change here only takes effect after DENIS restarts:
//! capture is opened once, at start-up, and there is no live hand-off between
//! `pcap` handles — the console says so.

use crate::store::Store;

pub const IFACE_KEY: &str = "capture.iface";
pub const MIRROR_KEY: &str = "capture.mirror_iface";

/// The GUI-configured interface names, if any were set (an empty string, or
/// none set, means "no override").
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Configured {
    pub iface: Option<String>,
    pub mirror_iface: Option<String>,
}

pub fn load(store: &dyn Store) -> Configured {
    Configured {
        iface: get(store, IFACE_KEY),
        mirror_iface: get(store, MIRROR_KEY),
    }
}

/// Persist the GUI's choice. `None` clears that override, falling back to
/// the CLI/auto-detected value again.
pub fn save(store: &dyn Store, iface: Option<&str>, mirror_iface: Option<&str>, now: i64) -> anyhow::Result<()> {
    match iface.filter(|s| !s.is_empty()) {
        Some(v) => store.set_setting(IFACE_KEY, v.as_bytes(), now)?,
        None => {
            store.delete_setting(IFACE_KEY)?;
        }
    }
    match mirror_iface.filter(|s| !s.is_empty()) {
        Some(v) => store.set_setting(MIRROR_KEY, v.as_bytes(), now)?,
        None => {
            store.delete_setting(MIRROR_KEY)?;
        }
    }
    Ok(())
}

/// A GUI-set value (non-empty) wins over the CLI/env value; otherwise the
/// CLI/env value (which may itself be `None`, meaning auto-detect) is kept.
pub fn effective(store: &dyn Store, cli_iface: Option<String>, cli_mirror: Option<String>) -> (Option<String>, Option<String>) {
    let c = load(store);
    (c.iface.or(cli_iface), c.mirror_iface.or(cli_mirror))
}

fn get(store: &dyn Store, key: &str) -> Option<String> {
    store
        .get_setting(key)
        .ok()
        .flatten()
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .filter(|s| !s.is_empty())
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
        assert_eq!(effective(&s, Some("eth0".into()), None), (Some("eth0".into()), None));
        assert_eq!(effective(&s, None, None), (None, None));
    }

    #[test]
    fn a_saved_override_wins_over_the_cli_value_and_can_be_cleared() {
        let s = mem();
        save(&s, Some("eth1"), Some("eth2"), 1).unwrap();
        assert_eq!(effective(&s, Some("eth0".into()), None), (Some("eth1".into()), Some("eth2".into())));

        // clearing one leaves the other alone
        save(&s, None, Some("eth2"), 2).unwrap();
        assert_eq!(effective(&s, Some("eth0".into()), None), (Some("eth0".into()), Some("eth2".into())));

        save(&s, None, None, 3).unwrap();
        assert_eq!(effective(&s, Some("eth0".into()), None), (Some("eth0".into()), None));
    }

    #[test]
    fn an_empty_string_clears_an_override_just_like_none() {
        let s = mem();
        save(&s, Some("eth1"), None, 1).unwrap();
        save(&s, Some(""), None, 2).unwrap();
        assert_eq!(effective(&s, Some("eth0".into()), None), (Some("eth0".into()), None));
    }
}
