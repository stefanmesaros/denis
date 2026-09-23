//! General data-retention setting (Settings → Data retention): how long events/alerts and trend
//! samples are kept before the engine purges them. Configurable from the console at any time,
//! takes effect within the hour (the same loop that already pruned trend metrics), no restart.
//!
//! Until an administrator saves a value here, the `--retention-days` CLI flag (default 90) keeps
//! deciding it, so nothing changes for an existing installation that never opens this page.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::store::Store;

pub const SETTINGS_KEY: &str = "retention";
pub const MIN_DAYS: i64 = 1;
pub const MAX_DAYS: i64 = 1095; // 3 years
pub const DEFAULT_DAYS: i64 = 180; // 6 months

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub days: i64,
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_DAYS..=MAX_DAYS).contains(&self.days) {
            bail!("keep data for between {MIN_DAYS} and {MAX_DAYS} days");
        }
        Ok(())
    }
}

/// The value to actually use: a saved GUI setting if there is a valid one, else `cli_default_days`
/// (clamped into range, so an old `--retention-days 3650` does not silently become unbounded).
pub fn effective_days(store: &dyn Store, cli_default_days: i64) -> i64 {
    load(store).map(|s| s.days).unwrap_or_else(|_| cli_default_days.clamp(MIN_DAYS, MAX_DAYS))
}

/// `None` when nothing has been saved yet, or what was saved is no longer valid.
pub fn load(store: &dyn Store) -> Result<Settings> {
    let Some(b) = store.get_setting(SETTINGS_KEY)? else { bail!("not set") };
    let s: Settings = serde_json::from_slice(&b)?;
    s.validate()?;
    Ok(s)
}

pub fn save(store: &dyn Store, s: &Settings, ts: i64) -> Result<()> {
    s.validate()?;
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(s)?, ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn unset_falls_back_to_the_clamped_cli_default_and_a_saved_value_is_validated() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(effective_days(&store, 90), 90);
        assert_eq!(effective_days(&store, 5000), MAX_DAYS, "an old unbounded CLI value is clamped");
        assert_eq!(effective_days(&store, 0), MIN_DAYS);

        assert!(save(&store, &Settings { days: 0 }, 1).is_err());
        assert!(save(&store, &Settings { days: 2000 }, 1).is_err());
        save(&store, &Settings { days: 30 }, 1).unwrap();
        assert_eq!(effective_days(&store, 90), 30, "the saved value wins once set");
    }
}
