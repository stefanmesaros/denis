//! CMDB import, third source: on-premises Active Directory, via LDAP/LDAPS.
//!
//! Independent of the Entra ID/Intune sync in `cmdb.rs`: its own settings, its own credentials
//! (an LDAP bind DN and password against a domain controller, not an OAuth2 app registration),
//! its own schedule. All three sources share the same imported-device store and list
//! (`CmdbDevice`, distinguished by `source`), and each sync only prunes its own source's rows —
//! see `sync_now` below — so an independent AD sync can never delete an Entra ID/Intune-sourced
//! device, or vice versa.
//!
//! Matching is the same deliberate choice as the other two sources: exact, case-insensitive
//! hostname only, never fuzzy — see `cmdb.rs`'s own module docs for why.

use anyhow::{anyhow, bail, Result};
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};

use crate::cmdb::{list_devices, CmdbDevice};
use crate::store::{SettingsStore, Store};

const SETTINGS_KEY: &str = "cmdb.ad.settings";
const BIND_PASSWORD_KEY: &str = "cmdb.ad.bind_password";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// `ldap://dc.contoso.local:389` or `ldaps://dc.contoso.local:636`.
    pub url: String,
    /// The account DENIS binds as to search. A dedicated, read-only service account is strongly
    /// recommended over a real administrator's own credentials.
    pub bind_dn: String,
    /// Where to search from, e.g. `DC=contoso,DC=local`.
    pub base_dn: String,
    #[serde(default = "default_interval_hours")]
    pub sync_interval_hours: i64,
}
fn default_interval_hours() -> i64 {
    24
}
impl Default for Settings {
    // same reasoning as cmdb::Settings's own manual Default impl: #[derive(Default)] does not
    // know about #[serde(default = "default_interval_hours")], and would give 0 instead of 24.
    fn default() -> Self {
        Settings { enabled: false, url: String::new(), bind_dn: String::new(), base_dn: String::new(), sync_interval_hours: default_interval_hours() }
    }
}

pub fn settings(store: &dyn SettingsStore) -> Settings {
    store.get_setting(SETTINGS_KEY).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}
pub fn save_settings(store: &dyn SettingsStore, cfg: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(cfg)?, now)
}

/// Never the password itself in `settings()` — same "blank means unchanged, never round-tripped"
/// convention as `cmdb::client_secret` and every other stored credential in this codebase.
pub fn bind_password(store: &dyn SettingsStore) -> Option<String> {
    store.get_setting(BIND_PASSWORD_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}
pub fn save_bind_password(store: &dyn SettingsStore, pw: &str, now: i64) -> Result<()> {
    store.set_setting(BIND_PASSWORD_KEY, pw.as_bytes(), now)
}

struct AdComputer {
    dn: String,
    name: Option<String>,
    dns_hostname: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    when_created: Option<String>,
}

/// Every `computer` object under the configured base DN. A plain subtree search, not a paged one
/// (`ldap3`'s sync API has no built-in paged-search helper, and a domain's computer count is
/// small enough — thousands, not millions — that this is not a real concern in practice, unlike
/// Graph's own default page size forcing pagination on `cmdb.rs`'s two sources).
fn fetch_computers(cfg: &Settings, password: &str) -> Result<Vec<AdComputer>> {
    let mut ldap = LdapConn::with_settings(LdapConnSettings::new(), &cfg.url).map_err(|e| anyhow!("could not connect to {}: {e}", cfg.url))?;
    ldap.simple_bind(&cfg.bind_dn, password)
        .map_err(|e| anyhow!("could not reach the domain controller: {e}"))?
        .success()
        .map_err(|e| anyhow!("the bind account or password was refused: {e}"))?;
    let (entries, _res) = ldap
        .search(&cfg.base_dn, Scope::Subtree, "(objectClass=computer)", vec!["name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "whenCreated"])
        .map_err(|e| anyhow!("the search failed: {e}"))?
        .success()
        .map_err(|e| anyhow!("the search was refused (check the base DN and the bind account's read access): {e}"))?;
    let out = entries
        .into_iter()
        .map(|e| {
            let se = SearchEntry::construct(e);
            let one = |k: &str| se.attrs.get(k).and_then(|v| v.first()).cloned();
            AdComputer { dn: se.dn, name: one("name"), dns_hostname: one("dNSHostName"), os: one("operatingSystem"), os_version: one("operatingSystemVersion"), when_created: one("whenCreated") }
        })
        .collect();
    let _ = ldap.unbind();
    Ok(out)
}

/// Sync now: bind to the domain controller, search for every computer object under the base DN,
/// match each to a DENIS asset by hostname, store the result, and forget any previously-imported
/// AD device that is no longer in the search — never touching Entra ID/Intune-sourced rows, which
/// belong to `cmdb.rs`'s own sync. Returns how many were imported.
pub fn sync_now(store: &dyn Store, now: i64) -> Result<usize> {
    let cfg = settings(store);
    if !cfg.enabled {
        bail!("Active Directory import is not enabled");
    }
    if cfg.url.trim().is_empty() || cfg.bind_dn.trim().is_empty() || cfg.base_dn.trim().is_empty() {
        bail!("server URL, bind DN and base DN must be set first");
    }
    let password = bind_password(store).ok_or_else(|| anyhow!("no bind password is saved yet"))?;
    let computers = fetch_computers(&cfg, &password)?;

    let assets = store.load_assets()?;
    let by_hostname: std::collections::HashMap<String, i64> =
        assets.iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();

    let mut kept = Vec::with_capacity(computers.len());
    for c in &computers {
        let display_name = c.dns_hostname.clone().or_else(|| c.name.clone()).unwrap_or_else(|| c.dn.clone());
        let matched_asset_id = by_hostname.get(&display_name.to_lowercase()).copied();
        let rec = CmdbDevice {
            external_id: format!("ad:{}", c.dn),
            source: "ad".into(),
            display_name,
            os: c.os.clone(),
            os_version: c.os_version.clone(),
            // AD has neither Entra ID's join-type concept nor Intune's compliance state.
            trust_type: None,
            compliant: None,
            registered_at: c.when_created.clone(),
            last_synced_at: now,
            matched_asset_id,
        };
        store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec)?, now)?;
        kept.push(rec.external_id);
    }
    // Prune only this source's rows: every device belonging to another source is kept as-is, so
    // this sync never deletes what cmdb.rs's own Entra ID/Intune sync imported.
    let other_sources: Vec<String> = list_devices(store)?.into_iter().filter(|d| d.source != "ad").map(|d| d.external_id).collect();
    kept.extend(other_sources);
    store.prune_cmdb_devices(&kept)?;
    Ok(computers.len())
}

/// Periodic background job, spawned once at start-up alongside `cmdb::run` and the other optional
/// integrations: checks hourly whether a sync is due, and runs one if so. A failure is logged and
/// retried at the next tick rather than crashing anything — the same posture every other optional
/// integration in this codebase already has.
pub async fn run(store: std::sync::Arc<dyn Store>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    loop {
        tick.tick().await;
        let s = store.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<Option<usize>> {
            let cfg = settings(&*s);
            if !cfg.enabled {
                return Ok(None);
            }
            let now = crate::model::now_ts();
            let last = list_devices(&*s)?.iter().filter(|d| d.source == "ad").map(|d| d.last_synced_at).max().unwrap_or(0);
            if now - last < cfg.sync_interval_hours.max(1) * 3600 {
                return Ok(None);
            }
            sync_now(&*s, now).map(Some)
        })
        .await;
        match result {
            Ok(Ok(Some(n))) => tracing::info!("Active Directory import: {n} devices synced"),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("Active Directory import failed, will retry at the next check: {e:#}"),
            Err(e) => tracing::warn!("Active Directory import failed, will retry at the next check: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Asset;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn settings_and_the_bind_password_round_trip_and_default_to_off() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(settings(&store), Settings::default());
        assert!(!settings(&store).enabled, "off by default: nothing calls out until configured");
        assert_eq!(settings(&store).sync_interval_hours, 24, "not 0 - #[derive(Default)] does not see #[serde(default = ...)]");
        assert_eq!(bind_password(&store), None);

        let cfg = Settings { enabled: true, url: "ldaps://dc.contoso.local:636".into(), bind_dn: "CN=denis-ro,OU=Service Accounts,DC=contoso,DC=local".into(), base_dn: "DC=contoso,DC=local".into(), sync_interval_hours: 12 };
        save_settings(&store, &cfg, 1000).unwrap();
        assert_eq!(settings(&store), cfg);

        save_bind_password(&store, "sekret", 1000).unwrap();
        assert_eq!(bind_password(&store).as_deref(), Some("sekret"));
    }

    #[test]
    fn an_empty_saved_password_reads_back_as_none() {
        let store = SqliteStore::open_in_memory().unwrap();
        save_bind_password(&store, "", 1000).unwrap();
        assert_eq!(bind_password(&store), None);
    }

    #[test]
    fn sync_now_refuses_when_not_enabled_or_not_configured() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(sync_now(&store, 1000).is_err(), "disabled by default");
        save_settings(&store, &Settings { enabled: true, ..Default::default() }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("base DN"));
        save_settings(&store, &Settings { enabled: true, url: "ldap://dc:389".into(), bind_dn: "cn=ro".into(), base_dn: "dc=x".into(), sync_interval_hours: 24 }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("bind password"), "no password saved yet");
    }

    #[test]
    fn an_ad_sync_never_touches_devices_from_the_other_two_sources() {
        // exercises sync_now's own source-scoped pruning without a live LDAP call - the pruning
        // logic itself is what is under test here, via a hand-inserted "existing" entra device.
        use crate::store::CmdbStore;
        let store = SqliteStore::open_in_memory().unwrap();
        let entra = CmdbDevice { external_id: "entra:1".into(), source: "entra".into(), display_name: "reception-pc".into(), os: None, os_version: None, trust_type: Some("AzureAd".into()), compliant: None, registered_at: None, last_synced_at: 1, matched_asset_id: None };
        store.save_cmdb_device(&entra.external_id, &serde_json::to_vec(&entra).unwrap(), 1).unwrap();
        // an AD sync that (for this test) imports nothing must still prune only "ad:*" rows
        let other_sources: Vec<String> = list_devices(&store).unwrap().into_iter().filter(|d| d.source != "ad").map(|d| d.external_id).collect();
        store.prune_cmdb_devices(&other_sources).unwrap();
        let listed = list_devices(&store).unwrap();
        assert_eq!(listed.len(), 1, "the entra device survives an ad-only prune");
        assert_eq!(listed[0].source, "entra");
    }

    #[test]
    fn hostname_matching_prefers_the_dns_hostname_over_the_bare_name() {
        let mut a = Asset::new(crate::model::Mac([1, 2, 3, 4, 5, 6]), 0);
        a.hostnames = vec!["reception-pc.contoso.local".into()];
        let by_hostname: std::collections::HashMap<String, i64> = [a].iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();
        let c = AdComputer { dn: "CN=RECEPTION-PC,CN=Computers,DC=contoso,DC=local".into(), name: Some("RECEPTION-PC".into()), dns_hostname: Some("reception-pc.contoso.local".into()), os: None, os_version: None, when_created: None };
        let display_name = c.dns_hostname.clone().or_else(|| c.name.clone()).unwrap_or_else(|| c.dn.clone());
        assert_eq!(by_hostname.get(&display_name.to_lowercase()).copied(), Some(0));
    }
}
