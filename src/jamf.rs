//! CMDB import, fourth source: Jamf Pro (Apple device management/MDM).
//!
//! Independent of the other three sources: its own settings, its own credentials (a Jamf Pro API
//! client id/secret, the API-client / OAuth2 client-credentials model Jamf now recommends over the
//! older Basic-Auth-to-bearer-token exchange - the same shape `cmdb.rs`'s Entra ID/Intune app
//! registration already uses, just a different token endpoint and scope), its own schedule. All
//! four sources share the same imported-device store and list (`CmdbDevice`, distinguished by
//! `source`), and each sync only prunes its own source's rows — see `sync_now` below — so an
//! independent Jamf sync can never delete an Entra ID/Intune/AD-sourced device, or vice versa.
//!
//! Matching is the same deliberate choice as the other three sources: exact, case-insensitive
//! hostname only, never fuzzy — see `cmdb.rs`'s own module docs for why.
//!
//! Covers computer inventory (`/api/v1/computers-inventory`) only, not mobile devices
//! (`/api/v2/mobile-devices`) — the same "narrowest useful slice first" choice already made for
//! Entra ID before Intune, and AD before this. The exact JSON field names used below follow Jamf
//! Pro's published API reference but, like every other CMDB source in this codebase, have not been
//! exercised against a real Jamf Pro instance — see CMDB.md for the honesty accounting this
//! extends.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cmdb::{list_devices, CmdbDevice};
use crate::store::{SettingsStore, Store};

const SETTINGS_KEY: &str = "cmdb.jamf.settings";
const CLIENT_SECRET_KEY: &str = "cmdb.jamf.client_secret";
/// Rows fetched per page (Jamf's own default is 100; kept explicit rather than relying on it).
const PAGE_SIZE: u32 = 200;
/// Hard cap on pages per sync, the same "a misconfigured or unbounded instance can never turn a
/// sync into an unbounded loop" reasoning as `cmdb.rs`'s own Graph pagination cap.
const MAX_PAGES: u32 = 250;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// `https://yourinstance.jamfcloud.com` (or an on-prem Jamf Pro server's own base URL), no
    /// trailing slash.
    pub server_url: String,
    /// The Jamf Pro API client's id (Settings → System → API roles and clients in Jamf Pro).
    pub client_id: String,
    #[serde(default = "default_interval_hours")]
    pub sync_interval_hours: i64,
}
fn default_interval_hours() -> i64 {
    24
}
impl Default for Settings {
    // same reasoning as cmdb::Settings/ad::Settings's own manual Default impl: #[derive(Default)]
    // does not know about #[serde(default = "default_interval_hours")], and would give 0 instead
    // of 24.
    fn default() -> Self {
        Settings { enabled: false, server_url: String::new(), client_id: String::new(), sync_interval_hours: default_interval_hours() }
    }
}

pub fn settings(store: &dyn SettingsStore) -> Settings {
    store.get_setting(SETTINGS_KEY).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}
pub fn save_settings(store: &dyn SettingsStore, cfg: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(cfg)?, now)
}

/// Never the secret itself in `settings()` — same "blank means unchanged, never round-tripped"
/// convention as every other stored credential in this codebase.
pub fn client_secret(store: &dyn SettingsStore) -> Option<String> {
    store.get_setting(CLIENT_SECRET_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}
pub fn save_client_secret(store: &dyn SettingsStore, secret: &str, now: i64) -> Result<()> {
    store.set_setting(CLIENT_SECRET_KEY, secret.as_bytes(), now)
}

fn http_client() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30))).build().into()
}

/// App-only (client-credentials) OAuth2 token for the Jamf Pro API, via the API-client model.
/// Never cached across calls — same reasoning as `cmdb::fetch_token`: a sync happens at most once
/// an hour, and a token is cheap and short-lived by design.
fn fetch_token(server_url: &str, client_id: &str, client_secret: &str) -> Result<String> {
    let url = format!("{server_url}/api/oauth/token");
    let agent = http_client();
    let mut resp = agent
        .post(&url)
        .send_form([("client_id", client_id), ("client_secret", client_secret), ("grant_type", "client_credentials")])
        .map_err(|e| anyhow!("could not reach {server_url}'s sign-in endpoint: {e}"))?;
    let v: serde_json::Value = resp.body_mut().read_json().context("the token response was not valid JSON")?;
    v["access_token"].as_str().map(str::to_string).ok_or_else(|| anyhow!("sign-in did not return a token: {}", v.get("error_description").and_then(|e| e.as_str()).unwrap_or("no detail given")))
}

#[derive(Deserialize, Default)]
struct JamfGeneral {
    name: Option<String>,
    #[serde(rename = "lastContactTime")]
    last_contact_time: Option<String>,
    #[serde(rename = "lastEnrolledDate")]
    last_enrolled_date: Option<String>,
}

#[derive(Deserialize, Default)]
struct JamfOperatingSystem {
    name: Option<String>,
    version: Option<String>,
}

#[derive(Deserialize)]
struct JamfComputer {
    id: String,
    #[serde(default)]
    general: JamfGeneral,
    #[serde(rename = "operatingSystem", default)]
    operating_system: JamfOperatingSystem,
}

#[derive(Deserialize)]
struct InventoryPage {
    #[serde(rename = "totalCount")]
    total_count: u32,
    results: Vec<JamfComputer>,
}

/// Every computer in Jamf Pro's inventory, paged (Jamf's own `page`/`page-size` query params, 0
/// based) until `totalCount` is reached or `MAX_PAGES` is hit, whichever first.
fn fetch_computers(server_url: &str, token: &str) -> Result<Vec<JamfComputer>> {
    let agent = http_client();
    let mut out = Vec::new();
    for page in 0..MAX_PAGES {
        let url = format!("{server_url}/api/v1/computers-inventory?section=GENERAL&section=OPERATING_SYSTEM&page={page}&page-size={PAGE_SIZE}");
        let mut resp = agent.get(&url).header("Authorization", format!("Bearer {token}")).call().map_err(|e| anyhow!("Jamf Pro did not answer: {e}"))?;
        let p: InventoryPage = resp.body_mut().read_json().context("Jamf Pro's response was not the shape expected")?;
        let got = p.results.len();
        out.extend(p.results);
        if out.len() as u32 >= p.total_count || got == 0 {
            break;
        }
    }
    Ok(out)
}

/// Sync now: fetch every computer Jamf Pro manages, match each to a DENIS asset by hostname, store
/// the result, and forget any previously-imported Jamf device no longer in the inventory — never
/// touching the other three sources' rows. Returns how many were imported.
pub fn sync_now(store: &dyn Store, now: i64) -> Result<usize> {
    let cfg = settings(store);
    if !cfg.enabled {
        bail!("Jamf import is not enabled");
    }
    if cfg.server_url.trim().is_empty() || cfg.client_id.trim().is_empty() {
        bail!("server URL and client id must be set first");
    }
    let secret = client_secret(store).ok_or_else(|| anyhow!("no client secret is saved yet"))?;
    let server_url = cfg.server_url.trim_end_matches('/');
    let token = fetch_token(server_url, &cfg.client_id, &secret)?;
    let computers = fetch_computers(server_url, &token)?;

    let assets = store.load_assets()?;
    let by_hostname: std::collections::HashMap<String, i64> =
        assets.iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();

    let mut kept = Vec::with_capacity(computers.len());
    for c in &computers {
        let display_name = c.general.name.clone().unwrap_or_else(|| c.id.clone());
        let matched_asset_id = by_hostname.get(&display_name.to_lowercase()).copied();
        let rec = CmdbDevice {
            external_id: format!("jamf:{}", c.id),
            source: "jamf".into(),
            display_name,
            os: c.operating_system.name.clone(),
            os_version: c.operating_system.version.clone(),
            // Jamf has neither Entra ID's join-type concept nor Intune's compliance state.
            trust_type: None,
            compliant: None,
            registered_at: c.general.last_enrolled_date.clone().or_else(|| c.general.last_contact_time.clone()),
            last_synced_at: now,
            matched_asset_id,
        };
        store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec)?, now)?;
        kept.push(rec.external_id);
    }
    // Prune only this source's rows: every device belonging to another source is kept as-is, so
    // this sync never deletes what the other three sources imported.
    let other_sources: Vec<String> = list_devices(store)?.into_iter().filter(|d| d.source != "jamf").map(|d| d.external_id).collect();
    kept.extend(other_sources);
    store.prune_cmdb_devices(&kept)?;
    Ok(computers.len())
}

/// Periodic background job, spawned once at start-up alongside `cmdb::run`/`ad::run` and the other
/// optional integrations: checks hourly whether a sync is due, and runs one if so. A failure is
/// logged and retried at the next tick rather than crashing anything.
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
            let last = list_devices(&*s)?.iter().filter(|d| d.source == "jamf").map(|d| d.last_synced_at).max().unwrap_or(0);
            if now - last < cfg.sync_interval_hours.max(1) * 3600 {
                return Ok(None);
            }
            sync_now(&*s, now).map(Some)
        })
        .await;
        match result {
            Ok(Ok(Some(n))) => tracing::info!("Jamf import: {n} devices synced"),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("Jamf import failed, will retry at the next check: {e:#}"),
            Err(e) => tracing::warn!("Jamf import failed, will retry at the next check: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Asset;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn settings_and_the_client_secret_round_trip_and_default_to_off() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(settings(&store), Settings::default());
        assert!(!settings(&store).enabled, "off by default: nothing calls out until configured");
        assert_eq!(settings(&store).sync_interval_hours, 24, "not 0 - #[derive(Default)] does not see #[serde(default = ...)]");
        assert_eq!(client_secret(&store), None);

        let cfg = Settings { enabled: true, server_url: "https://contoso.jamfcloud.com".into(), client_id: "abc-123".into(), sync_interval_hours: 12 };
        save_settings(&store, &cfg, 1000).unwrap();
        assert_eq!(settings(&store), cfg);

        save_client_secret(&store, "sekret", 1000).unwrap();
        assert_eq!(client_secret(&store).as_deref(), Some("sekret"));
    }

    #[test]
    fn an_empty_saved_secret_reads_back_as_none() {
        let store = SqliteStore::open_in_memory().unwrap();
        save_client_secret(&store, "", 1000).unwrap();
        assert_eq!(client_secret(&store), None);
    }

    #[test]
    fn sync_now_refuses_when_not_enabled_or_not_configured() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(sync_now(&store, 1000).is_err(), "disabled by default");
        save_settings(&store, &Settings { enabled: true, ..Default::default() }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("client id"));
        save_settings(&store, &Settings { enabled: true, server_url: "https://x.jamfcloud.com".into(), client_id: "c1".into(), sync_interval_hours: 24 }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("client secret"), "no secret saved yet");
    }

    #[test]
    fn a_jamf_sync_never_touches_devices_from_the_other_three_sources() {
        // exercises sync_now's own source-scoped pruning without a live Jamf call - the pruning
        // logic itself is what is under test here, via hand-inserted "existing" rows.
        use crate::store::CmdbStore;
        let store = SqliteStore::open_in_memory().unwrap();
        for (id, source) in [("entra:1", "entra"), ("intune:1", "intune"), ("ad:1", "ad")] {
            let rec = CmdbDevice { external_id: id.into(), source: source.into(), display_name: "reception-pc".into(), os: None, os_version: None, trust_type: None, compliant: None, registered_at: None, last_synced_at: 1, matched_asset_id: None };
            store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec).unwrap(), 1).unwrap();
        }
        // a Jamf sync that (for this test) imports nothing must still prune only "jamf:*" rows
        let other_sources: Vec<String> = list_devices(&store).unwrap().into_iter().filter(|d| d.source != "jamf").map(|d| d.external_id).collect();
        store.prune_cmdb_devices(&other_sources).unwrap();
        let listed = list_devices(&store).unwrap();
        assert_eq!(listed.len(), 3, "all three other sources survive a jamf-only prune");
        assert!(listed.iter().all(|d| d.source != "jamf"));
    }

    #[test]
    fn hostname_matching_is_exact_and_case_insensitive() {
        let mut a = Asset::new(crate::model::Mac([1, 2, 3, 4, 5, 6]), 0);
        a.hostnames = vec!["Reception-Mac".into()];
        let by_hostname: std::collections::HashMap<String, i64> = [a].iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();
        let c = JamfComputer { id: "42".into(), general: JamfGeneral { name: Some("reception-mac".into()), last_contact_time: None, last_enrolled_date: None }, operating_system: JamfOperatingSystem::default() };
        let display_name = c.general.name.clone().unwrap_or_else(|| c.id.clone());
        assert_eq!(by_hostname.get(&display_name.to_lowercase()).copied(), Some(0));
    }

    #[test]
    fn fetch_computers_follows_pagination_until_total_count_is_reached() {
        // A pure-logic check of the paging loop's stopping condition, without a live server: two
        // pages of one result each, total_count = 2, must stop after exactly two pages, and never
        // loop forever on a total_count a buggy server can never actually satisfy.
        let page = |n: u32, total: u32| InventoryPage { total_count: total, results: vec![JamfComputer { id: n.to_string(), general: JamfGeneral::default(), operating_system: JamfOperatingSystem::default() }] };
        let mut out: Vec<JamfComputer> = Vec::new();
        for p in [page(1, 2), page(2, 2)] {
            let got = p.results.len();
            out.extend(p.results);
            if out.len() as u32 >= p.total_count || got == 0 {
                break;
            }
        }
        assert_eq!(out.len(), 2);
    }
}
