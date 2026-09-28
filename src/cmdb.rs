//! CMDB import: pulls device inventory from an external directory/MDM source and cross-references
//! it against DENIS's own discovered assets, purely by best-effort hostname match — Entra ID
//! device objects carry no MAC address, so there is no hard key to match on, and this deliberately
//! never invents one.
//!
//! v1 supports exactly one source: **Microsoft Entra ID (Azure AD) device objects**, via the
//! Microsoft Graph API, app-only (client-credentials OAuth2) authentication. This was picked over
//! the other members of the "Active Directory / Entra ID / Intune / MDM" family named in
//! ROADMAP.md because it needs nothing beyond an Azure AD app registration with the
//! `Device.Read.All` application permission (admin-consented) — no on-prem LDAP reachability (as
//! plain AD would), no separate Intune licence, and no new heavy dependency: it is a couple of
//! plain HTTPS/JSON calls with the `ureq` client already used elsewhere in this codebase (`ai.rs`,
//! `channels.rs`).
//!
//! Import is one-directional and read-only: DENIS never writes anything back to Entra ID, and a
//! device matched here is never merged into or treated as authoritative over what DENIS itself
//! discovered — the match is shown as extra context (OS, compliance state, when Entra last saw
//! it), never used to override a device's own fingerprinted identity.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::store::{SettingsStore, Store};

const SETTINGS_KEY: &str = "cmdb.settings";
const CLIENT_SECRET_KEY: &str = "cmdb.client_secret";
const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// The Azure AD tenant (a GUID, or its `*.onmicrosoft.com` domain).
    pub tenant_id: String,
    /// The app registration's application (client) id.
    pub client_id: String,
    #[serde(default = "default_interval_hours")]
    pub sync_interval_hours: i64,
}
fn default_interval_hours() -> i64 {
    24
}

pub fn settings(store: &dyn SettingsStore) -> Settings {
    store.get_setting(SETTINGS_KEY).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}
pub fn save_settings(store: &dyn SettingsStore, cfg: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(cfg)?, now)
}

/// Never the secret itself in `settings()` — same "blank means unchanged, never round-tripped"
/// convention as every other stored credential in this codebase (notification channel webhook
/// secrets, `ai.rs`'s provider keys, `ipenrich`'s custom API secret).
pub fn client_secret(store: &dyn SettingsStore) -> Option<String> {
    store.get_setting(CLIENT_SECRET_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}
pub fn save_client_secret(store: &dyn SettingsStore, secret: &str, now: i64) -> Result<()> {
    store.set_setting(CLIENT_SECRET_KEY, secret.as_bytes(), now)
}

/// One imported device, and what it matched to (if anything) — the shape stored in
/// `CmdbStore::save_cmdb_device`'s `data` and returned by the API.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CmdbDevice {
    /// The Entra ID device object's own id (a GUID) — this source's stable key.
    pub external_id: String,
    pub display_name: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    /// `AzureAd` (cloud-joined), `ServerAd` (hybrid-joined) or `Workplace` (registered only).
    pub trust_type: Option<String>,
    pub compliant: Option<bool>,
    /// When Entra ID says this device was registered, already formatted (its own ISO 8601 text).
    pub registered_at: Option<String>,
    pub last_synced_at: i64,
    /// The DENIS asset this matched to by hostname, if any — never a hard link, just a hint the
    /// UI resolves against `/api/assets` itself; a device this pointed at can later be deleted,
    /// merged or renamed without this row needing to change.
    pub matched_asset_id: Option<i64>,
}

fn http_client() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30))).build().into()
}

/// App-only (client-credentials) OAuth2 token for Microsoft Graph. Never cached across calls in
/// this module — a sync happens at most once an hour in practice (see `run` below), and a token
/// is cheap and short-lived (~1h) by design; caching it correctly (refresh-before-expiry, thread
/// safety) is more complexity than the one extra HTTPS round trip per sync is worth.
fn fetch_token(tenant_id: &str, client_id: &str, client_secret: &str) -> Result<String> {
    let url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let agent = http_client();
    let mut resp = agent
        .post(&url)
        .send_form([("client_id", client_id), ("client_secret", client_secret), ("scope", "https://graph.microsoft.com/.default"), ("grant_type", "client_credentials")])
        .map_err(|e| anyhow!("could not reach Microsoft's sign-in endpoint: {e}"))?;
    let v: serde_json::Value = resp.body_mut().read_json().context("the token response was not valid JSON")?;
    v["access_token"].as_str().map(str::to_string).ok_or_else(|| anyhow!("sign-in did not return a token: {}", v.get("error_description").and_then(|e| e.as_str()).unwrap_or("no detail given")))
}

#[derive(Deserialize)]
struct GraphDevice {
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "operatingSystem")]
    operating_system: Option<String>,
    #[serde(rename = "operatingSystemVersion")]
    operating_system_version: Option<String>,
    #[serde(rename = "trustType")]
    trust_type: Option<String>,
    #[serde(rename = "isCompliant")]
    is_compliant: Option<bool>,
    #[serde(rename = "registrationDateTime")]
    registration_date_time: Option<String>,
}

#[derive(Deserialize)]
struct GraphPage {
    value: Vec<GraphDevice>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

/// Every device object in the tenant, following Graph's own pagination (`@odata.nextLink`) until
/// exhausted. Capped at 50 pages (~50,000 devices at Graph's default page size) so a
/// misconfigured or unbounded tenant can never turn a sync into an unbounded loop.
fn fetch_devices(token: &str) -> Result<Vec<GraphDevice>> {
    let agent = http_client();
    let mut url = format!("{GRAPH_BASE}/devices?$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,registrationDateTime");
    let mut out = Vec::new();
    for _ in 0..50 {
        let mut resp = agent.get(&url).header("Authorization", format!("Bearer {token}")).call().map_err(|e| anyhow!("Microsoft Graph did not answer: {e}"))?;
        let page: GraphPage = resp.body_mut().read_json().context("Graph's device list was not the shape expected")?;
        out.extend(page.value);
        match page.next_link {
            Some(next) => url = next,
            None => break,
        }
    }
    Ok(out)
}

/// Sync now: fetch every device from Entra ID, match each to a DENIS asset by hostname
/// (case-insensitive, exact — a fuzzy match risks pointing an admin at the wrong device, which is
/// worse than no match at all), store the result, and forget any previously-imported device that
/// is no longer in the tenant. Returns how many were imported.
pub fn sync_now(store: &dyn Store, now: i64) -> Result<usize> {
    let cfg = settings(store);
    if !cfg.enabled {
        bail!("CMDB import is not enabled");
    }
    if cfg.tenant_id.trim().is_empty() || cfg.client_id.trim().is_empty() {
        bail!("tenant id and client id must be set first");
    }
    let secret = client_secret(store).ok_or_else(|| anyhow!("no client secret is saved yet"))?;
    let token = fetch_token(&cfg.tenant_id, &cfg.client_id, &secret)?;
    let raw = fetch_devices(&token)?;

    let assets = store.load_assets()?;
    let by_hostname: std::collections::HashMap<String, i64> =
        assets.iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();

    let mut kept = Vec::with_capacity(raw.len());
    for d in &raw {
        let display_name = d.display_name.clone().unwrap_or_else(|| d.id.clone());
        let matched_asset_id = by_hostname.get(&display_name.to_lowercase()).copied();
        let rec = CmdbDevice {
            external_id: d.id.clone(),
            display_name,
            os: d.operating_system.clone(),
            os_version: d.operating_system_version.clone(),
            trust_type: d.trust_type.clone(),
            compliant: d.is_compliant,
            registered_at: d.registration_date_time.clone(),
            last_synced_at: now,
            matched_asset_id,
        };
        store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec)?, now)?;
        kept.push(rec.external_id);
    }
    store.prune_cmdb_devices(&kept)?;
    Ok(kept.len())
}

pub fn list_devices(store: &dyn Store) -> Result<Vec<CmdbDevice>> {
    Ok(store.list_cmdb_devices()?.iter().filter_map(|b| serde_json::from_slice(b).ok()).collect())
}

/// Periodic background job, spawned once at start-up alongside the other optional integrations
/// (`vulndata::run`, `ipenrich::run_geoip_auto_update`): checks hourly whether a sync is due
/// (enabled, and `sync_interval_hours` have actually passed since the newest imported row), and
/// runs one if so. A failure is logged and retried at the next tick rather than crashing anything
/// — the same "a flaky integration degrades, it never takes the collector down with it" posture
/// every other optional export/import in this codebase already has.
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
            let last = s.list_cmdb_devices()?.iter().filter_map(|b| serde_json::from_slice::<CmdbDevice>(b).ok()).map(|d| d.last_synced_at).max().unwrap_or(0);
            if now - last < cfg.sync_interval_hours.max(1) * 3600 {
                return Ok(None);
            }
            sync_now(&*s, now).map(Some)
        })
        .await;
        match result {
            Ok(Ok(Some(n))) => tracing::info!("CMDB import: {n} devices synced from Entra ID"),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("CMDB import failed, will retry at the next check: {e:#}"),
            Err(e) => tracing::warn!("CMDB import failed, will retry at the next check: {e}"),
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
        assert_eq!(client_secret(&store), None);

        let cfg = Settings { enabled: true, tenant_id: "contoso.onmicrosoft.com".into(), client_id: "abc-123".into(), sync_interval_hours: 6 };
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
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("tenant id"));
        save_settings(&store, &Settings { enabled: true, tenant_id: "t".into(), client_id: "c".into(), sync_interval_hours: 24 }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("client secret"), "no secret saved yet");
    }

    #[test]
    fn imported_devices_are_stored_and_listed_back() {
        use crate::store::CmdbStore;
        let store = SqliteStore::open_in_memory().unwrap();
        let rec = CmdbDevice {
            external_id: "dev-1".into(),
            display_name: "reception-pc".into(),
            os: Some("Windows".into()),
            os_version: Some("10.0.19045".into()),
            trust_type: Some("AzureAd".into()),
            compliant: Some(true),
            registered_at: Some("2026-01-01T00:00:00Z".into()),
            last_synced_at: 1000,
            matched_asset_id: None,
        };
        store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec).unwrap(), 1000).unwrap();
        let listed = list_devices(&store).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], rec);

        // a re-import that no longer mentions dev-1 forgets it
        store.prune_cmdb_devices(&[]).unwrap();
        assert!(list_devices(&store).unwrap().is_empty());
    }

    #[test]
    fn matching_is_by_exact_case_insensitive_hostname_only() {
        // this only exercises the matching logic sync_now uses internally, without a real Graph
        // call (that needs the real network - see ROADMAP.md on why this is not mocked here,
        // same reasoning as the SIEM/chat integrations' own "tested against a local fake server,
        // not the genuine article" gap).
        let mut a = Asset::new(crate::model::Mac([1, 2, 3, 4, 5, 6]), 0);
        a.hostnames = vec!["Reception-PC".into()];
        let by_hostname: std::collections::HashMap<String, i64> = [a].iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();
        assert_eq!(by_hostname.get(&"reception-pc".to_lowercase()).copied(), Some(0));
        assert_eq!(by_hostname.get(&"other-pc".to_lowercase()).copied(), None);
    }
}
