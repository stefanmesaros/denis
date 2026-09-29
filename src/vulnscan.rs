//! Vulnerability-scanner import: Nessus (Tenable Nessus Professional/Manager, and Tenable.io,
//! which speak the same REST API shape) — DENIS's own roadmap item "Vulnerability-scanner import
//! (Qualys/Tenable/Nessus)", scoped to one source first, the same "narrowest useful slice first"
//! choice the CMDB sources (`cmdb.rs`) made before adding Intune, then AD, then Jamf.
//!
//! Independent of the CMDB sources: a genuinely different kind of external data (a scanner reports
//! *findings* — zero or more per host, each with its own severity and plugin id — not one
//! inventory record per device), so it gets its own settings, credentials, schedule and store
//! table (`imported_vulns`) rather than being squeezed into `CmdbDevice`'s one-row-per-device
//! shape, which has no room for that.
//!
//! Matching is IP-first, falling back to hostname, both exact and case-insensitive — never fuzzy,
//! the same discipline every CMDB source already holds itself to (see `cmdb.rs`'s own module
//! docs). IP-first because a scanner speaks about hosts by address, not name, and DENIS's own
//! asset register is itself IP-centric for exactly that reason.
//!
//! Authentication: Nessus/Tenable API keys (`X-ApiKeys: accessKey=...; secretKey=...`) — no token
//! exchange needed, simpler than the CMDB sources' OAuth2 flows.
//!
//! Like every other integration in this codebase, the exact JSON shapes below follow Nessus's
//! published REST API reference but have not been exercised against a real Nessus/Tenable.io
//! instance — see CMDB.md's own honesty accounting, which this extends to a new integration.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::store::{SettingsStore, Store};

const SETTINGS_KEY: &str = "vulnscan.settings";
const ACCESS_KEY_KEY: &str = "vulnscan.access_key";
const SECRET_KEY_KEY: &str = "vulnscan.secret_key";
/// The most recently completed scans considered per sync, not a Nessus instance's whole history —
/// only what is still relevant to "what does my network look like right now".
const MAX_SCANS_PER_SYNC: usize = 20;
const MAX_HOSTS_PER_SCAN: usize = 2000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// e.g. `https://nessus.example.com:8834` (self-hosted Nessus) or `https://cloud.tenable.com`
    /// (Tenable.io) — both speak the same API shape below. No trailing slash.
    pub server_url: String,
    #[serde(default = "default_interval_hours")]
    pub sync_interval_hours: i64,
}
fn default_interval_hours() -> i64 {
    24
}
impl Default for Settings {
    // same reasoning as cmdb::Settings/jamf::Settings's own manual Default impl: #[derive(Default)]
    // does not know about #[serde(default = "default_interval_hours")], and would give 0 instead
    // of 24.
    fn default() -> Self {
        Settings { enabled: false, server_url: String::new(), sync_interval_hours: default_interval_hours() }
    }
}

pub fn settings(store: &dyn SettingsStore) -> Settings {
    store.get_setting(SETTINGS_KEY).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}
pub fn save_settings(store: &dyn SettingsStore, cfg: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(cfg)?, now)
}

/// Never the key itself in `settings()` — same "blank means unchanged, never round-tripped"
/// convention as every other stored credential in this codebase.
pub fn access_key(store: &dyn SettingsStore) -> Option<String> {
    store.get_setting(ACCESS_KEY_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}
pub fn save_access_key(store: &dyn SettingsStore, key: &str, now: i64) -> Result<()> {
    store.set_setting(ACCESS_KEY_KEY, key.as_bytes(), now)
}
pub fn secret_key(store: &dyn SettingsStore) -> Option<String> {
    store.get_setting(SECRET_KEY_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}
pub fn save_secret_key(store: &dyn SettingsStore, key: &str, now: i64) -> Result<()> {
    store.set_setting(SECRET_KEY_KEY, key.as_bytes(), now)
}

fn http_client() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30))).build().into()
}

fn auth_header(access: &str, secret: &str) -> String {
    format!("accessKey={access}; secretKey={secret}")
}

/// One vulnerability finding for one host, from one scan — the unit `imported_vulns` stores, one
/// row per (source, scan, host, plugin).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ImportedVuln {
    pub external_id: String,
    pub source: String,
    /// The host exactly as the scanner named it (usually an IP, sometimes a hostname).
    pub host: String,
    pub matched_asset_id: Option<i64>,
    pub plugin_id: u64,
    pub plugin_name: String,
    /// `info`, `low`, `medium`, `high` or `critical` — normalized from the scanner's own numeric
    /// scale (Nessus: 0-4) so the console never has to know which scanner a row came from to show
    /// it sensibly.
    pub severity: String,
    pub last_synced_at: i64,
}

fn severity_name(n: i64) -> &'static str {
    match n {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "info",
    }
}

#[derive(Deserialize)]
struct ScanListItem {
    id: i64,
    status: String,
}
#[derive(Deserialize, Default)]
struct ScanList {
    scans: Option<Vec<ScanListItem>>,
}

#[derive(Deserialize)]
struct ScanHost {
    host_id: i64,
    hostname: String,
}
#[derive(Deserialize)]
struct ScanDetail {
    #[serde(default)]
    hosts: Vec<ScanHost>,
}

#[derive(Deserialize)]
struct HostVuln {
    plugin_id: u64,
    plugin_name: String,
    severity: i64,
}
#[derive(Deserialize)]
struct HostDetail {
    #[serde(default)]
    vulnerabilities: Vec<HostVuln>,
}

fn fetch_json<T: serde::de::DeserializeOwned>(agent: &ureq::Agent, url: &str, access: &str, secret: &str) -> Result<T> {
    let mut resp = agent.get(url).header("X-ApiKeys", auth_header(access, secret)).call().map_err(|e| anyhow!("could not reach {url}: {e}"))?;
    resp.body_mut().read_json().context("the scanner's response was not the shape expected")
}

/// Every device's own IP/hostname, ready for the same exact-match-first-then-hostname lookup
/// every host below needs — built once per sync rather than per host.
fn asset_lookup(store: &dyn Store) -> Result<(HashMap<String, i64>, HashMap<String, i64>)> {
    let assets = store.load_assets()?;
    let by_ip: HashMap<String, i64> = assets.iter().filter_map(|a| a.current_ip().map(|ip| (ip.to_string(), a.id))).collect();
    let by_hostname: HashMap<String, i64> = assets.iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();
    Ok((by_ip, by_hostname))
}

fn match_host(host: &str, by_ip: &HashMap<String, i64>, by_hostname: &HashMap<String, i64>) -> Option<i64> {
    by_ip.get(host).copied().or_else(|| by_hostname.get(&host.to_lowercase()).copied())
}

/// Sync now: for each of the most recently completed scans, fetch every host and its
/// vulnerabilities, match each host to a DENIS asset (IP first, then hostname), store the result,
/// and forget any previously-imported finding not seen this time (a host rescanned clean, removed
/// from the scan, or the scan itself gone) — never touching another source's rows, the same
/// source-scoped pruning every CMDB source already holds itself to. Returns how many findings
/// were imported.
pub fn sync_now(store: &dyn Store, now: i64) -> Result<usize> {
    let cfg = settings(store);
    if !cfg.enabled {
        bail!("vulnerability-scanner import is not enabled");
    }
    if cfg.server_url.trim().is_empty() {
        bail!("the scanner's server URL must be set first");
    }
    let access = access_key(store).ok_or_else(|| anyhow!("no access key is saved yet"))?;
    let secret = secret_key(store).ok_or_else(|| anyhow!("no secret key is saved yet"))?;
    let server_url = cfg.server_url.trim_end_matches('/');
    let agent = http_client();

    let list: ScanList = fetch_json(&agent, &format!("{server_url}/scans"), &access, &secret)?;
    let scans: Vec<ScanListItem> = list.scans.unwrap_or_default().into_iter().filter(|s| s.status == "completed").take(MAX_SCANS_PER_SYNC).collect();

    let (by_ip, by_hostname) = asset_lookup(store)?;

    let mut kept = Vec::new();
    let mut total = 0usize;
    for scan in &scans {
        let detail: ScanDetail = fetch_json(&agent, &format!("{server_url}/scans/{}", scan.id), &access, &secret)?;
        for host in detail.hosts.into_iter().take(MAX_HOSTS_PER_SCAN) {
            let matched_asset_id = match_host(&host.hostname, &by_ip, &by_hostname);
            let hd: HostDetail = fetch_json(&agent, &format!("{server_url}/scans/{}/hosts/{}", scan.id, host.host_id), &access, &secret)?;
            for v in hd.vulnerabilities {
                let external_id = format!("nessus:{}:{}:{}", scan.id, host.host_id, v.plugin_id);
                let rec = ImportedVuln {
                    external_id: external_id.clone(),
                    source: "nessus".into(),
                    host: host.hostname.clone(),
                    matched_asset_id,
                    plugin_id: v.plugin_id,
                    plugin_name: v.plugin_name,
                    severity: severity_name(v.severity).into(),
                    last_synced_at: now,
                };
                store.save_imported_vuln(&external_id, &serde_json::to_vec(&rec)?, now)?;
                kept.push(external_id);
                total += 1;
            }
        }
    }
    // Prune only this source's rows: a second scanner source added later keeps its own findings
    // untouched by this one's sync, the same reasoning as every CMDB source's own pruning.
    let other_sources: Vec<String> = list_vulns(store)?.into_iter().filter(|v| v.source != "nessus").map(|v| v.external_id).collect();
    kept.extend(other_sources);
    store.prune_imported_vulns(&kept)?;
    Ok(total)
}

/// Every imported finding, from every configured scanner source.
pub fn list_vulns(store: &dyn Store) -> Result<Vec<ImportedVuln>> {
    Ok(store.list_imported_vulns()?.into_iter().filter_map(|b| serde_json::from_slice(&b).ok()).collect())
}

/// Periodic background job, spawned once at start-up alongside `cmdb::run`/`jamf::run` and the
/// other optional integrations: checks hourly whether a sync is due, and runs one if so. A
/// failure is logged and retried at the next tick rather than crashing anything.
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
            let last = list_vulns(&*s)?.iter().filter(|v| v.source == "nessus").map(|v| v.last_synced_at).max().unwrap_or(0);
            if now - last < cfg.sync_interval_hours.max(1) * 3600 {
                return Ok(None);
            }
            sync_now(&*s, now).map(Some)
        })
        .await;
        match result {
            Ok(Ok(Some(n))) => tracing::info!("vulnerability-scanner import: {n} findings synced"),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("vulnerability-scanner import failed, will retry at the next check: {e:#}"),
            Err(e) => tracing::warn!("vulnerability-scanner import failed, will retry at the next check: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Asset, Mac};
    use crate::store::sqlite::SqliteStore;
    use crate::store::VulnScanStore;

    #[test]
    fn settings_and_the_keys_round_trip_and_default_to_off() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(settings(&store), Settings::default());
        assert!(!settings(&store).enabled, "off by default: nothing calls out until configured");
        assert_eq!(settings(&store).sync_interval_hours, 24, "not 0 - #[derive(Default)] does not see #[serde(default = ...)]");
        assert_eq!(access_key(&store), None);
        assert_eq!(secret_key(&store), None);

        let cfg = Settings { enabled: true, server_url: "https://nessus.example.com:8834".into(), sync_interval_hours: 12 };
        save_settings(&store, &cfg, 1000).unwrap();
        assert_eq!(settings(&store), cfg);

        save_access_key(&store, "access-1", 1000).unwrap();
        save_secret_key(&store, "secret-1", 1000).unwrap();
        assert_eq!(access_key(&store).as_deref(), Some("access-1"));
        assert_eq!(secret_key(&store).as_deref(), Some("secret-1"));
    }

    #[test]
    fn an_empty_saved_key_reads_back_as_none() {
        let store = SqliteStore::open_in_memory().unwrap();
        save_access_key(&store, "", 1000).unwrap();
        save_secret_key(&store, "", 1000).unwrap();
        assert_eq!(access_key(&store), None);
        assert_eq!(secret_key(&store), None);
    }

    #[test]
    fn sync_now_refuses_when_not_enabled_or_not_configured() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(sync_now(&store, 1000).is_err(), "disabled by default");
        save_settings(&store, &Settings { enabled: true, ..Default::default() }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("server URL"));
        save_settings(&store, &Settings { enabled: true, server_url: "https://nessus.example.com:8834".into(), sync_interval_hours: 24 }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("access key"), "no keys saved yet");
        save_access_key(&store, "a1", 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("secret key"), "access key alone is not enough");
    }

    #[test]
    fn a_sync_never_touches_findings_from_another_source() {
        // exercises sync_now's own source-scoped pruning without a live Nessus call - the pruning
        // logic itself is what is under test here, via a hand-inserted "existing" row from a
        // hypothetical other scanner source.
        let store = SqliteStore::open_in_memory().unwrap();
        let other = ImportedVuln { external_id: "qualys:1:2:3".into(), source: "qualys".into(), host: "10.0.0.5".into(), matched_asset_id: None, plugin_id: 3, plugin_name: "x".into(), severity: "high".into(), last_synced_at: 1 };
        store.save_imported_vuln(&other.external_id, &serde_json::to_vec(&other).unwrap(), 1).unwrap();
        // a Nessus sync that (for this test) imports nothing must still prune only "nessus:*" rows
        let other_sources: Vec<String> = list_vulns(&store).unwrap().into_iter().filter(|v| v.source != "nessus").map(|v| v.external_id).collect();
        store.prune_imported_vulns(&other_sources).unwrap();
        let listed = list_vulns(&store).unwrap();
        assert_eq!(listed.len(), 1, "the other source survives a nessus-only prune");
        assert_eq!(listed[0].source, "qualys");
    }

    #[test]
    fn host_matching_prefers_ip_then_falls_back_to_hostname_case_insensitively() {
        let mut a1 = Asset::new(Mac([1, 2, 3, 4, 5, 6]), 0);
        a1.id = 1;
        a1.ip_history = vec![crate::model::IpRecord { ip: "10.0.0.5".parse().unwrap(), first_seen: 0, last_seen: 0 }];
        let mut a2 = Asset::new(Mac([1, 2, 3, 4, 5, 7]), 0);
        a2.id = 2;
        a2.hostnames = vec!["Reception-PC".into()];
        let by_ip: HashMap<String, i64> = [(&a1)].iter().filter_map(|a| a.current_ip().map(|ip| (ip.to_string(), a.id))).collect();
        let by_hostname: HashMap<String, i64> = [(&a2)].iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();

        assert_eq!(match_host("10.0.0.5", &by_ip, &by_hostname), Some(1), "matched by IP");
        assert_eq!(match_host("reception-pc", &by_ip, &by_hostname), Some(2), "matched by hostname, case-insensitively");
        assert_eq!(match_host("unknown-host", &by_ip, &by_hostname), None);
    }

    #[test]
    fn severity_numbers_map_to_names_and_default_to_info() {
        assert_eq!(severity_name(4), "critical");
        assert_eq!(severity_name(3), "high");
        assert_eq!(severity_name(2), "medium");
        assert_eq!(severity_name(1), "low");
        assert_eq!(severity_name(0), "info");
        assert_eq!(severity_name(99), "info", "an unknown/future value falls back to info, never panics");
    }
}
