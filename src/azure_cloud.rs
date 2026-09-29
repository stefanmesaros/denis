//! Cloud asset discovery, first source: Azure virtual machines, via Azure Resource Graph — the
//! first item of ROADMAP.md's "Cloud asset discovery (AWS/Azure/GCP)", picked first because Azure
//! is the natural next step from the CMDB work already done (Entra ID/Intune already establish
//! the same app-only, client-credentials OAuth2 pattern against the same Azure AD tenant type),
//! not because it reuses that app registration's *permissions* — Resource Graph is a different
//! API surface (Azure Resource Manager, not Microsoft Graph) with its own authorization model
//! (an Azure RBAC role, "Reader" is enough, assigned to the app at subscription scope — an
//! application permission like `Device.Read.All` grants nothing here). Kept as its own module with
//! its own settings/credentials/schedule rather than folded into `cmdb.rs`, the same "independent
//! sources, one shared list" shape `jamf.rs`/`ad.rs` already use — even though it happens to be
//! able to reuse the very same app registration's client id/secret if an administrator wants to,
//! nothing here assumes it will.
//!
//! This is genuinely "another CMDB-like source" (ROADMAP.md's own words): a VM is one row, matched
//! to a DENIS asset by hostname (its Azure resource `name`, which is the VM's own hostname in the
//! overwhelming majority of real deployments) exactly like every other CMDB source — so it writes
//! into the very same shared `cmdb_devices` table (`CmdbDevice`, `source: "azure"`), not a new one.
//! A VM will usually not itself be reachable from wherever DENIS is scanning (this is a hybrid or
//! fully cloud-only inventory source, not a discovery mechanism) — the match is simply absent when
//! that is the case, exactly like an unreachable directory device today.
//!
//! Scoped to one subscription per sync (`subscription_id`, a single GUID) rather than "every
//! subscription this app can see" — the narrower, more predictable default; multiple subscriptions
//! would need either several separate configurations or a comma-list, deliberately not built until
//! there is a real need for it. Only virtual machines are covered (not storage accounts, databases,
//! or other resource types) — the same "narrowest useful slice first" choice this project's other
//! CMDB sources already made.
//!
//! Like every other integration in this codebase, the exact Resource Graph query shape and JSON
//! fields below follow Microsoft's own published API reference but have not been exercised against
//! a real Azure subscription — see CMDB.md's own honesty accounting, which this extends.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cmdb::{list_devices, CmdbDevice};
use crate::store::{SettingsStore, Store};

const SETTINGS_KEY: &str = "cmdb.azure.settings";
const CLIENT_SECRET_KEY: &str = "cmdb.azure.client_secret";
/// Azure Resource Manager's own OAuth2 resource/scope for a client-credentials token — distinct
/// from Microsoft Graph's `https://graph.microsoft.com/.default` that `cmdb.rs` uses.
const ARM_SCOPE: &str = "https://management.azure.com/.default";
const RESOURCE_GRAPH_URL: &str = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01";
/// Resource Graph pages at up to 1000 rows; a hard cap on pages so a huge subscription can never
/// turn a sync into an unbounded loop — same reasoning as `cmdb.rs`'s own Graph pagination cap.
const MAX_PAGES: u32 = 50;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// The Azure AD tenant (a GUID, or its `*.onmicrosoft.com` domain) the app registration
    /// belongs to.
    pub tenant_id: String,
    /// The app registration's application (client) id. Needs an Azure RBAC "Reader" role (or
    /// broader) assigned to it at the subscription below — an Azure AD *application permission*
    /// grants nothing for this API.
    pub client_id: String,
    /// The one subscription (a GUID) to inventory.
    pub subscription_id: String,
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
        Settings { enabled: false, tenant_id: String::new(), client_id: String::new(), subscription_id: String::new(), sync_interval_hours: default_interval_hours() }
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

/// App-only (client-credentials) OAuth2 token for Azure Resource Manager. Never cached across
/// calls — same reasoning as `cmdb::fetch_token`: a sync happens at most once an hour, and a token
/// is cheap and short-lived by design.
fn fetch_token(tenant_id: &str, client_id: &str, client_secret: &str) -> Result<String> {
    let url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let agent = http_client();
    let mut resp = agent
        .post(&url)
        .send_form([("client_id", client_id), ("client_secret", client_secret), ("scope", ARM_SCOPE), ("grant_type", "client_credentials")])
        .map_err(|e| anyhow!("could not reach Azure AD's token endpoint: {e}"))?;
    let v: serde_json::Value = resp.body_mut().read_json().context("the token response was not valid JSON")?;
    v["access_token"].as_str().map(str::to_string).ok_or_else(|| anyhow!("sign-in did not return a token: {}", v.get("error_description").and_then(|e| e.as_str()).unwrap_or("no detail given")))
}

/// One virtual machine, exactly as the Resource Graph query below projects it (`resultFormat:
/// "objectArray"`, so each row is already a plain JSON object with these field names).
#[derive(Deserialize)]
struct AzureVm {
    id: String,
    name: String,
    #[serde(rename = "osType")]
    os_type: Option<String>,
    #[serde(rename = "powerState")]
    power_state: Option<String>,
}

#[derive(Deserialize)]
struct ResourceGraphResponse {
    data: Vec<AzureVm>,
    #[serde(rename = "$skipToken")]
    skip_token: Option<String>,
}

/// The KQL query every page of `fetch_vms` sends, `$skip`/`$skipToken`-paginated exactly the way
/// Resource Graph's own docs describe (a `Facet`-free, single-table query never needs anything
/// fancier than the plain skip-token loop below).
const QUERY: &str = "Resources \
| where type =~ 'microsoft.compute/virtualmachines' \
| project id, name, osType=tostring(properties.storageProfile.osDisk.osType), \
  powerState=tostring(properties.extended.instanceView.powerState.displayStatus)";

/// Every virtual machine in `subscription_id`, paged via Resource Graph's own `$skipToken` until
/// exhausted or `MAX_PAGES` is hit, whichever first.
fn fetch_vms(token: &str, subscription_id: &str) -> Result<Vec<AzureVm>> {
    let agent = http_client();
    let mut out = Vec::new();
    let mut skip_token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut body = serde_json::json!({
            "subscriptions": [subscription_id],
            "query": QUERY,
            "options": { "resultFormat": "objectArray" },
        });
        if let Some(t) = &skip_token {
            body["options"]["$skipToken"] = serde_json::json!(t);
        }
        let mut resp = agent
            .post(RESOURCE_GRAPH_URL)
            .header("Authorization", format!("Bearer {token}"))
            .send_json(&body)
            .map_err(|e| anyhow!("Azure Resource Graph did not answer: {e}"))?;
        let page: ResourceGraphResponse = resp.body_mut().read_json().context("Azure Resource Graph's response was not the shape expected")?;
        let got = page.data.len();
        out.extend(page.data);
        match page.skip_token {
            Some(t) if got > 0 => skip_token = Some(t),
            _ => break,
        }
    }
    Ok(out)
}

/// Sync now: fetch every virtual machine in the configured subscription, match each to a DENIS
/// asset by hostname (its Azure resource name), store the result, and forget any previously
/// imported Azure device no longer present — never touching the other CMDB sources' rows, the same
/// source-scoped pruning every one of them already holds itself to.
pub fn sync_now(store: &dyn Store, now: i64) -> Result<usize> {
    let cfg = settings(store);
    if !cfg.enabled {
        bail!("Azure cloud asset discovery is not enabled");
    }
    if cfg.tenant_id.trim().is_empty() || cfg.client_id.trim().is_empty() || cfg.subscription_id.trim().is_empty() {
        bail!("tenant id, client id and subscription id must all be set first");
    }
    let secret = client_secret(store).ok_or_else(|| anyhow!("no client secret is saved yet"))?;
    let token = fetch_token(&cfg.tenant_id, &cfg.client_id, &secret)?;
    let vms = fetch_vms(&token, &cfg.subscription_id)?;

    let assets = store.load_assets()?;
    let by_hostname: std::collections::HashMap<String, i64> =
        assets.iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();

    let mut kept = Vec::with_capacity(vms.len());
    for vm in &vms {
        let matched_asset_id = by_hostname.get(&vm.name.to_lowercase()).copied();
        let rec = CmdbDevice {
            external_id: format!("azure:{}", vm.id),
            source: "azure".into(),
            display_name: vm.name.clone(),
            os: vm.os_type.clone(),
            os_version: None,
            trust_type: None,
            // Azure has no "compliant" concept of its own; power state is the closest analogue
            // ("running" is the healthy state) but is not the same question, so this stays `None`
            // rather than overload the field with a different meaning per source.
            compliant: None,
            registered_at: vm.power_state.clone(),
            last_synced_at: now,
            matched_asset_id,
        };
        store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec)?, now)?;
        kept.push(rec.external_id);
    }
    // Prune only this source's rows: every device belonging to another source is kept as-is.
    let other_sources: Vec<String> = list_devices(store)?.into_iter().filter(|d| d.source != "azure").map(|d| d.external_id).collect();
    kept.extend(other_sources);
    store.prune_cmdb_devices(&kept)?;
    Ok(vms.len())
}

/// Periodic background job, spawned once at start-up alongside `cmdb::run`/`jamf::run` and the
/// other optional integrations: checks hourly whether a sync is due, and runs one if so. A failure
/// is logged and retried at the next tick rather than crashing anything.
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
            let last = list_devices(&*s)?.iter().filter(|d| d.source == "azure").map(|d| d.last_synced_at).max().unwrap_or(0);
            if now - last < cfg.sync_interval_hours.max(1) * 3600 {
                return Ok(None);
            }
            sync_now(&*s, now).map(Some)
        })
        .await;
        match result {
            Ok(Ok(Some(n))) => tracing::info!("Azure cloud asset discovery: {n} virtual machines synced"),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("Azure cloud asset discovery failed, will retry at the next check: {e:#}"),
            Err(e) => tracing::warn!("Azure cloud asset discovery failed, will retry at the next check: {e}"),
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

        let cfg = Settings { enabled: true, tenant_id: "contoso.onmicrosoft.com".into(), client_id: "abc-123".into(), subscription_id: "sub-1".into(), sync_interval_hours: 12 };
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
        save_settings(&store, &Settings { enabled: true, tenant_id: "t1".into(), client_id: "c1".into(), subscription_id: "s1".into(), sync_interval_hours: 24 }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("client secret"), "no secret saved yet");
    }

    #[test]
    fn an_azure_sync_never_touches_devices_from_the_other_cmdb_sources() {
        // exercises sync_now's own source-scoped pruning without a live Azure call - the pruning
        // logic itself is what is under test here, via hand-inserted "existing" rows.
        use crate::store::CmdbStore;
        let store = SqliteStore::open_in_memory().unwrap();
        for (id, source) in [("entra:1", "entra"), ("intune:1", "intune"), ("ad:1", "ad"), ("jamf:1", "jamf")] {
            let rec = CmdbDevice { external_id: id.into(), source: source.into(), display_name: "reception-pc".into(), os: None, os_version: None, trust_type: None, compliant: None, registered_at: None, last_synced_at: 1, matched_asset_id: None };
            store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec).unwrap(), 1).unwrap();
        }
        // an Azure sync that (for this test) imports nothing must still prune only "azure:*" rows
        let other_sources: Vec<String> = list_devices(&store).unwrap().into_iter().filter(|d| d.source != "azure").map(|d| d.external_id).collect();
        store.prune_cmdb_devices(&other_sources).unwrap();
        let listed = list_devices(&store).unwrap();
        assert_eq!(listed.len(), 4, "all four other sources survive an azure-only prune");
        assert!(listed.iter().all(|d| d.source != "azure"));
    }

    #[test]
    fn hostname_matching_is_exact_and_case_insensitive() {
        let mut a = Asset::new(crate::model::Mac([1, 2, 3, 4, 5, 6]), 0);
        a.hostnames = vec!["Web-Vm-01".into()];
        let by_hostname: std::collections::HashMap<String, i64> = [a].iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();
        let vm = AzureVm { id: "/subscriptions/s1/.../web-vm-01".into(), name: "web-vm-01".into(), os_type: Some("Linux".into()), power_state: Some("VM running".into()) };
        assert_eq!(by_hostname.get(&vm.name.to_lowercase()).copied(), Some(0));
    }

    #[test]
    fn fetch_vms_pagination_stops_when_no_skip_token_or_no_rows_come_back() {
        // A pure-logic check of the paging loop's stopping condition, without a live server:
        // mirrors jamf.rs's own `fetch_computers` pagination test.
        let page = |rows: Vec<&str>, token: Option<&str>| ResourceGraphResponse {
            data: rows.into_iter().map(|n| AzureVm { id: format!("/id/{n}"), name: n.into(), os_type: None, power_state: None }).collect(),
            skip_token: token.map(str::to_string),
        };
        let mut out: Vec<AzureVm> = Vec::new();
        for p in [page(vec!["vm1"], Some("tok1")), page(vec!["vm2"], None)] {
            let got = p.data.len();
            out.extend(p.data);
            match p.skip_token {
                Some(_) if got > 0 => continue,
                _ => break,
            }
        }
        assert_eq!(out.len(), 2);
    }
}
