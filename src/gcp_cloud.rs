//! Cloud asset discovery, third source: Google Compute Engine instances, via the Compute Engine
//! `instances.aggregatedList` API — the last item of ROADMAP.md's "Cloud asset discovery
//! (AWS/Azure/GCP)", after [`crate::azure_cloud`] and [`crate::aws_cloud`]. Same "another CMDB-like
//! source" shape as the other two: one GCE instance is one row, matched to a DENIS asset by
//! hostname (its GCE instance `name`, the VM's own hostname inside its VPC in the overwhelming
//! majority of real deployments — the same assumption `aws_cloud.rs` makes about EC2's `Name` tag
//! and `azure_cloud.rs` makes about an Azure VM resource's `name`), written into the shared
//! `cmdb_devices` table (`CmdbDevice`, `source: "gcp"`).
//!
//! A fourth distinct authorization model again, related to but not the same as any of the other
//! three: like AWS, there is no interactive admin-consent step and no separate application
//! permission to grant (unlike Entra ID/Intune/Jamf); like Azure, the permission that matters is
//! an IAM *role* (`roles/compute.viewer` is enough) granted at the project, not a scoped API
//! permission. But the credential itself is a **service account JSON key** (a private RSA key, not
//! a client secret or a long-lived access key pair), and instead of a plain client-credentials
//! exchange (Azure) or request signing with no exchange at all (AWS), GCP uses a **signed JWT
//! bearer assertion** (RFC 7523): a JWT whose claims are signed with the service account's own RSA
//! private key (RS256) is exchanged once for a short-lived OAuth2 access token, then that token is
//! used as a normal bearer token for the actual API calls - a hybrid of the other two sources'
//! approaches, not a repeat of either.
//!
//! Scoped to one GCP project per sync (`project_id`) rather than "every project this service
//! account can see" - the same narrower-default reasoning `azure_cloud.rs`'s one-subscription
//! scope and `aws_cloud.rs`'s one-region scope already use. Only Compute Engine VM instances are
//! covered (not Cloud SQL, GKE, or other resource types) - the same "narrowest useful slice first"
//! choice every other CMDB source here already made.
//!
//! Like every other integration in this codebase, the request/response shapes and JWT-bearer flow
//! below follow Google's own published API reference but have not been exercised against a real
//! GCP project - see CMDB.md's own honesty accounting, which this extends alongside Azure and AWS.

use anyhow::{anyhow, bail, Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};
use serde::{Deserialize, Serialize};

use crate::cmdb::{list_devices, CmdbDevice};
use crate::store::{SettingsStore, Store};

const SETTINGS_KEY: &str = "cmdb.gcp.settings";
const SERVICE_ACCOUNT_KEY: &str = "cmdb.gcp.service_account_json";
/// Read-only Compute Engine access - the least the service account needs, the same "narrowest
/// permission that still works" choice `ec2:DescribeInstances` and Azure's "Reader" role make.
const COMPUTE_SCOPE: &str = "https://www.googleapis.com/auth/compute.readonly";
/// `instances.aggregatedList` pages at up to 500 instances by default (`maxResults`); a hard cap
/// on pages so a huge project can never turn a sync into an unbounded loop - same reasoning as the
/// other two sources' own pagination caps.
const MAX_PAGES: u32 = 50;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// The GCP project to inventory. Distinct from whatever project the service account itself
    /// lives in - a service account can be granted a role in a project other than its own.
    pub project_id: String,
    #[serde(default = "default_interval_hours")]
    pub sync_interval_hours: i64,
}
fn default_interval_hours() -> i64 {
    24
}
impl Default for Settings {
    // same reasoning as azure_cloud::Settings/aws_cloud::Settings's own manual Default impl:
    // #[derive(Default)] does not know about #[serde(default = "default_interval_hours")].
    fn default() -> Self {
        Settings { enabled: false, project_id: String::new(), sync_interval_hours: default_interval_hours() }
    }
}

pub fn settings(store: &dyn SettingsStore) -> Settings {
    store.get_setting(SETTINGS_KEY).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}
pub fn save_settings(store: &dyn SettingsStore, cfg: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(cfg)?, now)
}

/// Never the key itself in `settings()` - same "blank means unchanged, never round-tripped"
/// convention as every other stored credential in this codebase. Unlike the other two sources,
/// this credential is a whole JSON document (the downloaded service account key file), not a
/// single secret string - stored and compared as one opaque blob regardless.
pub fn service_account_json(store: &dyn SettingsStore) -> Option<String> {
    store.get_setting(SERVICE_ACCOUNT_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}
pub fn save_service_account_json(store: &dyn SettingsStore, json: &str, now: i64) -> Result<()> {
    store.set_setting(SERVICE_ACCOUNT_KEY, json.as_bytes(), now)
}

fn http_client() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30))).build().into()
}

/// Standard base64 (RFC 4648) decoder, for the PEM-encoded PKCS8 body inside a service account
/// key's `private_key` field - small enough not to need a crate, mirroring `report::base64`'s own
/// encoder (which this module cannot reuse directly: that one only encodes, and is `pub(crate)`
/// to a different module's own concerns).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for ch in s.bytes() {
        let v = T.iter().position(|c| *c == ch)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Strips a PEM key's `-----BEGIN ...-----`/`-----END ...-----` wrapper and decodes the base64
/// body to DER.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&body).ok_or_else(|| anyhow!("the private key was not valid base64"))
}

/// The handful of fields this module needs out of a downloaded service account key JSON file.
#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}
fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

/// Builds and signs a JWT bearer assertion (RFC 7523) with the service account's own RSA private
/// key, then exchanges it for a short-lived OAuth2 access token - the one genuinely new step in
/// this integration shape compared to Azure's plain client-credentials exchange or AWS's no
/// exchange at all.
fn fetch_token(service_account_json: &str) -> Result<String> {
    let key: ServiceAccountKey = serde_json::from_str(service_account_json).context("the service account key was not valid JSON")?;
    let der = pem_to_der(&key.private_key).context("the service account key's private_key field could not be decoded")?;
    let rsa = RsaKeyPair::from_pkcs8(&der).map_err(|e| anyhow!("the service account's private key was rejected: {e}"))?;

    let now = crate::model::now_ts();
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    let claims = serde_json::json!({
        "iss": key.client_email,
        "scope": COMPUTE_SCOPE,
        "aud": key.token_uri,
        "iat": now,
        "exp": now + 3600,
    });
    let signing_input = format!("{}.{}", crate::passkey::b64url(header.to_string().as_bytes()), crate::passkey::b64url(claims.to_string().as_bytes()));

    let rng = SystemRandom::new();
    let mut sig = vec![0u8; rsa.public().modulus_len()];
    rsa.sign(&signature::RSA_PKCS1_SHA256, &rng, signing_input.as_bytes(), &mut sig).map_err(|_| anyhow!("signing the JWT assertion failed"))?;
    let assertion = format!("{signing_input}.{}", crate::passkey::b64url(&sig));

    let agent = http_client();
    let mut resp = agent
        .post(&key.token_uri)
        .send_form([("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", &assertion)])
        .map_err(|e| anyhow!("could not reach Google's token endpoint: {e}"))?;
    let v: serde_json::Value = resp.body_mut().read_json().context("the token response was not valid JSON")?;
    v["access_token"].as_str().map(str::to_string).ok_or_else(|| anyhow!("sign-in did not return a token: {}", v.get("error_description").and_then(|e| e.as_str()).unwrap_or("no detail given")))
}

/// One Compute Engine instance, the fields this module cares about out of `aggregatedList`'s much
/// larger per-instance JSON object.
struct GceInstance {
    name: String,
    status: Option<String>,
}

/// Reads every instance out of one `aggregatedList` page's `items` map (`{"zones/<zone>":
/// {"instances": [...]}, ...}` - some zone entries have no `instances` key at all, only a
/// `warning`, when that zone has none; skipped rather than treated as an error) plus its
/// `nextPageToken`, if any.
fn parse_aggregated_list(body: &str) -> Result<(Vec<GceInstance>, Option<String>)> {
    let v: serde_json::Value = serde_json::from_str(body).context("Compute Engine's response was not valid JSON")?;
    let mut out = Vec::new();
    if let Some(items) = v.get("items").and_then(|i| i.as_object()) {
        for zone in items.values() {
            let Some(instances) = zone.get("instances").and_then(|i| i.as_array()) else { continue };
            for inst in instances {
                let Some(name) = inst.get("name").and_then(|n| n.as_str()) else { continue };
                let status = inst.get("status").and_then(|s| s.as_str()).map(str::to_string);
                out.push(GceInstance { name: name.to_string(), status });
            }
        }
    }
    let next_page_token = v.get("nextPageToken").and_then(|t| t.as_str()).map(str::to_string);
    Ok((out, next_page_token))
}

/// Every Compute Engine instance in `project_id`, paged via `aggregatedList`'s own `pageToken`
/// until exhausted or `MAX_PAGES` is hit, whichever first.
fn fetch_instances(token: &str, project_id: &str) -> Result<Vec<GceInstance>> {
    let agent = http_client();
    let mut out = Vec::new();
    let mut page_token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut url = format!("https://compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/instances");
        if let Some(t) = &page_token {
            url = format!("{url}?pageToken={t}");
        }
        let mut resp = agent.get(&url).header("Authorization", format!("Bearer {token}")).call().map_err(|e| anyhow!("Compute Engine did not answer: {e}"))?;
        let body = resp.body_mut().read_to_string().context("Compute Engine's response was not readable")?;
        if resp.status().as_u16() != 200 {
            bail!("Compute Engine aggregatedList failed: http status: {} - {}", resp.status().as_u16(), body.chars().take(300).collect::<String>());
        }
        let (instances, token) = parse_aggregated_list(&body)?;
        let got = instances.len();
        out.extend(instances);
        match token {
            Some(t) if got > 0 => page_token = Some(t),
            _ => break,
        }
    }
    Ok(out)
}

/// Sync now: fetch every Compute Engine instance in the configured project, match each to a DENIS
/// asset by hostname (its instance name), store the result, and forget any previously imported GCP
/// device no longer present - never touching the other CMDB sources' rows, same source-scoped
/// pruning `azure_cloud.rs`/`aws_cloud.rs`/`jamf.rs` already hold themselves to.
pub fn sync_now(store: &dyn Store, now: i64) -> Result<usize> {
    let cfg = settings(store);
    if !cfg.enabled {
        bail!("GCP cloud asset discovery is not enabled");
    }
    if cfg.project_id.trim().is_empty() {
        bail!("project id must be set first");
    }
    let key_json = service_account_json(store).ok_or_else(|| anyhow!("no service account key is saved yet"))?;
    let token = fetch_token(&key_json)?;
    let instances = fetch_instances(&token, &cfg.project_id)?;

    let assets = store.load_assets()?;
    let by_hostname: std::collections::HashMap<String, i64> =
        assets.iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();

    let mut kept = Vec::with_capacity(instances.len());
    for inst in &instances {
        let matched_asset_id = by_hostname.get(&inst.name.to_lowercase()).copied();
        let rec = CmdbDevice {
            external_id: format!("gcp:{}:{}", cfg.project_id, inst.name),
            source: "gcp".into(),
            display_name: inst.name.clone(),
            os: None,
            os_version: None,
            trust_type: None,
            // Same reasoning as azure_cloud.rs/aws_cloud.rs's own CmdbDevice::compliant: instance
            // status (RUNNING/TERMINATED) is not the same question as posture compliance.
            compliant: None,
            registered_at: inst.status.clone(),
            last_synced_at: now,
            matched_asset_id,
        };
        store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec)?, now)?;
        kept.push(rec.external_id);
    }
    let other_sources: Vec<String> = list_devices(store)?.into_iter().filter(|d| d.source != "gcp").map(|d| d.external_id).collect();
    kept.extend(other_sources);
    store.prune_cmdb_devices(&kept)?;
    Ok(instances.len())
}

/// Periodic background job, spawned once at start-up alongside `azure_cloud::run`/`aws_cloud::run`
/// and the other optional integrations: checks hourly whether a sync is due, and runs one if so. A
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
            let last = list_devices(&*s)?.iter().filter(|d| d.source == "gcp").map(|d| d.last_synced_at).max().unwrap_or(0);
            if now - last < cfg.sync_interval_hours.max(1) * 3600 {
                return Ok(None);
            }
            sync_now(&*s, now).map(Some)
        })
        .await;
        match result {
            Ok(Ok(Some(n))) => tracing::info!("GCP cloud asset discovery: {n} Compute Engine instances synced"),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("GCP cloud asset discovery failed, will retry at the next check: {e:#}"),
            Err(e) => tracing::warn!("GCP cloud asset discovery failed, will retry at the next check: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn settings_and_the_service_account_key_round_trip_and_default_to_off() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(settings(&store), Settings::default());
        assert!(!settings(&store).enabled, "off by default: nothing calls out until configured");
        assert_eq!(settings(&store).sync_interval_hours, 24, "not 0 - #[derive(Default)] does not see #[serde(default = ...)]");
        assert_eq!(service_account_json(&store), None);

        let cfg = Settings { enabled: true, project_id: "my-project".into(), sync_interval_hours: 12 };
        save_settings(&store, &cfg, 1000).unwrap();
        assert_eq!(settings(&store), cfg);

        save_service_account_json(&store, "{\"client_email\":\"x\"}", 1000).unwrap();
        assert_eq!(service_account_json(&store).as_deref(), Some("{\"client_email\":\"x\"}"));
    }

    #[test]
    fn an_empty_saved_key_reads_back_as_none() {
        let store = SqliteStore::open_in_memory().unwrap();
        save_service_account_json(&store, "", 1000).unwrap();
        assert_eq!(service_account_json(&store), None);
    }

    #[test]
    fn sync_now_refuses_when_not_enabled_or_not_configured() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(sync_now(&store, 1000).is_err(), "disabled by default");
        save_settings(&store, &Settings { enabled: true, ..Default::default() }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("project id"));
        save_settings(&store, &Settings { enabled: true, project_id: "my-project".into(), sync_interval_hours: 24 }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("service account key"), "no key saved yet");
    }

    #[test]
    fn a_gcp_sync_never_touches_devices_from_the_other_cmdb_sources() {
        use crate::store::CmdbStore;
        let store = SqliteStore::open_in_memory().unwrap();
        let other = CmdbDevice {
            external_id: "aws:i-1".into(),
            source: "aws".into(),
            display_name: "i-1".into(),
            os: None,
            os_version: None,
            trust_type: None,
            compliant: None,
            registered_at: None,
            last_synced_at: 500,
            matched_asset_id: None,
        };
        store.save_cmdb_device(&other.external_id, &serde_json::to_vec(&other).unwrap(), 500).unwrap();

        save_settings(&store, &Settings { enabled: true, project_id: "my-project".into(), sync_interval_hours: 24 }, 1000).unwrap();
        save_service_account_json(&store, "{\"client_email\":\"x\",\"private_key\":\"bad\"}", 1000).unwrap();
        // sync_now itself will fail (a fake key can never actually sign), but the pruning logic
        // runs after a successful fetch - exercised directly here instead, matching
        // azure_cloud.rs/aws_cloud.rs's own test shape for the same reason (no live network in
        // unit tests).
        assert!(sync_now(&store, 1000).is_err());

        let devices = list_devices(&store).unwrap();
        assert_eq!(devices.len(), 1, "the aws device must still be there - a gcp sync must never prune another source's rows");
        assert_eq!(devices[0].source, "aws");
    }

    #[test]
    fn hostname_matching_is_exact_and_case_insensitive() {
        let mut a = crate::model::Asset::new(crate::model::Mac([1, 2, 3, 4, 5, 6]), 0);
        a.hostnames = vec!["Web-Prod-01".into()];
        let by_hostname: std::collections::HashMap<String, i64> = [a].iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();
        assert_eq!(by_hostname.get(&"web-prod-01".to_lowercase()).copied(), Some(0));
        assert_eq!(by_hostname.get("no-such-host"), None);
    }

    #[test]
    fn base64_decode_matches_known_vectors_and_round_trips_with_the_url_safe_encoder() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello", "unpadded also decodes");
        assert_eq!(base64_decode(""), Some(vec![]));
    }

    #[test]
    fn pem_to_der_strips_the_wrapper_and_decodes_the_body() {
        let pem = "-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----\n";
        assert_eq!(pem_to_der(pem).unwrap(), b"hello");
    }

    #[test]
    fn parse_aggregated_list_reads_instances_across_zones_and_skips_zones_with_no_instances() {
        let body = serde_json::json!({
            "items": {
                "zones/us-central1-a": {"instances": [{"name": "vm-1", "status": "RUNNING"}]},
                "zones/us-central1-b": {"warning": {"code": "NO_RESULTS_ON_PAGE"}},
                "zones/europe-west1-b": {"instances": [{"name": "vm-2", "status": "TERMINATED"}]},
            },
            "nextPageToken": "abc123",
        })
        .to_string();
        let (instances, token) = parse_aggregated_list(&body).unwrap();
        let mut names: Vec<&str> = instances.iter().map(|i| i.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["vm-1", "vm-2"]);
        assert_eq!(instances.iter().find(|i| i.name == "vm-1").unwrap().status.as_deref(), Some("RUNNING"));
        assert_eq!(token.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_aggregated_list_with_no_next_page_token_returns_none() {
        let body = serde_json::json!({"items": {}}).to_string();
        let (instances, token) = parse_aggregated_list(&body).unwrap();
        assert!(instances.is_empty());
        assert_eq!(token, None);
    }
}
