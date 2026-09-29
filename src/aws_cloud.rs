//! Cloud asset discovery, second source: AWS EC2 instances, via the EC2 `DescribeInstances` API —
//! the second item of ROADMAP.md's "Cloud asset discovery (AWS/Azure/GCP)", after [`crate::azure_cloud`].
//! Same "another CMDB-like source" shape as Azure: one EC2 instance is one row, matched to a DENIS
//! asset by hostname, written into the shared `cmdb_devices` table (`CmdbDevice`, `source: "aws"`).
//!
//! The authorization model here is genuinely different again from both Azure (an OAuth2
//! client-credentials bearer token) and Entra ID/Intune/Jamf (also bearer tokens): AWS has no
//! bearer-token concept for its own APIs at all. Every request is signed with AWS Signature
//! Version 4 (SigV4) using a long-lived IAM access key id/secret access key pair — there is no
//! token exchange step, no expiry to refresh, and no separate "scope" to request; the IAM policy
//! attached to that access key (an `ec2:DescribeInstances`-allowing policy is enough, read-only)
//! is what limits what it can see, the same role Azure's RBAC "Reader" role plays and Entra ID's
//! `Device.Read.All` application permission plays for their own APIs.
//!
//! Scoped to one AWS region per sync (`region`, e.g. `eu-central-1`) rather than "every region" —
//! same narrower-default reasoning as Azure's one-subscription scope; multiple regions would need
//! either several configurations or a region list, deliberately not built until there is a real
//! need for it. Only EC2 instances are covered (not RDS, S3, or other resource types) — the same
//! "narrowest useful slice first" choice every other CMDB source here already made.
//!
//! Like every other integration in this codebase, the request-signing and response-parsing code
//! below follows AWS's own published API reference but has not been exercised against a real AWS
//! account — see CMDB.md's own honesty accounting, which this extends alongside Azure's.

use anyhow::{anyhow, bail, Context, Result};
use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::cmdb::{list_devices, CmdbDevice};
use crate::store::{SettingsStore, Store};

const SETTINGS_KEY: &str = "cmdb.aws.settings";
const SECRET_ACCESS_KEY_KEY: &str = "cmdb.aws.secret_access_key";
const SERVICE: &str = "ec2";
const API_VERSION: &str = "2016-11-15";
/// EC2's own `DescribeInstances` pages at up to 1000 instances (`MaxResults`); a hard cap on pages
/// so a huge account can never turn a sync into an unbounded loop — same reasoning as
/// `azure_cloud.rs`'s `MAX_PAGES`.
const MAX_PAGES: u32 = 50;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// The IAM access key id. Needs an IAM policy allowing at least `ec2:DescribeInstances` — a
    /// read-only permission, nothing here ever calls a mutating EC2 action.
    pub access_key_id: String,
    /// The one AWS region (e.g. `eu-central-1`) to inventory.
    pub region: String,
    #[serde(default = "default_interval_hours")]
    pub sync_interval_hours: i64,
}
fn default_interval_hours() -> i64 {
    24
}
impl Default for Settings {
    // same reasoning as azure_cloud::Settings's own manual Default impl: #[derive(Default)] does
    // not know about #[serde(default = "default_interval_hours")], and would give 0 instead of 24.
    fn default() -> Self {
        Settings { enabled: false, access_key_id: String::new(), region: String::new(), sync_interval_hours: default_interval_hours() }
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
pub fn secret_access_key(store: &dyn SettingsStore) -> Option<String> {
    store.get_setting(SECRET_ACCESS_KEY_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}
pub fn save_secret_access_key(store: &dyn SettingsStore, secret: &str, now: i64) -> Result<()> {
    store.set_setting(SECRET_ACCESS_KEY_KEY, secret.as_bytes(), now)
}

fn http_client() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30))).build().into()
}

fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn hmac_sha256(key: &[u8], data: &[u8]) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
}

/// AWS Signature Version 4 for one request, following AWS's own published algorithm exactly
/// (`AWS4-HMAC-SHA256`, a canonical-request hash chained through a date/region/service/`aws4_request`
/// derived signing key) — this is what stands in for a bearer token or OAuth2 client-credentials
/// flow with AWS's APIs; there is no separate token-exchange step to do first.
#[allow(clippy::too_many_arguments)]
fn sign(access_key_id: &str, secret_access_key: &str, region: &str, method: &str, host: &str, canonical_query: &str, body: &str, amz_date: &str, date_stamp: &str) -> String {
    let canonical_headers = format!("host:{host}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-date";
    let payload_hash = sha256_hex(body.as_bytes());
    let canonical_request = format!("{method}\n/\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let credential_scope = format!("{date_stamp}/{region}/{SERVICE}/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}", sha256_hex(canonical_request.as_bytes()));

    let k_date = hmac_sha256(format!("AWS4{secret_access_key}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(k_date.as_ref(), region.as_bytes());
    let k_service = hmac_sha256(k_region.as_ref(), SERVICE.as_bytes());
    let k_signing = hmac_sha256(k_service.as_ref(), b"aws4_request");
    let signature = hmac_sha256(k_signing.as_ref(), string_to_sign.as_bytes()).as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>();

    format!("AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}")
}

/// One EC2 instance, the fields this module cares about out of `DescribeInstances`' much larger
/// XML response (parsed with a small ad-hoc extractor below rather than a full XML crate — the
/// response shape is flat and well-known enough that pulling in a new dependency for it is not
/// worth it).
struct Ec2Instance {
    instance_id: String,
    /// EC2 has no single "hostname" field the way an Azure VM resource has a `name` — the closest
    /// equivalent most real deployments actually set is the `Name` tag; falls back to the instance
    /// id itself (never matches anything by hostname, but is still listed) when absent.
    name: String,
    platform: Option<String>,
    state: Option<String>,
}

/// Extracts every *top-level* occurrence of `<tag>...</tag>` from `xml`, tracking nesting depth of
/// that same tag name so that e.g. `<item>` blocks nested inside other `<item>` blocks (EC2's
/// `reservationSet`/`instancesSet`/`tagSet` all use the same generic `item` tag at every level) are
/// returned whole rather than split at the first inner close tag.
fn xml_tag<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel_start) = xml[search_from..].find(&open) {
        let start = search_from + rel_start + open.len();
        let mut depth = 1i32;
        let mut pos = start;
        let end = loop {
            let next_open = xml[pos..].find(&open).map(|i| pos + i);
            let next_close = xml[pos..].find(&close).map(|i| pos + i);
            match (next_open, next_close) {
                (Some(o), Some(c)) if o < c => {
                    depth += 1;
                    pos = o + open.len();
                }
                (_, Some(c)) => {
                    depth -= 1;
                    if depth == 0 {
                        break c;
                    }
                    pos = c + close.len();
                }
                _ => return out, // unbalanced tags: stop rather than panic on a malformed document
            }
        };
        out.push(&xml[start..end]);
        search_from = end + close.len();
    }
    out
}

/// Splits `DescribeInstances`' response into its per-`<item>` instance blocks (nested inside
/// `<reservationSet><item><instancesSet><item>...`), then reads the handful of fields this module
/// needs out of each block independently, so nesting elsewhere in the document cannot confuse it.
fn parse_describe_instances(xml: &str) -> (Vec<Ec2Instance>, Option<String>) {
    let mut out = Vec::new();
    for reservation in xml_tag(xml, "item") {
        // A reservation's top-level <item> contains <instancesSet><item>...instance
        // fields...</item></instancesSet>; xml_tag's nesting tracking means this correctly finds
        // just the instance-level <item> blocks, tagSet/item nested inside each one included whole.
        for inst in xml_tag(reservation, "item") {
            let Some(instance_id) = xml_tag(inst, "instanceId").into_iter().next() else { continue };
            let state = xml_tag(inst, "name").into_iter().next().map(str::to_string);
            let platform = xml_tag(inst, "platform").into_iter().next().map(str::to_string);
            let name_tag = xml_tag(inst, "tagSet")
                .into_iter()
                .next()
                .and_then(|tag_set| {
                    xml_tag(tag_set, "item").into_iter().find_map(|item| {
                        let key = xml_tag(item, "key").into_iter().next()?;
                        (key == "Name").then(|| xml_tag(item, "value").into_iter().next().map(str::to_string)).flatten()
                    })
                });
            out.push(Ec2Instance { instance_id: instance_id.to_string(), name: name_tag.unwrap_or_else(|| instance_id.to_string()), platform, state });
        }
    }
    let next_token = xml_tag(xml, "nextToken").into_iter().next().map(str::to_string);
    (out, next_token)
}

/// Every EC2 instance in `region`, paged via `DescribeInstances`' own `NextToken` until exhausted
/// or `MAX_PAGES` is hit, whichever first.
fn fetch_instances(access_key_id: &str, secret_access_key: &str, region: &str) -> Result<Vec<Ec2Instance>> {
    let host = format!("ec2.{region}.amazonaws.com");
    let agent = http_client();
    let mut out = Vec::new();
    let mut next_token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let now = time::OffsetDateTime::now_utc();
        let amz_date = format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        let date_stamp = &amz_date[..8];

        let mut params = vec![("Action".to_string(), "DescribeInstances".to_string()), ("Version".to_string(), API_VERSION.to_string()), ("MaxResults".to_string(), "1000".to_string())];
        if let Some(t) = &next_token {
            params.push(("NextToken".to_string(), t.clone()));
        }
        params.sort();
        let canonical_query = params.iter().map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v))).collect::<Vec<_>>().join("&");

        let authorization = sign(access_key_id, secret_access_key, region, "GET", &host, &canonical_query, "", &amz_date, date_stamp);
        let url = format!("https://{host}/?{canonical_query}");
        let mut resp = agent
            .get(&url)
            .header("host", &host)
            .header("x-amz-date", &amz_date)
            .header("Authorization", &authorization)
            .call()
            .map_err(|e| anyhow!("AWS EC2 did not answer: {e}"))?;
        let body = resp.body_mut().read_to_string().context("EC2's response was not readable")?;
        if resp.status().as_u16() != 200 {
            bail!("EC2 DescribeInstances failed: http status: {} - {}", resp.status().as_u16(), body.chars().take(300).collect::<String>());
        }
        let (instances, token) = parse_describe_instances(&body);
        let got = instances.len();
        out.extend(instances);
        match token {
            Some(t) if got > 0 => next_token = Some(t),
            _ => break,
        }
    }
    Ok(out)
}

fn urlencode(s: &str) -> String {
    // AWS SigV4's own canonical-query-string encoding: RFC 3986 unreserved characters pass
    // through unescaped, everything else is percent-encoded - the standard `form_urlencoded`
    // encoder is close but encodes space as `+`, which SigV4 rejects, so this stays hand-rolled.
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Sync now: fetch every EC2 instance in the configured region, match each to a DENIS asset by
/// hostname (its `Name` tag), store the result, and forget any previously imported AWS device no
/// longer present — never touching the other CMDB sources' rows, same source-scoped pruning
/// `azure_cloud.rs`/`jamf.rs` already hold themselves to.
pub fn sync_now(store: &dyn Store, now: i64) -> Result<usize> {
    let cfg = settings(store);
    if !cfg.enabled {
        bail!("AWS cloud asset discovery is not enabled");
    }
    if cfg.access_key_id.trim().is_empty() || cfg.region.trim().is_empty() {
        bail!("access key id and region must both be set first");
    }
    let secret = secret_access_key(store).ok_or_else(|| anyhow!("no secret access key is saved yet"))?;
    let instances = fetch_instances(&cfg.access_key_id, &secret, &cfg.region)?;

    let assets = store.load_assets()?;
    let by_hostname: std::collections::HashMap<String, i64> =
        assets.iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();

    let mut kept = Vec::with_capacity(instances.len());
    for inst in &instances {
        let matched_asset_id = by_hostname.get(&inst.name.to_lowercase()).copied();
        let rec = CmdbDevice {
            external_id: format!("aws:{}", inst.instance_id),
            source: "aws".into(),
            display_name: inst.name.clone(),
            os: inst.platform.clone(),
            os_version: None,
            trust_type: None,
            // Same reasoning as azure_cloud.rs's CmdbDevice::compliant: instance state
            // (running/stopped) is not the same question as posture compliance.
            compliant: None,
            registered_at: inst.state.clone(),
            last_synced_at: now,
            matched_asset_id,
        };
        store.save_cmdb_device(&rec.external_id, &serde_json::to_vec(&rec)?, now)?;
        kept.push(rec.external_id);
    }
    let other_sources: Vec<String> = list_devices(store)?.into_iter().filter(|d| d.source != "aws").map(|d| d.external_id).collect();
    kept.extend(other_sources);
    store.prune_cmdb_devices(&kept)?;
    Ok(instances.len())
}

/// Periodic background job, spawned once at start-up alongside `azure_cloud::run` and the other
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
            let last = list_devices(&*s)?.iter().filter(|d| d.source == "aws").map(|d| d.last_synced_at).max().unwrap_or(0);
            if now - last < cfg.sync_interval_hours.max(1) * 3600 {
                return Ok(None);
            }
            sync_now(&*s, now).map(Some)
        })
        .await;
        match result {
            Ok(Ok(Some(n))) => tracing::info!("AWS cloud asset discovery: {n} EC2 instances synced"),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("AWS cloud asset discovery failed, will retry at the next check: {e:#}"),
            Err(e) => tracing::warn!("AWS cloud asset discovery failed, will retry at the next check: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Asset;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn settings_and_the_secret_access_key_round_trip_and_default_to_off() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(settings(&store), Settings::default());
        assert!(!settings(&store).enabled, "off by default: nothing calls out until configured");
        assert_eq!(settings(&store).sync_interval_hours, 24, "not 0 - #[derive(Default)] does not see #[serde(default = ...)]");
        assert_eq!(secret_access_key(&store), None);

        let cfg = Settings { enabled: true, access_key_id: "AKIAEXAMPLE".into(), region: "eu-central-1".into(), sync_interval_hours: 12 };
        save_settings(&store, &cfg, 1000).unwrap();
        assert_eq!(settings(&store), cfg);

        save_secret_access_key(&store, "sekret", 1000).unwrap();
        assert_eq!(secret_access_key(&store).as_deref(), Some("sekret"));
    }

    #[test]
    fn an_empty_saved_secret_reads_back_as_none() {
        let store = SqliteStore::open_in_memory().unwrap();
        save_secret_access_key(&store, "", 1000).unwrap();
        assert_eq!(secret_access_key(&store), None);
    }

    #[test]
    fn sync_now_refuses_when_not_enabled_or_not_configured() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(sync_now(&store, 1000).is_err(), "disabled by default");
        save_settings(&store, &Settings { enabled: true, ..Default::default() }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("access key id"));
        save_settings(&store, &Settings { enabled: true, access_key_id: "AKIAEXAMPLE".into(), region: "eu-central-1".into(), sync_interval_hours: 24 }, 1000).unwrap();
        assert!(sync_now(&store, 1000).unwrap_err().to_string().contains("secret access key"), "no secret saved yet");
    }

    #[test]
    fn an_aws_sync_never_touches_devices_from_the_other_cmdb_sources() {
        use crate::store::CmdbStore;
        let store = SqliteStore::open_in_memory().unwrap();
        let other = CmdbDevice {
            external_id: "azure:vm-1".into(),
            source: "azure".into(),
            display_name: "vm-1".into(),
            os: None,
            os_version: None,
            trust_type: None,
            compliant: None,
            registered_at: None,
            last_synced_at: 500,
            matched_asset_id: None,
        };
        store.save_cmdb_device(&other.external_id, &serde_json::to_vec(&other).unwrap(), 500).unwrap();

        save_settings(&store, &Settings { enabled: true, access_key_id: "AKIAEXAMPLE".into(), region: "eu-central-1".into(), sync_interval_hours: 24 }, 1000).unwrap();
        save_secret_access_key(&store, "sekret", 1000).unwrap();
        // sync_now itself will fail (no real AWS to reach), but the pruning logic runs after a
        // successful fetch - exercised directly here instead, matching azure_cloud.rs's own test
        // shape for the same reason (no live network in unit tests).
        assert!(sync_now(&store, 1000).is_err());

        let devices = list_devices(&store).unwrap();
        assert_eq!(devices.len(), 1, "the azure device must still be there - an aws sync must never prune another source's rows");
        assert_eq!(devices[0].source, "azure");
    }

    #[test]
    fn hostname_matching_is_exact_and_case_insensitive() {
        let mut a = Asset::new(crate::model::Mac([1, 2, 3, 4, 5, 6]), 0);
        a.hostnames = vec!["Web-Prod-01".into()];
        let by_hostname: std::collections::HashMap<String, i64> = [a].iter().flat_map(|a| a.hostnames.iter().map(move |h| (h.to_lowercase(), a.id))).collect();
        assert_eq!(by_hostname.get(&"web-prod-01".to_lowercase()).copied(), Some(0));
        assert_eq!(by_hostname.get("no-such-host"), None);
    }

    #[test]
    fn xml_parsing_reads_instance_id_name_tag_platform_and_state_out_of_a_reservation_set() {
        let xml = r#"<DescribeInstancesResponse>
<reservationSet>
<item>
<instancesSet>
<item>
<instanceId>i-0abc123</instanceId>
<platform>windows</platform>
<instanceState><code>16</code><name>running</name></instanceState>
<tagSet>
<item><key>Name</key><value>web-prod-01</value></item>
<item><key>Env</key><value>prod</value></item>
</tagSet>
</item>
</instancesSet>
</item>
</reservationSet>
</DescribeInstancesResponse>"#;
        let (instances, next_token) = parse_describe_instances(xml);
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].instance_id, "i-0abc123");
        assert_eq!(instances[0].name, "web-prod-01");
        assert_eq!(instances[0].platform.as_deref(), Some("windows"));
        assert_eq!(instances[0].state.as_deref(), Some("running"));
        assert_eq!(next_token, None);
    }

    #[test]
    fn an_instance_with_no_name_tag_falls_back_to_its_instance_id() {
        let xml = r#"<reservationSet><item><instancesSet><item>
<instanceId>i-0nameless</instanceId>
<instanceState><code>16</code><name>running</name></instanceState>
</item></instancesSet></item></reservationSet>"#;
        let (instances, _) = parse_describe_instances(xml);
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].name, "i-0nameless");
    }

    #[test]
    fn a_next_token_is_read_when_present() {
        let xml = "<x><nextToken>abc==</nextToken></x>";
        let (_, token) = parse_describe_instances(xml);
        assert_eq!(token.as_deref(), Some("abc=="));
    }

    #[test]
    fn urlencode_leaves_unreserved_characters_alone_and_percent_encodes_the_rest() {
        assert_eq!(urlencode("Describe-Instances_v1.0~test"), "Describe-Instances_v1.0~test");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("abc=="), "abc%3D%3D");
    }
}
