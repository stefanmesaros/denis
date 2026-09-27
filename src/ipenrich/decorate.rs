//! Decorates an event/alert's `raw_details` (or any other JSON blob with IP addresses in it) with
//! whatever enrichment is already cached, at the point a response is built for the API — not at
//! detection time. This keeps `detect.rs`'s rule engine exactly as it is (pure, synchronous, no
//! knowledge of enrichment at all) while still satisfying `IP_ENRICHMENT.md` §13: every "ip" or
//! "remote" field anywhere in an event's JSON (`destinations[].ip`, `client.ip`, `server.ip`, a
//! bare top-level `ip`, `threat_list_match`/port-scan/volume-anomaly's own `remote`, …) gains a
//! sibling `ip_info` object with whatever is known, generically — new rules never need to
//! remember to call anything for this to keep working, they just need to keep calling their
//! address field `"ip"` or `"remote"`, which every existing rule already does (checked against
//! every literal `"ip":`/`"remote":` in `detect.rs` — two names, not one, is a real inconsistency
//! in the rules themselves, not a simplification made here).
//!
//! Always best-effort and read-only against the cache (`Service::best_effort`), so decorating a
//! whole page of alerts is exactly as fast as walking their JSON, never a per-request network
//! wait; whatever IPs are found are also hand off to `Service::enqueue` so the *next* time the
//! same address is seen, it is more likely already answered.

use std::collections::HashMap;
use std::net::IpAddr;

use serde_json::Value;

use super::service::Service;
use super::types::IpInfo;

/// The address-field names checked at every object in the tree — see the module doc for why
/// there are two rather than one.
const IP_KEYS: [&str; 2] = ["ip", "remote"];

fn addr_in(map: &serde_json::Map<String, Value>) -> Option<IpAddr> {
    IP_KEYS.iter().find_map(|k| map.get(*k).and_then(Value::as_str).and_then(|s| s.parse::<IpAddr>().ok()))
}

fn collect(v: &Value, out: &mut Vec<IpAddr>) {
    match v {
        Value::Object(map) => {
            if let Some(ip) = addr_in(map) {
                out.push(ip);
            }
            for val in map.values() {
                collect(val, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|val| collect(val, out)),
        _ => {}
    }
}

fn inject(v: &mut Value, infos: &HashMap<IpAddr, IpInfo>) {
    match v {
        Value::Object(map) => {
            if let Some(ip) = addr_in(map) {
                if let Some(info) = infos.get(&ip) {
                    if let Ok(json) = serde_json::to_value(info) {
                        map.insert("ip_info".to_string(), json);
                    }
                }
            }
            // `IpInfo` itself carries an `ip` field, so the "ip_info" node just inserted above
            // would otherwise look like yet another node needing its own "ip_info" — recursing
            // into it would insert one more nested "ip_info" inside that, forever. It never needs
            // decorating a second time, so it is the one key this walk always skips.
            for (k, val) in map.iter_mut() {
                if k != "ip_info" {
                    inject(val, infos);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|val| inject(val, infos)),
        _ => {}
    }
}

/// Decorates every one of `values` in place, batching the cache lookups across the whole slice —
/// what the Alerts/Events list endpoints call on the page they are about to return.
pub fn decorate_all(service: &Service, values: &mut [Value], now: i64) {
    let mut ips = Vec::new();
    for v in values.iter() {
        collect(v, &mut ips);
    }
    if ips.is_empty() {
        return;
    }
    let infos = service.best_effort(&ips, now);
    service.enqueue(&ips);
    for v in values.iter_mut() {
        inject(v, &infos);
    }
}

/// The same, for one value (a single alert fetched by id, an asset's IP history, …).
pub fn decorate(service: &Service, value: &mut Value, now: i64) {
    let mut values = [value.take()];
    decorate_all(service, &mut values, now);
    *value = values[0].take();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipenrich::dns::DnsConfig;
    use crate::ipenrich::provider::test_support::FixedProvider;
    use crate::ipenrich::types::EnrichedIp;
    use crate::ipenrich::{DnsResolver, GeoipProvider};
    use crate::store::sqlite::SqliteStore;
    use std::sync::Arc;

    fn service_with(answer: EnrichedIp) -> Arc<Service> {
        let store: std::sync::Arc<dyn crate::store::Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let dns = Arc::new(DnsResolver::new(DnsConfig { enabled: false, ..Default::default() }));
        let geoip: Arc<dyn GeoipProvider> = Arc::new(FixedProvider { answer });
        Service::spawn(store, dns, geoip, super::super::service::CacheTtls::default())
    }

    #[tokio::test]
    async fn a_destinations_array_and_a_nested_client_server_pair_both_get_decorated() {
        let svc = service_with(EnrichedIp::default());
        // prime the cache the way the background worker would, so decorate_all (read-only) sees it
        svc.enrich_now("8.8.8.8".parse().unwrap(), 1000).await;

        let mut details = serde_json::json!({
            "destinations": [{"ip": "8.8.8.8", "proto": "tcp", "port": 443}, {"ip": "10.0.0.5", "proto": "tcp", "port": 80}],
            "client": {"mac": "aa:bb", "ip": "8.8.8.8"},
        });
        decorate(&svc, &mut details, 1000);
        assert!(details["destinations"][0]["ip_info"]["classification"] == "public", "{details}");
        // a private address still gets its classification (cheap, always known, useful on its
        // own — "10.0.0.5 (private)") but no country/ASN/etc., which are never looked up for it
        assert_eq!(details["destinations"][1]["ip_info"]["classification"], "private");
        assert!(details["destinations"][1]["ip_info"]["country"].is_null());
        assert_eq!(details["client"]["ip_info"]["classification"], "public");
    }

    #[tokio::test]
    async fn a_bare_remote_field_is_decorated_the_same_as_ip_threat_list_match_and_friends() {
        // detect.rs's threat_list_match/port-scan/volume-anomaly rules name the address "remote",
        // not "ip" — a real inconsistency in the rules themselves (see the module doc), which this
        // locks in so it is never silently reintroduced.
        let svc = service_with(EnrichedIp { country: Some("RU".into()), ..Default::default() });
        svc.enrich_now("185.220.101.7".parse().unwrap(), 1000).await;
        let mut details = serde_json::json!({"summary": "contacted a known-bad address", "remote": "185.220.101.7", "port": 4444, "proto": "tcp"});
        decorate(&svc, &mut details, 1000);
        assert_eq!(details["ip_info"]["classification"], "public");
        assert_eq!(details["ip_info"]["country"], "RU");
    }

    #[tokio::test]
    async fn a_blob_with_no_ip_fields_at_all_is_left_completely_untouched() {
        let svc = service_with(EnrichedIp::default());
        let mut details = serde_json::json!({"summary": "no addresses here", "score": 42});
        let before = details.clone();
        decorate(&svc, &mut details, 1000);
        assert_eq!(details, before);
    }

    #[tokio::test]
    async fn decorate_all_batches_lookups_across_the_whole_page_at_once() {
        let svc = service_with(EnrichedIp { country: Some("US".into()), ..Default::default() });
        svc.enrich_now("1.1.1.1".parse().unwrap(), 1000).await;
        let mut values = vec![serde_json::json!({"ip": "1.1.1.1"}), serde_json::json!({"ip": "1.1.1.1"}), serde_json::json!({"ip": "not-an-ip"})];
        decorate_all(&svc, &mut values, 1000);
        assert_eq!(values[0]["ip_info"]["country"], "US");
        assert_eq!(values[1]["ip_info"]["country"], "US");
        assert!(values[2].get("ip_info").is_none(), "an unparseable ip field is ignored, not an error");
    }
}
