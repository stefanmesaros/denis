//! A proactive, dismissible nudge on the Rules page: "this kind of rule would suit your traffic"
//! (AI.md section 18, discussed alongside step 11 but kept as its own, smaller follow-on).
//! Deliberately not an AI feature: no LLM call, nothing sent anywhere, no schedule of its own —
//! computed fresh, cheaply, from data DENIS already tracks (baselines) each time the Rules page
//! asks for it (`GET /api/rules`), same cost as `/api/baseline/destinations`. Dismissal is a
//! purely client-side, per-browser convenience (`ui/rules.js`, `localStorage`), same as the
//! "New Rule" reason dropdowns elsewhere — nothing is written back to the server for it.
//!
//! Kept to one narrow, clearly data-backed case rather than a general recommender: devices are
//! already reaching the internet, but nothing watches that traffic at all. More patterns can be
//! added the same way later without disturbing this one.

use crate::model::Baseline;
use crate::rules::{is_public_addr, remote_entry_matches, ItWatch};

/// One thing the Rules page can proactively suggest. Currently just the one case; the id is
/// stable so the frontend can remember a dismissal across reloads without the banner text itself
/// having to be a fixed key.
pub const INTERNET_TRAFFIC_UNWATCHED: &str = "internet_traffic_unwatched";

/// True if `watches` already includes at least one enabled watch that would fire for ordinary
/// public-internet traffic (a probe address stands in for "any real public address", so this
/// also recognizes a hand-written CIDR-based watch, not just the literal word "public").
fn any_watch_covers_internet(watches: &[ItWatch]) -> bool {
    let probe: std::net::Ipv4Addr = std::net::Ipv4Addr::new(8, 8, 8, 8);
    watches.iter().any(|w| {
        w.enabled
            && match w.remotes_mode.as_str() {
                "any" => true,
                "only" => w.remotes.iter().any(|r| remote_entry_matches(r, probe)),
                "except" => !w.remotes.iter().any(|r| remote_entry_matches(r, probe)),
                _ => false,
            }
    })
}

/// True if this device's own already-tracked baseline shows it has talked to the public internet
/// at least once — no new tracking, the exact same `typical_destinations` the baseline panel and
/// `new_destination` detection already use.
fn baseline_has_public_destination(b: &Baseline) -> bool {
    b.typical_destinations.keys().any(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok_and(is_public_addr))
}

/// The one suggestion that currently applies, or `None`. `watches` should be every configured
/// network watch (enabled or not — disabled ones are filtered out here); `baselines` every
/// device's own baseline.
pub fn suggest(watches: &[ItWatch], baselines: &[Baseline]) -> Option<&'static str> {
    if any_watch_covers_internet(watches) {
        return None;
    }
    baselines.iter().any(baseline_has_public_destination).then_some(INTERNET_TRAFFIC_UNWATCHED)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(remotes_mode: &str, remotes: &[&str], enabled: bool) -> ItWatch {
        ItWatch {
            id: "w1".into(), name: "w".into(), enabled, sources: vec![], except_sources: vec![],
            proto: "any".into(), ports_mode: "any".into(), ports: vec![],
            remotes_mode: remotes_mode.into(), remotes: remotes.iter().map(|s| s.to_string()).collect(),
            min_kb: 0, score: 50, cooldown_minutes: 30,
        }
    }

    fn baseline_with(ips: &[&str]) -> Baseline {
        let mut b = Baseline::new(1, 0);
        for ip in ips {
            b.typical_destinations.insert(
                ip.to_string(),
                crate::model::DestStat { first_seen: 0, last_seen: 0, bytes: 0, bytes_out: 0, bytes_in: 0, port_churn: 0 },
            );
        }
        b
    }

    #[test]
    fn no_suggestion_with_no_data_at_all() {
        assert_eq!(suggest(&[], &[]), None);
    }

    #[test]
    fn suggests_a_watch_when_a_device_reaches_the_internet_and_nothing_watches_it() {
        let baselines = [baseline_with(&["8.8.4.4", "10.0.0.5"])];
        assert_eq!(suggest(&[], &baselines), Some(INTERNET_TRAFFIC_UNWATCHED));
    }

    #[test]
    fn private_only_traffic_never_suggests_it() {
        let baselines = [baseline_with(&["10.0.0.5", "192.168.1.9"])];
        assert_eq!(suggest(&[], &baselines), None);
    }

    #[test]
    fn an_existing_watch_covering_public_addresses_silences_the_suggestion() {
        let baselines = [baseline_with(&["8.8.4.4"])];
        assert_eq!(suggest(&[watch("only", &["public"], true)], &baselines), None);
        // a CIDR-based watch that happens to exclude the whole internet counts too
        assert_eq!(suggest(&[watch("any", &[], true)], &baselines), None);
    }

    #[test]
    fn a_disabled_watch_does_not_count_as_coverage() {
        let baselines = [baseline_with(&["8.8.4.4"])];
        assert_eq!(suggest(&[watch("only", &["public"], false)], &baselines), Some(INTERNET_TRAFFIC_UNWATCHED));
    }

    #[test]
    fn a_watch_scoped_to_only_a_private_network_does_not_count_as_internet_coverage() {
        let baselines = [baseline_with(&["8.8.4.4"])];
        assert_eq!(suggest(&[watch("only", &["private"], true)], &baselines), Some(INTERNET_TRAFFIC_UNWATCHED));
    }
}
