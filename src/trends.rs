//! Historical trends: 5-minute samples of network health, and their
//! downsampling for charts. Pure functions; the engine owns the schedule.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::model::{Asset, Baseline, Event, Metric};
use crate::store::Store;

pub const SAMPLE_SECS: i64 = 300;

/// One sample per collector (`""` = local) at the 5-minute boundary of `now`.
///
/// * `traffic`: bytes (out, in) per collector since the previous sample
/// * `alerts`: alerts raised since the previous sample
/// * `online_window`: a device counts as online if seen this recently
pub fn build_metrics(
    assets: &[Asset],
    traffic: &HashMap<String, (u64, u64)>,
    alerts: &[Event],
    online_window: i64,
    now: i64,
) -> Vec<Metric> {
    let ts = now / SAMPLE_SECS * SAMPLE_SECS;
    let mut by: BTreeMap<String, Metric> = BTreeMap::new();
    let blank = |agent: &str| Metric {
        ts,
        agent_id: agent.to_string(),
        devices_total: 0,
        devices_online: 0,
        bytes_out: 0,
        bytes_in: 0,
        alerts: 0,
    };
    for a in assets {
        let m = by.entry(a.agent_id.clone().unwrap_or_default()).or_insert_with_key(|k| blank(k));
        m.devices_total += 1;
        if now - a.last_seen <= online_window {
            m.devices_online += 1;
        }
    }
    for (k, (o, i)) in traffic {
        let m = by.entry(k.clone()).or_insert_with_key(|k| blank(k));
        m.bytes_out += *o as i64;
        m.bytes_in += *i as i64;
    }
    for e in alerts.iter().filter(|e| e.severity != "info") {
        let m = by.entry(e.agent_id.clone().unwrap_or_default()).or_insert_with_key(|k| blank(k));
        m.alerts += 1;
    }
    by.into_values().collect()
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Point {
    pub ts: i64,
    pub devices_total: i64,
    pub devices_online: i64,
    pub bytes_out: i64,
    pub bytes_in: i64,
    pub alerts: i64,
}

/// Merge collectors per timestamp, then group into buckets of `step` seconds
/// (a multiple of `SAMPLE_SECS`) so a chart never receives more than `max_points`.
/// Within a step: device counts are averaged, traffic and alerts summed.
/// Returns the points and the step used.
pub fn downsample(samples: &[Metric], max_points: usize) -> (Vec<Point>, i64) {
    let mut merged: BTreeMap<i64, Point> = BTreeMap::new();
    for m in samples {
        let p = merged.entry(m.ts).or_insert(Point {
            ts: m.ts,
            devices_total: 0,
            devices_online: 0,
            bytes_out: 0,
            bytes_in: 0,
            alerts: 0,
        });
        p.devices_total += m.devices_total;
        p.devices_online += m.devices_online;
        p.bytes_out += m.bytes_out;
        p.bytes_in += m.bytes_in;
        p.alerts += m.alerts;
    }
    let (Some(first), Some(last)) = (merged.keys().next().copied(), merged.keys().next_back().copied()) else {
        return (Vec::new(), SAMPLE_SECS);
    };
    let span = last - first + SAMPLE_SECS;
    let steps_needed = (span + max_points as i64 * SAMPLE_SECS - 1) / (max_points as i64 * SAMPLE_SECS);
    let step = steps_needed.max(1) * SAMPLE_SECS;
    let mut groups: BTreeMap<i64, (Point, i64)> = BTreeMap::new();
    for p in merged.into_values() {
        let key = p.ts / step * step;
        let (g, n) = groups.entry(key).or_insert((Point { ts: key, devices_total: 0, devices_online: 0, bytes_out: 0, bytes_in: 0, alerts: 0 }, 0));
        g.devices_total += p.devices_total;
        g.devices_online += p.devices_online;
        g.bytes_out += p.bytes_out;
        g.bytes_in += p.bytes_in;
        g.alerts += p.alerts;
        *n += 1;
    }
    let pts = groups
        .into_values()
        .map(|(mut g, n)| {
            g.devices_total /= n;
            g.devices_online /= n;
            g
        })
        .collect();
    (pts, step)
}

// --------------------------------------------------------------------------------- top talkers

/// One device's share of `top_talkers`: a live snapshot, not a time series.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct TopTalker {
    pub asset_id: i64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// Every device's traffic so far, from its baseline (`--flows` only: without it every
/// `typical_destinations` map is empty and this returns nothing). Unlike `Metric`/`Point`
/// this is cumulative since each destination was first learned, not a period total — it is a
/// leaderboard of who talks the most, not a chart of when. A device's own gateway and the
/// monitoring host itself (`is_gateway`/`is_self`) are left out by default, since traffic
/// naturally funnels through them and they would otherwise dominate every list; `excluded`
/// (asset ids an administrator picked by hand) is removed the same way. Devices with no
/// recorded traffic are dropped rather than shown as a zero-length bar.
pub fn top_talkers(baselines: &[Baseline], assets: &[Asset], excluded: &HashSet<i64>) -> Vec<TopTalker> {
    let auto_excluded: HashSet<i64> = assets.iter().filter(|a| a.is_gateway || a.is_self).map(|a| a.id).collect();
    baselines
        .iter()
        .filter(|b| !auto_excluded.contains(&b.asset_id) && !excluded.contains(&b.asset_id))
        .map(|b| {
            let (bytes_out, bytes_in) = b.typical_destinations.values().fold((0u64, 0u64), |(o, i), d| (o + d.bytes_out, i + d.bytes_in));
            TopTalker { asset_id: b.asset_id, bytes_out, bytes_in }
        })
        .filter(|t| t.bytes_out > 0 || t.bytes_in > 0)
        .collect()
}

const TOP_TALKERS_EXCLUDED_KEY: &str = "top_talkers_excluded";

/// Asset ids an administrator excluded from the Top talkers leaderboards by hand, on top of the
/// automatic gateway/self exclusion `top_talkers` always applies.
pub fn load_excluded(store: &dyn Store) -> anyhow::Result<HashSet<i64>> {
    Ok(store.get_setting(TOP_TALKERS_EXCLUDED_KEY)?.and_then(|b| serde_json::from_slice::<Vec<i64>>(&b).ok()).unwrap_or_default().into_iter().collect())
}

pub fn save_excluded(store: &dyn Store, ids: &HashSet<i64>, now: i64) -> anyhow::Result<()> {
    let mut list: Vec<i64> = ids.iter().copied().collect();
    list.sort_unstable();
    store.set_setting(TOP_TALKERS_EXCLUDED_KEY, &serde_json::to_vec(&list)?, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IpRecord, Mac};
    use std::net::Ipv4Addr;

    fn asset(n: u8, agent: Option<&str>, last_seen: i64) -> Asset {
        let mut a = Asset::new(Mac([0x3c, 0, 0, 0, 0, n]), 0);
        a.agent_id = agent.map(str::to_string);
        a.last_seen = last_seen;
        a.ip_history.push(IpRecord { ip: Ipv4Addr::new(10, 0, 0, n), first_seen: 0, last_seen });
        a
    }

    fn alert(agent: Option<&str>, sev: &str) -> Event {
        Event { id: 1, agent_id: agent.map(str::to_string), asset_id: 1, kind: "x".into(), timestamp: 0, severity: sev.into(), score: 50, acked: false, raw_details: serde_json::json!({}) }
    }

    #[test]
    fn samples_are_per_collector_and_aligned() {
        let now = 10_000 + 123;
        let assets = vec![asset(1, None, now - 10), asset(2, None, now - 5000), asset(3, Some("b"), now - 20)];
        let mut traffic = HashMap::new();
        traffic.insert(String::new(), (1000u64, 2000u64));
        traffic.insert("b".to_string(), (7, 8));
        traffic.insert("ghost".to_string(), (1, 1)); // traffic from an agent with no assets yet
        let alerts = vec![alert(None, "high"), alert(None, "info"), alert(Some("b"), "low")];
        let m = build_metrics(&assets, &traffic, &alerts, 600, now);
        assert!(m.iter().all(|x| x.ts == 9900));
        let get = |k: &str| m.iter().find(|x| x.agent_id == k).unwrap();
        assert_eq!((get("").devices_total, get("").devices_online, get("").bytes_out, get("").bytes_in, get("").alerts), (2, 1, 1000, 2000, 1));
        assert_eq!((get("b").devices_total, get("b").devices_online, get("b").alerts), (1, 1, 1));
        assert_eq!(get("ghost").bytes_out, 1);
    }

    fn metric(ts: i64, agent: &str, online: i64, out: i64) -> Metric {
        Metric { ts, agent_id: agent.into(), devices_total: online + 1, devices_online: online, bytes_out: out, bytes_in: 0, alerts: 1 }
    }

    #[test]
    fn collectors_merge_per_timestamp() {
        let (p, step) = downsample(&[metric(0, "", 3, 10), metric(0, "b", 2, 5), metric(300, "", 4, 1)], 100);
        assert_eq!(step, 300);
        assert_eq!((p[0].devices_online, p[0].bytes_out, p[0].alerts), (5, 15, 2));
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn long_ranges_are_bucketed_to_the_point_budget() {
        // 2 days of 5-minute samples = 576 points -> at most 100
        let samples: Vec<_> = (0..576).map(|i| metric(i * 300, "", 10, 100)).collect();
        let (p, step) = downsample(&samples, 100);
        assert!(p.len() <= 100, "{}", p.len());
        assert_eq!(step % 300, 0);
        assert!(step > 300);
        // traffic and alerts are conserved by summing; device counts are averaged
        assert_eq!(p.iter().map(|x| x.bytes_out).sum::<i64>(), 576 * 100);
        assert_eq!(p.iter().map(|x| x.alerts).sum::<i64>(), 576);
        assert!(p.iter().all(|x| x.devices_online == 10));
    }

    #[test]
    fn empty_input_is_fine() {
        assert_eq!(downsample(&[], 50).0.len(), 0);
    }

    fn dest(bytes_out: u64, bytes_in: u64) -> crate::model::DestStat {
        crate::model::DestStat { first_seen: 0, last_seen: 0, bytes: bytes_out + bytes_in, bytes_out, bytes_in }
    }

    fn baseline_with(asset_id: i64, dests: &[(&str, u64, u64)]) -> Baseline {
        let mut b = Baseline::new(asset_id, 0);
        for (ip, out, inb) in dests {
            b.typical_destinations.insert((*ip).to_string(), dest(*out, *inb));
        }
        b
    }

    #[test]
    fn top_talkers_sums_each_devices_destinations() {
        let b = baseline_with(1, &[("1.1.1.1", 100, 10), ("2.2.2.2", 50, 5)]);
        let a = asset(1, None, 0);
        let out = top_talkers(&[b], &[a], &HashSet::new());
        assert_eq!(out, vec![TopTalker { asset_id: 1, bytes_out: 150, bytes_in: 15 }]);
    }

    #[test]
    fn top_talkers_leaves_out_gateway_self_and_hand_picked_devices() {
        let mut gw = asset(1, None, 0);
        gw.id = 1;
        gw.is_gateway = true;
        let mut me = asset(2, None, 0);
        me.id = 2;
        me.is_self = true;
        let mut picked = asset(3, None, 0);
        picked.id = 3;
        let mut normal = asset(4, None, 0);
        normal.id = 4;
        let baselines = vec![
            baseline_with(1, &[("1.1.1.1", 100, 0)]),
            baseline_with(2, &[("1.1.1.1", 100, 0)]),
            baseline_with(3, &[("1.1.1.1", 100, 0)]),
            baseline_with(4, &[("1.1.1.1", 100, 0)]),
        ];
        let excluded = HashSet::from([3]);
        let out = top_talkers(&baselines, &[gw, me, picked, normal], &excluded);
        assert_eq!(out, vec![TopTalker { asset_id: 4, bytes_out: 100, bytes_in: 0 }]);
    }

    #[test]
    fn top_talkers_drops_devices_with_no_recorded_traffic() {
        let b = baseline_with(1, &[]);
        let out = top_talkers(&[b], &[asset(1, None, 0)], &HashSet::new());
        assert!(out.is_empty());
    }

    #[test]
    fn excluded_list_round_trips_through_settings() {
        let store = crate::store::sqlite::SqliteStore::open_in_memory().unwrap();
        assert!(load_excluded(&store).unwrap().is_empty());
        save_excluded(&store, &HashSet::from([3, 1, 2]), 1).unwrap();
        assert_eq!(load_excluded(&store).unwrap(), HashSet::from([1, 2, 3]));
    }
}
