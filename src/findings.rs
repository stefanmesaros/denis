//! Findings: the standing weaknesses and housekeeping problems in the inventory,
//! each with an explanation and what to do about it.
//!
//! Alerts say "something just happened"; findings say "this is wrong right now and
//! stays wrong until you fix it". They are derived on demand from the inventory
//! (never stored), so a finding disappears the moment the cause is fixed, and
//! grouped by kind so 30 devices with the same problem are one line of work.
//!
//! What is deliberately *not* here: anything that would need probing beyond the
//! open-port list DENIS already has, and anything that would guess (no CVE
//! matching from a banner). Every finding is a plain fact about data the
//! collector or a person entered.

use std::collections::HashMap;

use serde::Serialize;

use crate::fingerprint::is_ot_device;
use crate::model::{Asset, AssetMeta, RiskAcceptance};
use crate::tracking::warranty_state;

/// A device not seen for this long is considered gone, so its problems are not listed.
const RECENT_SECS: i64 = 7 * 86_400;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Finding {
    /// Stable identifier of the kind of finding.
    pub id: &'static str,
    /// `high`, `medium`, `low` or `info`.
    pub severity: &'static str,
    pub title: &'static str,
    /// Why it matters.
    pub why: &'static str,
    /// What to do.
    pub fix: &'static str,
    /// The devices affected (asset ids), in a stable order.
    pub assets: Vec<i64>,
}

struct Kind {
    id: &'static str,
    severity: &'static str,
    title: &'static str,
    why: &'static str,
    fix: &'static str,
}

const fn kind(id: &'static str, severity: &'static str, title: &'static str, why: &'static str, fix: &'static str) -> Kind {
    Kind { id, severity, title, why, fix }
}

const TELNET: Kind = kind("telnet_open", "high", "Telnet is open",
    "Telnet sends the password and everything typed in clear text; anyone on the network path can read it.",
    "Turn Telnet off and use SSH. If the device cannot do SSH, limit access to a management VLAN or replace the device.");
const FTP: Kind = kind("ftp_open", "medium", "FTP is open",
    "FTP sends passwords and files unencrypted.",
    "Switch to SFTP or FTPS, or disable the service if nobody needs it.");
const RDP: Kind = kind("rdp_open", "medium", "Remote Desktop (RDP) is open",
    "RDP is a favourite target for password guessing and has had serious remote-code-execution flaws.",
    "Allow RDP only through a VPN or gateway, require Network Level Authentication and multi-factor sign-in, and keep the system patched. Disable it where it is not needed.");
const VNC: Kind = kind("vnc_open", "medium", "VNC remote screen is open",
    "VNC often has a weak or no password and does not encrypt by default.",
    "Disable it, or tunnel it through SSH or a VPN and set a strong password.");
const SMB: Kind = kind("smb_open", "low", "File sharing (SMB/NetBIOS) is open on a device that is not a computer or file server",
    "File-sharing services on printers, cameras or embedded devices are rarely needed and are often outdated.",
    "Turn off file sharing on the device unless it is used, and update its firmware.");
const MYSQL: Kind = kind("mysql_open", "medium", "A MySQL database is reachable on the network",
    "Databases should be reachable only from the applications that use them.",
    "Bind the database to localhost or a private interface and firewall the port to the application servers.");
const MQTT: Kind = kind("mqtt_open", "low", "An MQTT broker is open",
    "MQTT brokers accept anonymous connections unless configured otherwise, exposing sensor data and control topics.",
    "Require authentication (and TLS) on the broker, and restrict the port to the devices that use it.");
const WINBOX: Kind = kind("winbox_open", "medium", "MikroTik Winbox management is open",
    "Management interfaces on the LAN side are reachable by every device, including compromised ones.",
    "Restrict management to a management VLAN or specific addresses, use strong credentials and keep RouterOS updated.");
const LOST: Kind = kind("lost_device_online", "high", "A device marked lost or stolen is on the network",
    "A device you recorded as lost or stolen has been seen recently.",
    "Treat it as an incident: find where it is connected, block its MAC at the switch or access point, and change credentials it may hold.");
const RETIRED: Kind = kind("retired_device_online", "medium", "A retired device is still on the network",
    "Retired equipment is usually not patched or monitored, but it is still connected.",
    "Disconnect and wipe it, or change its status if it is back in service.");
const CRIT_NO_OWNER: Kind = kind("critical_no_owner", "medium", "Critical devices have no owner",
    "When a device you rated high or critical misbehaves, nobody is responsible for answering.",
    "Open each device and fill in the owner (a person or team).");
const OT_NO_LEVEL: Kind = kind("ot_no_purdue_level", "low", "Industrial devices have no Purdue level",
    "Without a level DENIS and your auditors cannot check that traffic follows the segmentation plan.",
    "Set the Purdue level (0–5) and zone on each industrial device.");
const UNIDENTIFIED: Kind = kind("unidentified", "low", "Devices could not be identified",
    "A device you cannot name is a device you cannot secure or explain.",
    "Find out what each one is and enter its type and name; DENIS will then treat it as known.");
const UNREVIEWED: Kind = kind("unreviewed", "info", "Devices nobody has reviewed yet",
    "New devices stay on this list until a person confirms they belong. It is how an unknown device gets noticed rather than assumed.",
    "Look through them (Devices tab, filter: needs review). Open each to correct its name and type, or press Mark as known; \"Mark all shown as known\" accepts a whole list at once.");
const WARRANTY_EXPIRED: Kind = kind("warranty_expired", "low", "Warranty has expired",
    "Out-of-warranty devices are often out of support, too: no repairs and sometimes no security updates.",
    "Renew support, plan the replacement, or set the status to retired when it goes.");
const WARRANTY_EXPIRING: Kind = kind("warranty_expiring", "info", "Warranty expires within 60 days",
    "Renewal is cheaper before it lapses.",
    "Renew the warranty or support contract, or plan the replacement.");

/// Exposed-service findings: (port, kind, applies to computers/NAS/servers too?)
const PORT_FINDINGS: &[(u16, &Kind, bool)] = &[
    (23, &TELNET, true),
    (21, &FTP, true),
    (3389, &RDP, true),
    (5900, &VNC, true),
    (3306, &MYSQL, true),
    (1883, &MQTT, true),
    (8291, &WINBOX, true),
    (445, &SMB, false),
    (139, &SMB, false),
];

/// Every sentence a finding can show (title, why, fix), so the translation catalogs can be checked
/// against them.
pub fn texts() -> Vec<&'static str> {
    ALL_KINDS
        .iter()
        .copied()
        .flat_map(|k| [k.title, k.why, k.fix])
        .collect()
}

const ALL_KINDS: [&Kind; 16] = [&TELNET, &FTP, &RDP, &VNC, &SMB, &MYSQL, &MQTT, &WINBOX, &LOST, &RETIRED, &CRIT_NO_OWNER, &OT_NO_LEVEL, &UNIDENTIFIED, &UNREVIEWED, &WARRANTY_EXPIRED, &WARRANTY_EXPIRING];

/// Is `id` a kind of finding this program knows?
pub fn is_known(id: &str) -> bool {
    ALL_KINDS.iter().any(|k| k.id == id)
}

/// Findings that are about what a scan of the device shows (an open port), so a rescan can confirm a fix.
pub fn is_port_finding(id: &str) -> bool {
    PORT_FINDINGS.iter().any(|(_, k, _)| k.id == id)
}

/// An accepted risk as the console shows it: the decision plus the words of the finding it is about.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct AcceptedRisk {
    pub id: i64,
    pub finding_id: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
    pub asset_id: i64,
    pub reason: String,
    pub accepted_by: String,
    pub accepted_at: i64,
    pub expires_at: Option<i64>,
    /// `false` when the problem has gone away since (fixed, or the device left): the decision can be withdrawn.
    pub still_applies: bool,
}

/// Split the current findings by the decisions in force: what is still open, and what people accepted. A device
/// with an accepted risk drops out of its finding (the finding disappears when nothing else is left); an
/// expired or withdrawn decision no longer counts.
pub fn apply_acceptances(all: Vec<Finding>, acceptances: &[RiskAcceptance], now: i64) -> (Vec<Finding>, Vec<AcceptedRisk>) {
    let active: Vec<&RiskAcceptance> = acceptances.iter().filter(|a| a.is_active(now)).collect();
    let accepted_now = |finding: &str, asset: i64| active.iter().any(|a| a.finding_id == finding && a.asset_id == asset);
    let mut listed: Vec<AcceptedRisk> = Vec::new();
    for a in &active {
        let Some(k) = ALL_KINDS.iter().find(|k| k.id == a.finding_id) else { continue };
        let still = all.iter().any(|f| f.id == k.id && f.assets.contains(&a.asset_id));
        listed.push(AcceptedRisk {
            id: a.id, finding_id: k.id, title: k.title, severity: k.severity, asset_id: a.asset_id, reason: a.reason.clone(),
            accepted_by: a.accepted_by.clone(), accepted_at: a.accepted_at, expires_at: a.expires_at, still_applies: still,
        });
    }
    let open = all
        .into_iter()
        .filter_map(|mut f| {
            f.assets.retain(|id| !accepted_now(f.id, *id));
            (!f.assets.is_empty()).then_some(f)
        })
        .collect();
    (open, listed)
}

/// Does `finding_id` apply to this device right now? (Used to confirm a fix after a rescan.)
pub fn applies(a: &Asset, meta: Option<&AssetMeta>, now: i64, finding_id: &str) -> bool {
    let metas: HashMap<i64, AssetMeta> = meta.map(|m| (a.id, m.clone())).into_iter().collect();
    compute(std::slice::from_ref(a), &metas, now).iter().any(|f| f.id == finding_id)
}

fn rank(sev: &str) -> u8 {
    match sev {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

/// All current findings, most severe first.
pub fn compute(assets: &[Asset], metas: &HashMap<i64, AssetMeta>, now: i64) -> Vec<Finding> {
    let mut by_kind: Vec<(&Kind, Vec<i64>)> = Vec::new();
    let mut add = |k: &'static Kind, id: i64| match by_kind.iter_mut().find(|(x, _)| x.id == k.id) {
        Some((_, v)) => {
            if !v.contains(&id) {
                v.push(id)
            }
        }
        None => by_kind.push((k, vec![id])),
    };
    let default_meta = AssetMeta::default();

    for a in assets {
        let m = metas.get(&a.id).unwrap_or(&default_meta);
        let recent = now - a.last_seen <= RECENT_SECS;
        let status = m.status.as_deref().unwrap_or("active");
        let device_type = m.type_override.as_deref().unwrap_or(&a.device_type);
        let ot = is_ot_device(a);

        // status-based: a lost or retired device that is talking is the finding
        if recent {
            match status {
                "lost" | "stolen" => add(&LOST, a.id),
                "retired" => add(&RETIRED, a.id),
                _ => {}
            }
        }
        // Everything below is about devices in use.
        if !recent || matches!(status, "lost" | "stolen" | "retired" | "spare") {
            continue;
        }

        let server_like = matches!(device_type, "computer" | "nas" | "server");
        for (port, k, on_servers) in PORT_FINDINGS {
            if a.open_ports.iter().any(|p| p.port == *port && p.proto == "tcp") && (*on_servers || !server_like) {
                add(k, a.id);
            }
        }
        if matches!(m.criticality.as_deref(), Some("high" | "critical")) && m.owner.is_none() {
            add(&CRIT_NO_OWNER, a.id);
        }
        if ot && m.purdue_level.is_none() {
            add(&OT_NO_LEVEL, a.id);
        }
        if !m.reviewed && !m.manual && !a.is_self {
            add(&UNREVIEWED, a.id);
        }
        if device_type == "unknown" && m.display_name.is_none() && !a.is_self {
            add(&UNIDENTIFIED, a.id);
        }
        match warranty_state(m, now) {
            Some(("expired", _)) => add(&WARRANTY_EXPIRED, a.id),
            Some(("expiring", _)) => add(&WARRANTY_EXPIRING, a.id),
            _ => {}
        }
    }

    let mut out: Vec<Finding> = by_kind
        .into_iter()
        .map(|(k, mut ids)| {
            ids.sort_unstable();
            Finding { id: k.id, severity: k.severity, title: k.title, why: k.why, fix: k.fix, assets: ids }
        })
        .collect();
    out.sort_by(|a, b| rank(a.severity).cmp(&rank(b.severity)).then(b.assets.len().cmp(&a.assets.len())).then(a.id.cmp(b.id)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mac, OpenPort};

    const NOW: i64 = 1_800_000_000;

    fn dev(id: i64, ty: &str, ports: &[u16]) -> Asset {
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, id as u8]), NOW - 1000);
        a.id = id;
        a.device_type = ty.into();
        a.vendor = Some("Acme".into());
        a.last_seen = NOW - 60;
        a.open_ports = ports.iter().map(|p| OpenPort { port: *p, proto: "tcp".into(), service: None }).collect();
        a
    }

    fn ids(f: &[Finding], id: &str) -> Vec<i64> {
        f.iter().find(|x| x.id == id).map(|x| x.assets.clone()).unwrap_or_default()
    }

    #[test]
    fn exposed_services_are_grouped_by_kind_and_ranked_by_severity() {
        let assets = vec![dev(1, "camera", &[23, 445]), dev(2, "iot", &[23]), dev(3, "printer", &[21])];
        let f = compute(&assets, &HashMap::new(), NOW);
        assert_eq!(f[0].id, "telnet_open");
        assert_eq!(f[0].severity, "high");
        assert_eq!(f[0].assets, vec![1, 2], "one finding, two devices");
        assert_eq!(ids(&f, "ftp_open"), vec![3]);
        assert_eq!(ids(&f, "smb_open"), vec![1], "SMB on a camera is a finding");
        assert!(f.iter().all(|x| !x.fix.is_empty() && !x.why.is_empty()));
    }

    #[test]
    fn file_sharing_is_normal_on_computers_and_servers_but_telnet_is_not() {
        let f = compute(&[dev(1, "computer", &[445, 139, 23]), dev(2, "nas", &[445])], &HashMap::new(), NOW);
        assert!(ids(&f, "smb_open").is_empty());
        assert_eq!(ids(&f, "telnet_open"), vec![1]);
    }

    #[test]
    fn a_users_type_correction_decides_what_counts_as_normal() {
        let mut metas = HashMap::new();
        metas.insert(1, AssetMeta { type_override: Some("server".into()), ..Default::default() });
        let f = compute(&[dev(1, "unknown", &[445])], &metas, NOW);
        assert!(ids(&f, "smb_open").is_empty());
        assert!(ids(&f, "unidentified").is_empty(), "the corrected type is not 'unknown'");
    }

    #[test]
    fn lost_and_retired_devices_that_are_still_talking_are_findings_but_quiet_ones_are_not() {
        let mut metas = HashMap::new();
        metas.insert(1, AssetMeta { status: Some("stolen".into()), ..Default::default() });
        metas.insert(2, AssetMeta { status: Some("retired".into()), ..Default::default() });
        metas.insert(3, AssetMeta { status: Some("retired".into()), ..Default::default() });
        let mut gone = dev(3, "computer", &[]);
        gone.last_seen = NOW - 30 * 86_400;
        let f = compute(&[dev(1, "phone", &[23]), dev(2, "computer", &[23]), gone], &metas, NOW);
        assert_eq!(ids(&f, "lost_device_online"), vec![1]);
        assert_eq!(f[0].id, "lost_device_online", "listed first");
        assert_eq!(ids(&f, "retired_device_online"), vec![2]);
        assert!(ids(&f, "telnet_open").is_empty(), "no exposure noise about devices that should not be there");
    }

    #[test]
    fn devices_not_seen_for_a_week_are_not_nagged_about() {
        let mut a = dev(1, "camera", &[23]);
        a.last_seen = NOW - 8 * 86_400;
        assert!(compute(&[a], &HashMap::new(), NOW).is_empty());
    }

    #[test]
    fn housekeeping_findings_follow_the_register() {
        let mut metas = HashMap::new();
        metas.insert(1, AssetMeta { criticality: Some("critical".into()), ..Default::default() });
        metas.insert(2, AssetMeta { criticality: Some("critical".into()), owner: Some("Ops".into()), ..Default::default() });
        let day = NOW / 86_400;
        let date = |d: i64| crate::report::iso((day + d) * 86_400)[..10].to_string();
        metas.insert(3, AssetMeta { warranty_expires: Some(date(-5)), ..Default::default() });
        metas.insert(4, AssetMeta { warranty_expires: Some(date(30)), ..Default::default() });
        metas.insert(5, AssetMeta { warranty_expires: Some(date(400)), ..Default::default() });
        let assets: Vec<Asset> = (1..=5).map(|i| dev(i, "computer", &[])).collect();
        let f = compute(&assets, &metas, NOW);
        assert_eq!(ids(&f, "critical_no_owner"), vec![1]);
        assert_eq!(ids(&f, "warranty_expired"), vec![3]);
        assert_eq!(ids(&f, "warranty_expiring"), vec![4]);
    }

    #[test]
    fn industrial_devices_without_a_purdue_level_and_unknown_devices_are_listed() {
        let plc = dev(1, "plc", &[]);
        let leveled = dev(2, "plc", &[]);
        let mut metas = HashMap::new();
        metas.insert(2, AssetMeta { purdue_level: Some("1".into()), ..Default::default() });
        let mystery = dev(3, "unknown", &[]);
        let mut named = dev(4, "unknown", &[]);
        named.vendor = None;
        metas.insert(4, AssetMeta { display_name: Some("Gate box".into()), ..Default::default() });
        let mut me = dev(5, "unknown", &[]);
        me.is_self = true;
        let f = compute(&[plc, leveled, mystery, named, me], &metas, NOW);
        assert_eq!(ids(&f, "ot_no_purdue_level"), vec![1]);
        assert_eq!(ids(&f, "unidentified"), vec![3], "named devices and this scanner are not 'unidentified'");
    }

    #[test]
    fn spare_and_empty_inventories_are_quiet() {
        let mut metas = HashMap::new();
        metas.insert(1, AssetMeta { status: Some("spare".into()), ..Default::default() });
        assert!(compute(&[dev(1, "camera", &[23])], &metas, NOW).is_empty());
        assert!(compute(&[], &HashMap::new(), NOW).is_empty());
    }

    fn accept(id: i64, finding: &str, asset: i64, expires: Option<i64>) -> RiskAcceptance {
        RiskAcceptance { id, finding_id: finding.into(), asset_id: asset, reason: "behind the firewall".into(), accepted_by: "admin".into(), accepted_at: NOW - 10, expires_at: expires, revoked_at: None, revoked_by: None }
    }

    #[test]
    fn an_accepted_risk_leaves_the_open_list_and_appears_in_the_accepted_one_until_it_expires_or_is_withdrawn() {
        let assets = vec![dev(1, "camera", &[23]), dev(2, "iot", &[23]), dev(3, "printer", &[21])];
        let all = compute(&assets, &HashMap::new(), NOW);
        // device 1's telnet is accepted: the finding stays for device 2, and lists the decision
        let (open, accepted) = apply_acceptances(all.clone(), &[accept(1, "telnet_open", 1, None)], NOW);
        assert_eq!(ids(&open, "telnet_open"), vec![2]);
        assert_eq!(ids(&open, "ftp_open"), vec![3], "other findings are untouched");
        assert_eq!((accepted.len(), accepted[0].asset_id, accepted[0].still_applies, accepted[0].title), (1, 1, true, "Telnet is open"));
        // when every device with the finding is accepted the finding is gone
        let (open, _) = apply_acceptances(all.clone(), &[accept(1, "telnet_open", 1, None), accept(2, "telnet_open", 2, None)], NOW);
        assert!(ids(&open, "telnet_open").is_empty() && open.iter().all(|f| f.id != "telnet_open"));
        // an expired decision no longer counts, and a withdrawn one neither
        let (open, accepted) = apply_acceptances(all.clone(), &[accept(1, "telnet_open", 1, Some(NOW - 1))], NOW);
        assert_eq!((ids(&open, "telnet_open"), accepted.len()), (vec![1, 2], 0));
        let mut withdrawn = accept(1, "telnet_open", 1, None);
        withdrawn.revoked_at = Some(NOW - 5);
        assert_eq!(ids(&apply_acceptances(all.clone(), &[withdrawn], NOW).0, "telnet_open"), vec![1, 2]);
        // a decision for the wrong finding does not hide another one on the same device
        let (open, _) = apply_acceptances(all, &[accept(1, "ftp_open", 1, None)], NOW);
        assert_eq!(ids(&open, "telnet_open"), vec![1, 2]);
        // the problem went away: the decision stays visible, marked as no longer applying
        let fixed = compute(&[dev(1, "camera", &[])], &HashMap::new(), NOW);
        let (_, accepted) = apply_acceptances(fixed, &[accept(1, "telnet_open", 1, None)], NOW);
        assert!(!accepted[0].still_applies);
        // unknown kinds are ignored, known ones are recognised
        assert!(is_known("telnet_open") && !is_known("nope") && is_port_finding("rdp_open") && !is_port_finding("unreviewed"));
    }

    #[test]
    fn whether_a_finding_applies_follows_the_device_as_it_is_now() {
        let mut a = dev(1, "camera", &[23]);
        assert!(applies(&a, None, NOW, "telnet_open"));
        a.open_ports.clear();
        assert!(!applies(&a, None, NOW, "telnet_open"), "the port is closed: fixed");
        assert!(applies(&dev(2, "computer", &[]), None, NOW, "unreviewed"));
    }
}
