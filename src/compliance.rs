//! Coverage and standards mapping: how complete the inventory is, which protective and
//! detective capabilities are switched on, and how that lines up with the controls of
//! CIS Controls v8, NIST CSF, IEC 62443-3-3, NIST SP 800-82 (via its SP 800-53 controls),
//! ISO/IEC 27001 Annex A, NIS2, DORA, PCI DSS v4.0, the HIPAA Security Rule, SOC 2 (Trust
//! Services Criteria) and CMMC 2.0 (via NIST SP 800-171).
//!
//! This is *evidence*, not certification. Each line says what DENIS can show and whether
//! it is currently in place on this installation; whether a control is *satisfied* for an
//! audit is the auditor's call. Percentages are computed from the register as it is now, so
//! they move as people fill it in.
//!
//! The mapping is indicative and intentionally short: only controls where an asset
//! inventory / network monitoring product supplies real evidence, and only identifiers
//! that are well established.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::fingerprint::is_ot_device;
use crate::model::{Asset, AssetMeta};

/// Everything the assessment looks at, gathered by the caller.
pub struct Inputs<'a> {
    pub assets: &'a [Asset],
    pub metas: &'a HashMap<i64, AssetMeta>,
    /// Ever seen within this many seconds counts as "current".
    pub now: i64,
    pub passive_discovery: bool,
    pub active_discovery: bool,
    pub traffic_analysis: bool,
    pub learning_finished: bool,
    pub rules_enabled: usize,
    pub rules_total: usize,
    pub channels_enabled: usize,
    pub exports_configured: usize,
    pub users: usize,
    pub users_with_passkey: usize,
    pub admins: usize,
    pub admins_with_mfa: usize,
    /// Open findings of high severity, and risks people decided to accept.
    pub high_findings: usize,
    pub accepted_risks: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Measure {
    pub label: &'static str,
    /// `0..=100`
    pub percent: u32,
    /// A sentence with `{name}` placeholders (so it can be translated); `vars` fills them.
    pub detail: &'static str,
    pub vars: Vars,
}

/// Values for the `{placeholders}` of a translatable sentence.
pub type Vars = BTreeMap<&'static str, String>;

fn vars<const N: usize>(pairs: [(&'static str, String); N]) -> Vars {
    pairs.into_iter().collect()
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Control {
    /// e.g. "CIS Controls v8 · 1.1"
    pub reference: &'static str,
    pub title: &'static str,
    /// What DENIS provides for it.
    pub evidence: &'static str,
    /// `in_place`, `partial` or `not_in_place`.
    pub status: &'static str,
    /// Why it has that status right now: a sentence with `{name}` placeholders, filled from `vars`.
    pub note: &'static str,
    pub vars: Vars,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Report {
    pub measures: Vec<Measure>,
    pub controls: Vec<Control>,
    pub disclaimer: &'static str,
}

fn pct(n: usize, d: usize) -> u32 {
    // nothing to measure counts as complete
    ((n * 100 + d / 2).checked_div(d).unwrap_or(100)) as u32
}

fn status(percent: u32, full: u32, partial: u32) -> &'static str {
    if percent >= full { "in_place" } else if percent >= partial { "partial" } else { "not_in_place" }
}

fn flag(on: bool) -> &'static str {
    if on { "in_place" } else { "not_in_place" }
}

pub fn assess(i: &Inputs) -> Report {
    let default = AssetMeta::default();
    let meta = |a: &Asset| i.metas.get(&a.id).unwrap_or(&default);
    // devices in use: not retired/spare/lost, and seen in the last month
    let live: Vec<&Asset> = i
        .assets
        .iter()
        .filter(|a| i.now - a.last_seen <= 30 * 86_400 && !matches!(meta(a).status.as_deref(), Some("retired" | "spare" | "lost" | "stolen")))
        .collect();
    let n = live.len();
    let count = |f: &dyn Fn(&Asset, &AssetMeta) -> bool| live.iter().filter(|a| f(a, meta(a))).count();
    let reviewed = count(&|a, m| m.reviewed || m.manual || a.is_self);
    let owned = count(&|_, m| m.owner.is_some());
    let identified = count(&|a, m| m.type_override.as_deref().unwrap_or(&a.device_type) != "unknown");
    let rated = count(&|_, m| m.criticality.is_some());
    let ot: Vec<&&Asset> = live.iter().filter(|a| is_ot_device(a)).collect();
    let ot_leveled = ot.iter().filter(|a| meta(a).purdue_level.is_some()).count();
    let identified_pct = pct(identified, n);
    let reviewed_pct = pct(reviewed, n);
    let owned_pct = pct(owned, n);

    let ratio = |a: usize, b: usize| vars([("a", a.to_string()), ("b", b.to_string())]);
    let measures = vec![
        Measure { label: "Devices reviewed by a person", percent: reviewed_pct, detail: "{a} of {b} devices in use", vars: ratio(reviewed, n) },
        Measure { label: "Devices with a known type", percent: identified_pct, detail: "{a} of {b}", vars: ratio(identified, n) },
        Measure { label: "Devices with an owner", percent: owned_pct, detail: "{a} of {b}", vars: ratio(owned, n) },
        Measure { label: "Devices with a criticality rating", percent: pct(rated, n), detail: "{a} of {b}", vars: ratio(rated, n) },
        Measure {
            label: "Industrial devices with a Purdue level", percent: pct(ot_leveled, ot.len()),
            detail: if ot.is_empty() { "no industrial devices found" } else { "{a} of {b}" }, vars: ratio(ot_leveled, ot.len()),
        },
        Measure { label: "Detection rules switched on", percent: pct(i.rules_enabled, i.rules_total), detail: "{a} of {b}", vars: ratio(i.rules_enabled, i.rules_total) },
        Measure { label: "Administrators with a second sign-in step", percent: pct(i.admins_with_mfa, i.admins), detail: "{a} of {b}", vars: ratio(i.admins_with_mfa, i.admins) },
    ];


    let inventory = (reviewed_pct + identified_pct + owned_pct) / 3;
    let mut controls = vec![
        Control {
            reference: "CIS Controls v8 · 1.1", title: "Establish and maintain a detailed enterprise asset inventory",
            evidence: "Asset register: type, manufacturer, name, owner, location, serial number, criticality, with change history and CSV export.",
            status: status(inventory, 80, 40),
            note: "Reviewed {reviewed}%, type known {known}%, owner recorded {owner}% (average {average}%).",
            vars: vars([("reviewed", reviewed_pct.to_string()), ("known", identified_pct.to_string()), ("owner", owned_pct.to_string()), ("average", inventory.to_string())]),
        },
        Control {
            reference: "CIS Controls v8 · 1.2", title: "Address unauthorized assets",
            evidence: "New-device alerts, the review queue (\"needs review\") and findings for lost or retired devices still on the network.",
            status: status(reviewed_pct, 90, 50),
            note: "{percent}% of devices in use have been reviewed by a person.", vars: vars([("percent", reviewed_pct.to_string())]),
        },
        Control {
            reference: "CIS Controls v8 · 1.5", title: "Use a passive asset discovery tool",
            evidence: "Passive discovery from ARP, DHCP, mDNS, SSDP, LLDP/CDP and industrial protocols.",
            status: flag(i.passive_discovery),
            note: if i.passive_discovery { "Passive listening is on." } else { "The collector is not listening." }, vars: Vars::new(),
        },
        Control {
            reference: "CIS Controls v8 · 13.1", title: "Centralize security event alerting",
            evidence: "Scored alerts with advice, plus delivery to chat, e-mail, PagerDuty, a webhook, syslog/CEF or OpenObserve.",
            status: if i.channels_enabled + i.exports_configured > 0 { "in_place" } else { "partial" },
            note: "{channels} notification channel(s) and {exports} export(s) configured; alerts are always visible in the console.",
            vars: vars([("channels", i.channels_enabled.to_string()), ("exports", i.exports_configured.to_string())]),
        },
        Control {
            reference: "CIS Controls v8 · 13.6", title: "Collect network traffic flow logs",
            evidence: "Per-device flow accounting and baselines of destinations, ports, volume and hours.",
            status: flag(i.traffic_analysis),
            note: if i.traffic_analysis { "Traffic analysis is on (it sees traffic that crosses the monitored interface)." } else { "Start with --flows (or --profile ot) and place the collector where the traffic is." },
            vars: Vars::new(),
        },
        Control {
            reference: "CIS Controls v8 · 6.5", title: "Require MFA for administrative access",
            evidence: "A second sign-in step: a passkey (a verified fingerprint, face, PIN or security key) or a one-time code from an authenticator app.",
            status: if i.admins == 0 { "not_in_place" } else { status(pct(i.admins_with_mfa, i.admins), 100, 1) },
            note: "{a} of {b} administrator(s) use a passkey or an authenticator app. Where a second step is not required (Settings), a password alone still works.", vars: ratio(i.admins_with_mfa, i.admins),
        },
        Control {
            reference: "NIST CSF 2.0 · ID.AM-01", title: "Inventories of hardware managed by the organization are maintained",
            evidence: "As CIS 1.1: the asset register with lifecycle (warranty, status) tracking.",
            status: status(inventory, 80, 40),
            note: "Inventory completeness {percent}%.", vars: vars([("percent", inventory.to_string())]),
        },
        Control {
            reference: "NIST CSF 2.0 · DE.CM-01", title: "Networks and network services are monitored to find potentially adverse events",
            evidence: "Continuous passive and (optionally) active monitoring with learned baselines and explainable rules.",
            status: if i.passive_discovery && i.learning_finished && i.rules_enabled > 0 { "in_place" } else if i.passive_discovery { "partial" } else { "not_in_place" },
            note: if !i.learning_finished { "Still in the learning period: new devices and destinations are learned, not alerted on." } else { "{a} of {b} detection rules are on." },
            vars: ratio(i.rules_enabled, i.rules_total),
        },
        Control {
            reference: "NIST CSF 2.0 · DE.AE-02", title: "Potentially adverse events are analyzed to better understand associated activities",
            evidence: "Each alert lists the factors behind its score and what to do about it.",
            status: flag(i.rules_enabled > 0),
            note: "{n} detection rules are on.", vars: vars([("n", i.rules_enabled.to_string())]),
        },
        Control {
            reference: "IEC 62443-3-3 · SR 5.1", title: "Network segmentation",
            evidence: "Zone and Purdue level per device, and alerts for communication that skips a level or crosses the network boundary.",
            status: if ot.is_empty() { "in_place" } else { status(pct(ot_leveled, ot.len()), 90, 40) },
            note: if ot.is_empty() { "No industrial devices were found, so there is nothing to segment yet." } else { "{a} of {b} industrial devices have a Purdue level entered; the segmentation rules can only judge those." },
            vars: ratio(ot_leveled, ot.len()),
        },
        Control {
            reference: "IEC 62443-3-3 · SR 6.2", title: "Continuous monitoring",
            evidence: "Passive industrial protocol monitoring (Modbus, S7, EtherNet/IP, DNP3, BACnet, OPC UA, IEC 104) with new-path and control-command detection.",
            status: if i.traffic_analysis && i.rules_enabled > 0 { "in_place" } else { "not_in_place" },
            note: if i.traffic_analysis { "Traffic analysis is on." } else { "Industrial monitoring needs --profile ot (or --flows) on a mirror port." }, vars: Vars::new(),
        },
        Control {
            reference: "IEC 62443-3-3 · SR 2.8", title: "Auditable events",
            evidence: "An audit log of every sign-in, change, user, token, channel and rule edit, exportable to a SIEM.",
            status: "in_place",
            note: "The audit log is always on.", vars: Vars::new(),
        },
    ];
    // ---- ISO/IEC 27001:2022 Annex A and NIS2 Article 21(2): the same evidence, in their words
    let inventory_status = status(inventory, 80, 40);
    let vuln_status = if i.high_findings == 0 { "in_place" } else { "partial" };
    let mfa_status = if i.admins == 0 { "not_in_place" } else { status(pct(i.admins_with_mfa, i.admins), 100, 1) };
    let mfa_note = "{a} of {b} administrator(s) use a passkey or an authenticator app. Where a second step is not required (Settings), a password alone still works.";
    let mfa_vars = ratio(i.admins_with_mfa, i.admins);
    let vuln_note = "{a} high-severity finding(s) are open; {b} risk(s) were accepted with a reason.";
    let vuln_vars = ratio(i.high_findings, i.accepted_risks);
    let monitoring_status = if i.passive_discovery && i.learning_finished && i.rules_enabled > 0 { "in_place" } else if i.passive_discovery { "partial" } else { "not_in_place" };
    let inventory_note_vars = vars([("percent", inventory.to_string())]);
    let inventory_note_vars2 = inventory_note_vars.clone();
    let vuln_vars2 = vuln_vars.clone();
    controls.extend([
        Control {
            reference: "ISO/IEC 27001:2022 · A.5.9", title: "Inventory of information and other associated assets",
            evidence: "Asset register with owner, criticality, lifecycle and change history.",
            status: inventory_status, note: "Inventory completeness {percent}%.", vars: inventory_note_vars.clone(),
        },
        Control {
            reference: "ISO/IEC 27001:2022 · A.8.5", title: "Secure authentication",
            evidence: "A second sign-in step: a passkey (a verified fingerprint, face, PIN or security key) or a one-time code from an authenticator app.",
            status: mfa_status, note: mfa_note, vars: mfa_vars.clone(),
        },
        Control {
            reference: "ISO/IEC 27001:2022 · A.8.8", title: "Management of technical vulnerabilities",
            evidence: "Findings for exposed and risky services, each with a fix, confirmed by a fresh scan (Verify fix); accepted risks are recorded with a reason, an owner and an end date.",
            status: vuln_status, note: vuln_note, vars: vuln_vars.clone(),
        },
        Control {
            reference: "ISO/IEC 27001:2022 · A.8.15", title: "Logging",
            evidence: "An audit log of every sign-in, change, user, token, channel and rule edit, exportable to a SIEM.",
            status: "in_place", note: "The audit log is always on.", vars: Vars::new(),
        },
        Control {
            reference: "ISO/IEC 27001:2022 · A.8.16", title: "Monitoring activities",
            evidence: "Continuous passive and (optionally) active monitoring with learned baselines and explainable rules.",
            status: monitoring_status,
            note: if !i.learning_finished { "Still in the learning period: new devices and destinations are learned, not alerted on." } else { "{a} of {b} detection rules are on." },
            vars: ratio(i.rules_enabled, i.rules_total),
        },
        Control {
            reference: "ISO/IEC 27001:2022 · A.8.20", title: "Networks security",
            evidence: "Network discovery and monitoring with alerts for new devices, rogue DHCP servers and ARP conflicts.",
            status: flag(i.passive_discovery && i.rules_enabled > 0), note: "{n} detection rules are on.", vars: vars([("n", i.rules_enabled.to_string())]),
        },
        Control {
            reference: "NIS2 · Article 21(2)(b)", title: "Incident handling",
            evidence: "Scored alerts with advice on what to do, delivery to chat, e-mail, PagerDuty or a SIEM, and an audit trail.",
            status: if i.channels_enabled + i.exports_configured > 0 { "in_place" } else { "partial" },
            note: "{channels} notification channel(s) and {exports} export(s) configured; alerts are always visible in the console.",
            vars: vars([("channels", i.channels_enabled.to_string()), ("exports", i.exports_configured.to_string())]),
        },
        Control {
            reference: "NIS2 · Article 21(2)(e)", title: "Vulnerability handling",
            evidence: "Findings for exposed and risky services, each with a fix, confirmed by a fresh scan (Verify fix); accepted risks are recorded with a reason, an owner and an end date.",
            status: vuln_status, note: vuln_note, vars: vuln_vars,
        },
        Control {
            reference: "NIS2 · Article 21(2)(i)", title: "Asset management",
            evidence: "Asset register with owner, criticality, lifecycle and change history.",
            status: inventory_status, note: "Inventory completeness {percent}%.", vars: inventory_note_vars.clone(),
        },
        // NIST SP 800-82 Rev. 3 (guide to OT security) points to these NIST SP 800-53 controls
        Control {
            reference: "NIST SP 800-82 Rev. 3 · CM-8", title: "System component inventory",
            evidence: "Asset register with owner, criticality, lifecycle and change history.",
            status: inventory_status, note: "Inventory completeness {percent}%.", vars: inventory_note_vars2,
        },
        Control {
            reference: "NIST SP 800-82 Rev. 3 · SC-7", title: "Boundary protection",
            evidence: "Zone and Purdue level per device, and alerts for communication that skips a level or crosses the network boundary.",
            status: if ot.is_empty() { "in_place" } else { status(pct(ot_leveled, ot.len()), 90, 40) },
            note: if ot.is_empty() { "No industrial devices were found, so there is nothing to segment yet." } else { "{a} of {b} industrial devices have a Purdue level entered; the segmentation rules can only judge those." },
            vars: ratio(ot_leveled, ot.len()),
        },
        Control {
            reference: "NIST SP 800-82 Rev. 3 · SI-4", title: "System monitoring",
            evidence: "Passive industrial protocol monitoring (Modbus, S7, EtherNet/IP, DNP3, BACnet, OPC UA, IEC 104) with new-path and control-command detection.",
            status: if i.traffic_analysis && i.rules_enabled > 0 { "in_place" } else { "not_in_place" },
            note: if i.traffic_analysis { "Traffic analysis is on." } else { "Industrial monitoring needs --profile ot (or --flows) on a mirror port." }, vars: Vars::new(),
        },
        Control {
            reference: "NIST SP 800-82 Rev. 3 · RA-5", title: "Vulnerability monitoring and scanning",
            evidence: "Findings for exposed and risky services, each with a fix, confirmed by a fresh scan (Verify fix); accepted risks are recorded with a reason, an owner and an end date.",
            status: vuln_status, note: vuln_note, vars: vuln_vars2,
        },
        Control {
            reference: "NIST SP 800-82 Rev. 3 · AU-2", title: "Event logging",
            evidence: "An audit log of every sign-in, change, user, token, channel and rule edit, exportable to a SIEM.",
            status: "in_place", note: "The audit log is always on.", vars: Vars::new(),
        },
        Control {
            reference: "NIS2 · Article 21(2)(j)", title: "Multi-factor authentication",
            evidence: "A second sign-in step: a passkey (a verified fingerprint, face, PIN or security key) or a one-time code from an authenticator app.",
            status: mfa_status, note: mfa_note, vars: mfa_vars.clone(),
        },
        // ---- DORA (Regulation (EU) 2022/2554), PCI DSS v4.0, HIPAA Security Rule, SOC 2 and
        // CMMC 2.0 (Level 2 / NIST SP 800-171): the same evidence again, in their own words.
        Control {
            reference: "DORA · Article 8(1)", title: "Identification of ICT assets",
            evidence: "Asset register with owner, criticality, lifecycle and change history, covering both IT and OT.",
            status: inventory_status, note: "Inventory completeness {percent}%.", vars: inventory_note_vars.clone(),
        },
        Control {
            reference: "DORA · Article 10(1)", title: "Prompt detection of anomalous activities",
            evidence: "Continuous passive and (optionally) active monitoring with learned baselines and explainable rules.",
            status: monitoring_status,
            note: if !i.learning_finished { "Still in the learning period: new devices and destinations are learned, not alerted on." } else { "{a} of {b} detection rules are on." },
            vars: ratio(i.rules_enabled, i.rules_total),
        },
        Control {
            reference: "DORA · Article 17(1)", title: "ICT-related incident management",
            evidence: "Scored alerts with advice on what to do, delivery to chat, e-mail, PagerDuty or a SIEM, and an audit trail.",
            status: if i.channels_enabled + i.exports_configured > 0 { "in_place" } else { "partial" },
            note: "{channels} notification channel(s) and {exports} export(s) configured; alerts are always visible in the console.",
            vars: vars([("channels", i.channels_enabled.to_string()), ("exports", i.exports_configured.to_string())]),
        },
        Control {
            reference: "PCI DSS v4.0 · 12.5.1", title: "Inventory of system components in scope",
            evidence: "Asset register with owner, criticality, lifecycle and change history.",
            status: inventory_status, note: "Inventory completeness {percent}%.", vars: inventory_note_vars.clone(),
        },
        Control {
            reference: "PCI DSS v4.0 · 11.5.1", title: "Network intrusion detection",
            evidence: "Continuous passive and (optionally) active monitoring with learned baselines and explainable rules.",
            status: monitoring_status,
            note: if !i.learning_finished { "Still in the learning period: new devices and destinations are learned, not alerted on." } else { "{a} of {b} detection rules are on." },
            vars: ratio(i.rules_enabled, i.rules_total),
        },
        Control {
            reference: "PCI DSS v4.0 · 8.4.2", title: "Multi-factor authentication into the CDE",
            evidence: "A second sign-in step: a passkey (a verified fingerprint, face, PIN or security key) or a one-time code from an authenticator app.",
            status: mfa_status, note: mfa_note, vars: mfa_vars.clone(),
        },
        Control {
            reference: "HIPAA Security Rule · §164.308(a)(1)(ii)(A)", title: "Risk analysis",
            evidence: "Asset register and findings for exposed and risky services feed the risk analysis with concrete, current evidence.",
            status: inventory_status, note: "Inventory completeness {percent}%.", vars: inventory_note_vars.clone(),
        },
        Control {
            reference: "HIPAA Security Rule · §164.312(b)", title: "Audit controls",
            evidence: "An audit log of every sign-in, change, user, token, channel and rule edit, exportable to a SIEM.",
            status: "in_place", note: "The audit log is always on.", vars: Vars::new(),
        },
        Control {
            reference: "HIPAA Security Rule · §164.312(d)", title: "Person or entity authentication",
            evidence: "A second sign-in step: a passkey (a verified fingerprint, face, PIN or security key) or a one-time code from an authenticator app.",
            status: mfa_status, note: mfa_note, vars: mfa_vars.clone(),
        },
        Control {
            reference: "SOC 2 · CC7.1", title: "Detects and monitors changes to infrastructure",
            evidence: "Asset register with owner, criticality, lifecycle and change history.",
            status: inventory_status, note: "Inventory completeness {percent}%.", vars: inventory_note_vars.clone(),
        },
        Control {
            reference: "SOC 2 · CC7.2", title: "Monitors system components for anomalies",
            evidence: "Continuous passive and (optionally) active monitoring with learned baselines and explainable rules.",
            status: monitoring_status,
            note: if !i.learning_finished { "Still in the learning period: new devices and destinations are learned, not alerted on." } else { "{a} of {b} detection rules are on." },
            vars: ratio(i.rules_enabled, i.rules_total),
        },
        Control {
            reference: "SOC 2 · CC6.1", title: "Logical access security",
            evidence: "A second sign-in step: a passkey (a verified fingerprint, face, PIN or security key) or a one-time code from an authenticator app.",
            status: mfa_status, note: mfa_note, vars: mfa_vars.clone(),
        },
        Control {
            reference: "CMMC 2.0 · CM.L2-3.4.1", title: "Baseline configurations and system inventories",
            evidence: "Asset register with owner, criticality, lifecycle and change history.",
            status: inventory_status, note: "Inventory completeness {percent}%.", vars: inventory_note_vars,
        },
        Control {
            reference: "CMMC 2.0 · SI.L2-3.14.6", title: "Monitor systems to detect attacks",
            evidence: "Continuous passive and (optionally) active monitoring with learned baselines and explainable rules.",
            status: monitoring_status,
            note: if !i.learning_finished { "Still in the learning period: new devices and destinations are learned, not alerted on." } else { "{a} of {b} detection rules are on." },
            vars: ratio(i.rules_enabled, i.rules_total),
        },
        Control {
            reference: "CMMC 2.0 · IA.L2-3.5.3", title: "Multi-factor authentication for privileged accounts",
            evidence: "A second sign-in step: a passkey (a verified fingerprint, face, PIN or security key) or a one-time code from an authenticator app.",
            status: mfa_status, note: mfa_note, vars: mfa_vars,
        },
        Control {
            reference: "CMMC 2.0 · AU.L2-3.3.1", title: "Create and retain system audit logs",
            evidence: "An audit log of every sign-in, change, user, token, channel and rule edit, exportable to a SIEM.",
            status: "in_place", note: "The audit log is always on.", vars: Vars::new(),
        },
    ]);
    if i.active_discovery {
        controls.push(Control {
            reference: "CIS Controls v8 · 1.3", title: "Utilize an active discovery tool",
            evidence: "Polite ARP sweep, ping and light port scan (never used on industrial devices).",
            status: "in_place",
            note: "Active discovery is on.", vars: Vars::new(),
        });
    }
    Report { measures, controls, disclaimer: "Evidence to support your own assessment, not a certification. Whether a control is satisfied is for you and your auditor to decide." }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Mac;

    const NOW: i64 = 1_800_000_000;

    fn dev(id: i64, ty: &str) -> Asset {
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, id as u8]), 1);
        a.id = id;
        a.device_type = ty.into();
        a.last_seen = NOW - 100;
        a
    }

    fn inputs<'a>(assets: &'a [Asset], metas: &'a HashMap<i64, AssetMeta>) -> Inputs<'a> {
        Inputs {
            assets, metas, now: NOW, passive_discovery: true, active_discovery: false, traffic_analysis: false, learning_finished: true,
            rules_enabled: 10, rules_total: 15, channels_enabled: 0, exports_configured: 0, users: 2, users_with_passkey: 0, admins: 1, admins_with_mfa: 0, high_findings: 0, accepted_risks: 0,
        }
    }

    fn status_of<'a>(r: &'a Report, reference: &str) -> &'a str {
        r.controls.iter().find(|c| c.reference.ends_with(reference)).unwrap_or_else(|| panic!("{reference}")).status
    }

    fn measure<'a>(r: &'a Report, label: &str) -> &'a Measure {
        r.measures.iter().find(|m| m.label.contains(label)).unwrap()
    }

    #[test]
    fn a_fresh_install_shows_low_completeness_and_no_false_comfort() {
        let assets: Vec<Asset> = (1..=4).map(|i| dev(i, if i == 1 { "unknown" } else { "computer" })).collect();
        let metas = HashMap::new();
        let r = assess(&inputs(&assets, &metas));
        assert_eq!(measure(&r, "reviewed").percent, 0);
        assert_eq!(measure(&r, "known type").percent, 75);
        assert_eq!(status_of(&r, "1.2"), "not_in_place");
        assert_eq!(status_of(&r, "1.1"), "not_in_place");
        assert_eq!(status_of(&r, "6.5"), "not_in_place", "no passkeys yet");
        assert_eq!(status_of(&r, "13.6"), "not_in_place", "no traffic analysis");
        assert_eq!(status_of(&r, "1.5"), "in_place");
        assert_eq!(status_of(&r, "13.1"), "partial", "alerts only in the console");
        assert_eq!(status_of(&r, "SR 2.8"), "in_place");
        assert!(r.controls.iter().all(|c| !c.note.is_empty() && !c.evidence.is_empty()));
        assert!(r.disclaimer.contains("not a certification"));
    }

    #[test]
    fn filling_in_the_register_and_switching_features_on_moves_the_statuses() {
        let assets: Vec<Asset> = (1..=4).map(|i| dev(i, "computer")).collect();
        let metas: HashMap<i64, AssetMeta> = (1..=4).map(|i| (i, AssetMeta { reviewed: true, owner: Some("Ops".into()), criticality: Some("normal".into()), ..Default::default() })).collect();
        let mut i = inputs(&assets, &metas);
        i.traffic_analysis = true;
        i.channels_enabled = 1;
        i.admins_with_mfa = 1;
        i.active_discovery = true;
        let r = assess(&i);
        for c in ["1.1", "1.2", "13.1", "13.6", "6.5", "ID.AM-01", "DE.CM-01", "SR 6.2", "1.3"] {
            assert_eq!(status_of(&r, c), "in_place", "{c}");
        }
        assert_eq!(measure(&r, "owner").percent, 100);
        // still learning: monitoring is only partly in place
        i.learning_finished = false;
        assert_eq!(status_of(&assess(&i), "DE.CM-01"), "partial");
    }

    #[test]
    fn iso_27001_and_nis2_reuse_the_same_evidence_and_follow_findings_and_passkeys() {
        let assets: Vec<Asset> = (1..=2).map(|i| dev(i, "computer")).collect();
        let metas = HashMap::new();
        let mut i = inputs(&assets, &metas);
        i.high_findings = 2;
        i.accepted_risks = 1;
        let r = assess(&i);
        for c in ["A.8.8", "Article 21(2)(e)"] {
            assert_eq!(status_of(&r, c), "partial", "{c}: high findings are open");
        }
        assert_eq!(status_of(&r, "A.8.5"), "not_in_place");
        assert_eq!(status_of(&r, "Article 21(2)(j)"), "not_in_place");
        assert_eq!(status_of(&r, "A.8.15"), "in_place");
        i.high_findings = 0;
        i.admins_with_mfa = i.admins;
        let r = assess(&i);
        for c in ["A.8.8", "Article 21(2)(e)", "A.8.5", "Article 21(2)(j)"] {
            assert_eq!(status_of(&r, c), "in_place", "{c}");
        }
        assert_eq!(status_of(&r, "Article 21(2)(b)"), "partial", "no channel or export yet");
        assert_eq!(status_of(&r, "CM-8"), status_of(&r, "A.5.9"), "same evidence, same status");
        assert_eq!(status_of(&r, "RA-5"), "in_place");
        assert_eq!(status_of(&r, "SI-4"), "not_in_place", "no traffic analysis");
    }

    #[test]
    fn dora_pci_hipaa_soc2_and_cmmc_reuse_the_same_evidence_as_the_others() {
        let assets: Vec<Asset> = (1..=2).map(|i| dev(i, "computer")).collect();
        let metas: HashMap<i64, AssetMeta> = (1..=2).map(|i| (i, AssetMeta { reviewed: true, owner: Some("Ops".into()), criticality: Some("normal".into()), ..Default::default() })).collect();
        let mut i = inputs(&assets, &metas);
        i.traffic_analysis = true;
        i.admins_with_mfa = 1;
        let r = assess(&i);
        for c in ["DORA · Article 8(1)", "PCI DSS v4.0 · 12.5.1", "HIPAA Security Rule · §164.308(a)(1)(ii)(A)", "SOC 2 · CC7.1", "CMMC 2.0 · CM.L2-3.4.1"] {
            assert_eq!(status_of(&r, c), "in_place", "{c}: same inventory evidence as CIS 1.1");
        }
        for c in ["DORA · Article 10(1)", "PCI DSS v4.0 · 11.5.1", "SOC 2 · CC7.2", "CMMC 2.0 · SI.L2-3.14.6"] {
            assert_eq!(status_of(&r, c), "in_place", "{c}: same monitoring evidence as NIS2 21(2)(b)/DE.CM-01");
        }
        for c in ["PCI DSS v4.0 · 8.4.2", "HIPAA Security Rule · §164.312(d)", "SOC 2 · CC6.1", "CMMC 2.0 · IA.L2-3.5.3"] {
            assert_eq!(status_of(&r, c), "in_place", "{c}: same MFA evidence as CIS 6.5");
        }
        for c in ["HIPAA Security Rule · §164.312(b)", "CMMC 2.0 · AU.L2-3.3.1"] {
            assert_eq!(status_of(&r, c), "in_place", "{c}: the audit log is always on");
        }
        // no admins with MFA yet: the new frameworks' MFA controls move too, not just NIS2's
        i.admins_with_mfa = 0;
        let r = assess(&i);
        assert_eq!(status_of(&r, "PCI DSS v4.0 · 8.4.2"), "not_in_place");
    }

    #[test]
    fn retired_and_long_gone_devices_do_not_count_and_industrial_levels_are_measured_separately() {
        let mut assets: Vec<Asset> = vec![dev(1, "plc"), dev(2, "plc"), dev(3, "computer"), dev(4, "computer")];
        assets[3].last_seen = NOW - 90 * 86_400; // gone
        let mut metas = HashMap::new();
        metas.insert(1, AssetMeta { purdue_level: Some("1".into()), reviewed: true, ..Default::default() });
        metas.insert(3, AssetMeta { status: Some("retired".into()), ..Default::default() });
        let r = assess(&inputs(&assets, &metas));
        assert_eq!(measure(&r, "reviewed").detail, "{a} of {b} devices in use");
        assert_eq!(measure(&r, "reviewed").vars["a"], "1");
        assert_eq!(measure(&r, "reviewed").vars["b"], "2");
        assert_eq!((measure(&r, "Purdue").percent, measure(&r, "Purdue").vars["a"].as_str()), (50, "1"));
        assert_eq!(status_of(&r, "SR 5.1"), "partial");
        // no industrial devices: segmentation is trivially fine, and the measure says so
        let it = vec![dev(1, "computer")];
        let r = assess(&inputs(&it, &HashMap::new()));
        assert_eq!(status_of(&r, "SR 5.1"), "in_place");
        assert!(measure(&r, "Purdue").detail.contains("no industrial"));
        // nothing at all: no division by zero
        let r = assess(&inputs(&[], &HashMap::new()));
        assert!(r.measures.iter().all(|m| m.percent <= 100));
    }
}
