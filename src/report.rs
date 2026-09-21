//! Exports and the printable report.
//!
//! Everything here renders strings that came off the network (hostnames, mDNS
//! names, vendor strings). CSV cells are neutralised against spreadsheet
//! formula injection and HTML is escaped; both are tested.

use std::collections::HashMap;

use anyhow::Result;

use crate::branding::{self, Branding};
use crate::model::{AgentInfo, Asset, AssetMeta, Event};
use crate::risk::{self, Risk};
use crate::store::{EventQuery, Store};
use crate::trends::{self, Point};

pub struct DeviceRow {
    /// With manual overrides (type, OS, manufacturer) already applied.
    pub asset: Asset,
    /// Everything entered by hand: owner, serial number, warranty...
    pub meta: AssetMeta,
    pub risk: Risk,
}

pub struct ReportData {
    /// Whose report this is (white-label name, accent colour).
    pub brand: Branding,
    /// The logo as a `data:` URI, so the report stays one self-contained file.
    pub logo: Option<String>,
    pub generated_at: i64,
    pub days: i64,
    /// Highest risk first.
    pub devices: Vec<DeviceRow>,
    /// Alerts raised within the period, newest first.
    pub alerts: Vec<Event>,
    pub agents: Vec<AgentInfo>,
    /// Standing problems and what to do about them.
    pub findings: Vec<crate::findings::Finding>,
    /// Risks people decided to accept, with who and why (an auditor asks for exactly this).
    pub accepted: Vec<crate::findings::AcceptedRisk>,
    pub points: Vec<Point>,
    pub step_secs: i64,
}

pub fn gather(store: &dyn Store, days: i64, now: i64) -> Result<ReportData> {
    let days = days.clamp(1, 365);
    let since = now - days * 86_400;
    let assets = store.load_assets()?;
    let mut metas = store.load_all_meta()?;
    let all_alerts = store.list_events(&EventQuery { limit: 5000, alerts_only: true, ..Default::default() })?;

    let mut per_asset: HashMap<i64, Vec<&Event>> = HashMap::new();
    for e in &all_alerts {
        per_asset.entry(e.asset_id).or_default().push(e);
    }
    let mut devices: Vec<DeviceRow> = assets
        .into_iter()
        .map(|mut a| {
            let meta = metas.remove(&a.id).unwrap_or_default();
            crate::tracking::apply_overrides(&mut a, &meta);
            let r = risk::assess_with(&a, per_asset.get(&a.id).map_or(&[][..], |v| v.as_slice()), now, meta.criticality.as_deref());
            DeviceRow { asset: a, meta, risk: r }
        })
        .collect();
    devices.sort_by(|x, y| {
        y.risk.score.cmp(&x.risk.score).then(y.asset.last_seen.cmp(&x.asset.last_seen))
    });

    let (findings, accepted) = {
        let assets: Vec<Asset> = devices.iter().map(|d| d.asset.clone()).collect();
        let metas = devices.iter().map(|d| (d.asset.id, d.meta.clone())).collect();
        crate::findings::apply_acceptances(crate::findings::compute(&assets, &metas, now), &store.list_risk_acceptances()?, now)
    };
    let alerts: Vec<Event> = all_alerts.into_iter().filter(|e| e.timestamp >= since).collect();
    let (points, step_secs) = trends::downsample(&store.list_metrics(since, now + 1, None)?, 168);
    let brand = branding::load(store)?;
    let logo = branding::load_logo(store)?.map(|(t, b)| format!("data:{t};base64,{}", base64(&b)));
    Ok(ReportData {
        brand,
        logo,
        generated_at: now,
        days,
        devices,
        alerts,
        agents: store.list_agents()?,
        findings,
        accepted,
        points,
        step_secs,
    })
}

/// Standard base64 (RFC 4648) with padding; small enough not to need a crate.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

// ------------------------------------------------------------------ time

/// Unix seconds -> `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, no time-zone data needed).
pub fn iso(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

fn minute(ts: i64) -> String {
    iso(ts)[..16].replace('T', " ") + " UTC"
}

// ------------------------------------------------------------------- csv

/// One CSV field. Cells starting with `= + - @` (or a tab/CR) are executed as
/// formulas by spreadsheet software, and hostnames are attacker-controlled, so
/// they get a leading apostrophe.
pub fn csv_cell(s: &str) -> String {
    let mut v = s.to_string();
    if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        v.insert(0, '\'');
    }
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

fn row(cells: &[String]) -> String {
    let mut s = cells.join(",");
    s.push_str("\r\n");
    s
}

/// Discovered name only; `DeviceRow::name` prefers a manual one.
fn display_name(a: &Asset) -> String {
    a.hostnames
        .iter()
        .chain(a.fingerprint.mdns_names.iter())
        .find(|h| !is_uuid(h))
        .cloned()
        .unwrap_or_default()
}

/// Machine-generated names (a UUID, or 32 hex digits) that a person would not recognise.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() == 36 && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')) || (b.len() == 32 && b.iter().all(u8::is_ascii_hexdigit))
}

impl DeviceRow {
    /// The name to show: the manual one, else what discovery found.
    pub fn name(&self) -> String {
        self.meta.display_name.clone().unwrap_or_else(|| display_name(&self.asset))
    }
}

fn site(agent_id: &Option<String>, agents: &[AgentInfo]) -> String {
    match agent_id {
        None => "local".into(),
        Some(id) => agents.iter().find(|a| &a.id == id).map_or(id.clone(), |a| a.name.clone()),
    }
}

/// Editable columns, in export order. The same names are accepted by the CSV
/// import (`tracking::parse_import`), so an export can be edited in a
/// spreadsheet and re-imported.
const META_COLUMNS: &[&str] = &[
    "display_name", "asset_tag", "serial_number", "model", "manufacturer", "type_override", "os_override", "owner",
    "department", "location", "supplier", "purchase_date", "purchase_price", "warranty_expires", "status",
    "criticality", "icon", "zone", "purdue_level", "notes",
];

pub fn assets_csv(data: &ReportData) -> String {
    let custom = crate::tracking::custom_columns(&data.devices.iter().map(|d| &d.meta).collect::<Vec<_>>());
    let mut head: Vec<String> = ["mac", "ip", "name", "vendor", "device_type", "os_guess", "open_ports", "risk_score", "risk_level", "site", "first_seen", "last_seen", "private_mac", "gateway", "warranty"]
        .map(String::from)
        .to_vec();
    head.extend(META_COLUMNS.iter().map(|c| c.to_string()));
    head.push("tags".into());
    head.extend(custom.iter().map(|c| format!("custom.{c}")));
    let mut out = row(&head);
    for d in &data.devices {
        let a = &d.asset;
        let mut cells = vec![
            csv_cell(&a.mac.to_string()),
            csv_cell(&a.current_ip().map(|i| i.to_string()).unwrap_or_default()),
            csv_cell(&d.name()),
            csv_cell(a.vendor.as_deref().unwrap_or("")),
            csv_cell(&a.device_type),
            csv_cell(a.os_guess.as_deref().unwrap_or("")),
            csv_cell(&a.open_ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(" ")),
            d.risk.score.to_string(),
            d.risk.level.to_string(),
            csv_cell(&site(&a.agent_id, &data.agents)),
            iso(a.first_seen),
            if a.last_seen > 0 { iso(a.last_seen) } else { String::new() },
            a.randomized_mac.to_string(),
            a.is_gateway.to_string(),
            crate::tracking::warranty_state(&d.meta, data.generated_at).map(|(s, _)| s.to_string()).unwrap_or_default(),
        ];
        for c in META_COLUMNS {
            cells.push(csv_cell(&crate::tracking::get_field(&d.meta, c).unwrap_or_default()));
        }
        cells.push(csv_cell(&d.meta.tags.join("; ")));
        for c in &custom {
            cells.push(csv_cell(d.meta.custom.get(c).map_or("", String::as_str)));
        }
        out.push_str(&row(&cells));
    }
    out
}

pub fn alerts_csv(data: &ReportData) -> String {
    let by_id: HashMap<i64, &Asset> = data.devices.iter().map(|d| (d.asset.id, &d.asset)).collect();
    let by_id_name: HashMap<i64, String> = data.devices.iter().map(|d| (d.asset.id, d.name())).collect();
    let mut out = row(
        &["time", "severity", "score", "type", "device_mac", "device_ip", "device_name", "site", "summary", "reasons", "acknowledged"]
            .map(String::from),
    );
    for e in &data.alerts {
        let a = by_id.get(&e.asset_id);
        let reasons = e.raw_details["reasons"]
            .as_array()
            .map(|r| r.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" | "))
            .unwrap_or_default();
        out.push_str(&row(&[
            iso(e.timestamp),
            e.severity.clone(),
            e.score.to_string(),
            csv_cell(&e.kind),
            csv_cell(&a.map(|a| a.mac.to_string()).unwrap_or_default()),
            csv_cell(&a.and_then(|a| a.current_ip()).map(|i| i.to_string()).unwrap_or_default()),
            csv_cell(&by_id_name.get(&e.asset_id).cloned().unwrap_or_default()),
            csv_cell(&site(&e.agent_id, &data.agents)),
            csv_cell(e.raw_details["summary"].as_str().unwrap_or("")),
            csv_cell(&reasons),
            e.acked.to_string(),
        ]));
    }
    out
}

// ------------------------------------------------------------------ html

pub fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn sparkline(values: &[f64], color: &str) -> String {
    const W: f64 = 300.0;
    const H: f64 = 44.0;
    if values.len() < 2 {
        return "<span class=\"muted\">not enough history yet</span>".into();
    }
    let max = values.iter().cloned().fold(0.0, f64::max).max(1.0);
    let pts: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(i, v)| format!("{:.1},{:.1}", i as f64 * W / (values.len() - 1) as f64, H - 2.0 - v / max * (H - 4.0)))
        .collect();
    format!(
        "<svg viewBox=\"0 0 {W} {H}\" width=\"{W}\" height=\"{H}\" role=\"img\"><polyline fill=\"none\" stroke=\"{color}\" stroke-width=\"1.6\" points=\"{}\"/></svg>",
        pts.join(" ")
    )
}

fn mb(b: i64) -> String {
    if b >= 1_000_000_000 { format!("{:.1} GB", b as f64 / 1e9) } else { format!("{:.1} MB", b as f64 / 1e6) }
}

const CSS: &str = "body{font:14px/1.45 system-ui,-apple-system,sans-serif;color:#1b1f24;margin:32px auto;max-width:1000px;padding:0 20px}\
h1{margin:0 0 4px}h2{margin:28px 0 8px;font-size:16px;border-bottom:1px solid #d8dce1;padding-bottom:4px}\
.muted{color:#6a737d}.cards{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}\
.card{border:1px solid #d8dce1;border-radius:8px;padding:10px 14px;min-width:120px}.card b{display:block;font-size:22px}\
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #e6e9ed;vertical-align:top}\
th{color:#6a737d;font-weight:600}.sev{display:inline-block;padding:0 7px;border-radius:9px;font-weight:600;font-size:11px;text-transform:uppercase}\
.high{background:#fde2e2;color:#b91c1c}.medium{background:#fdecc8;color:#92400e}.low{background:#dbeafe;color:#1e40af}.none,.info{background:#eceff2;color:#59636e}\
.why{color:#6a737d;font-size:11.5px}.mono{font-family:ui-monospace,Menlo,monospace}\
@media print{body{margin:0;max-width:none}h2{break-after:avoid}tr{break-inside:avoid}}";

pub fn html(data: &ReportData) -> String {
    let now = data.generated_at;
    // Colours were validated as #rrggbb when stored; check again before they
    // are written into a stylesheet.
    let accent = data.brand.accent.as_deref().and_then(branding::valid_color).unwrap_or_else(|| "#1b1f24".into());
    let seen_1h = data.devices.iter().filter(|d| now - d.asset.last_seen <= 3600).count();
    let count = |sev: &str| data.alerts.iter().filter(|e| e.severity == sev).count();
    let unacked = data.alerts.iter().filter(|e| !e.acked).count();
    let high_risk = data.devices.iter().filter(|d| d.risk.level == "high").count();
    let out_total: i64 = data.points.iter().map(|p| p.bytes_out).sum();

    let mut h = String::new();
    h.push_str(&format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Network report</title><style>{CSS}h1,h2{{color:{accent}}}h2{{border-bottom-color:{accent}}}.brandbar{{display:flex;align-items:center;gap:12px;margin-bottom:6px}}.brandbar img{{max-height:44px;max-width:180px}}</style></head><body>"
    ));
    h.push_str("<div class=\"brandbar\">");
    if let Some(logo) = &data.logo {
        h.push_str(&format!("<img alt=\"\" src=\"{}\">", esc(logo)));
    }
    h.push_str(&format!("<b>{}</b></div>", esc(&data.brand.product_name)));
    h.push_str(&format!(
        "<h1>Network report</h1><div class=\"muted\">Last {} day(s) &middot; generated {}</div>",
        data.days,
        esc(&minute(now)),
    ));
    h.push_str("<div class=\"cards\">");
    for (n, label) in [
        (data.devices.len().to_string(), "devices known"),
        (seen_1h.to_string(), "seen in the last hour"),
        (high_risk.to_string(), "high-risk devices"),
        (data.alerts.len().to_string(), "alerts in period"),
        (unacked.to_string(), "unacknowledged"),
        (data.agents.len().to_string(), "remote sites"),
    ] {
        h.push_str(&format!("<div class=\"card\"><b>{n}</b>{label}</div>"));
    }
    h.push_str("</div>");
    h.push_str(&format!(
        "<div class=\"muted\">Alerts by severity: <span class=\"sev high\">high</span> {} <span class=\"sev medium\">medium</span> {} <span class=\"sev low\">low</span> {}</div>",
        count("high"), count("medium"), count("low")
    ));

    if !data.findings.is_empty() {
        h.push_str("<h2>Findings: what to fix</h2><table><tr><th>Severity</th><th>Finding</th><th>What to do</th><th>Devices</th></tr>");
        for f in &data.findings {
            let names: Vec<String> = f
                .assets
                .iter()
                .take(8)
                .map(|id| {
                    data.devices.iter().find(|d| d.asset.id == *id).map_or(format!("#{id}"), |d| d.name())
                })
                .collect();
            let more = f.assets.len().saturating_sub(8);
            h.push_str(&format!(
                "<tr><td><span class=\"sev {}\">{}</span></td><td><b>{}</b><div class=\"muted\">{}</div></td><td>{}</td><td>{}{}</td></tr>",
                if f.severity == "info" { "low" } else { f.severity }, f.severity, esc(f.title), esc(f.why), esc(f.fix),
                esc(&names.join(", ")), if more > 0 { format!(" and {more} more") } else { String::new() }
            ));
        }
        h.push_str("</table>");
    }

    if !data.accepted.is_empty() {
        h.push_str("<h2>Accepted risks</h2><table><tr><th>Finding</th><th>Device</th><th>Reason</th><th>Accepted by</th><th>Until</th></tr>");
        for r in &data.accepted {
            let device = data.devices.iter().find(|d| d.asset.id == r.asset_id).map_or(format!("#{}", r.asset_id), |d| d.name());
            let until = r.expires_at.map_or("withdrawn by hand only".to_string(), |t| iso(t)[..10].to_string());
            h.push_str(&format!(
                "<tr><td><b>{}</b>{}</td><td>{}</td><td>{}</td><td>{} on {}</td><td>{}</td></tr>",
                esc(r.title), if r.still_applies { "" } else { "<div class=\"muted\">no longer applies</div>" }, esc(&device), esc(&r.reason),
                esc(&r.accepted_by), &iso(r.accepted_at)[..10], until
            ));
        }
        h.push_str("</table>");
    }

    h.push_str("<h2>Trends</h2><table><tr><th>Devices online</th><th>Traffic sent outside</th></tr><tr><td>");
    h.push_str(&sparkline(&data.points.iter().map(|p| p.devices_online as f64).collect::<Vec<_>>(), "#2563eb"));
    h.push_str("</td><td>");
    h.push_str(&sparkline(&data.points.iter().map(|p| p.bytes_out as f64).collect::<Vec<_>>(), "#b45309"));
    h.push_str(&format!("<div class=\"muted\">{} in the period</div></td></tr></table>", mb(out_total)));

    h.push_str("<h2>Devices by risk</h2><table><tr><th>Risk</th><th>IP</th><th>Name / vendor</th><th>Type</th><th>Site</th><th>Open ports</th><th>Why</th></tr>");
    for d in data.devices.iter().take(200) {
        let a = &d.asset;
        let m = &d.meta;
        // Inventory details entered by hand, on one muted line.
        let inv: Vec<String> = [
            m.asset_tag.as_ref().map(|v| format!("tag {v}")),
            m.serial_number.as_ref().map(|v| format!("S/N {v}")),
            m.owner.as_ref().map(|v| format!("owner {v}")),
            m.location.as_ref().map(|v| format!("at {v}")),
            m.zone.as_ref().map(|v| format!("zone {v}")),
            m.purdue_level.as_ref().map(|v| format!("Purdue L{v}")),
        ]
        .into_iter()
        .flatten()
        .collect();
        h.push_str(&format!(
            "<tr><td><span class=\"sev {}\">{}</span> {}</td><td class=\"mono\">{}</td><td>{}<div class=\"why\">{}</div><div class=\"why\">{}</div></td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"why\">{}</td></tr>",
            d.risk.level, d.risk.level, d.risk.score,
            esc(&a.current_ip().map(|i| i.to_string()).unwrap_or_default()),
            esc(&d.name()),
            esc(a.vendor.as_deref().unwrap_or(if a.randomized_mac { "private MAC" } else { "" })),
            esc(&inv.join(" · ")),
            esc(&format!("{}{}", a.device_type, a.os_guess.as_ref().map(|o| format!(" / {o}")).unwrap_or_default())),
            esc(&site(&a.agent_id, &data.agents)),
            esc(&a.open_ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(" ")),
            esc(&d.risk.factors.join("; ")),
        ));
    }
    h.push_str("</table>");
    if data.devices.len() > 200 {
        h.push_str(&format!("<p class=\"muted\">{} more devices are in the CSV export.</p>", data.devices.len() - 200));
    }

    h.push_str("<h2>Alerts</h2>");
    if data.alerts.is_empty() {
        h.push_str("<p class=\"muted\">No alerts in this period.</p>");
    } else {
        let by_id: HashMap<i64, &DeviceRow> = data.devices.iter().map(|d| (d.asset.id, d)).collect();
        h.push_str("<table><tr><th>Time</th><th>Severity</th><th>Type</th><th>Device</th><th>What happened</th></tr>");
        for e in data.alerts.iter().take(150) {
            let a = by_id.get(&e.asset_id);
            let reasons = e.raw_details["reasons"].as_array().map(|r| r.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; ")).unwrap_or_default();
            h.push_str(&format!(
                "<tr><td>{}</td><td><span class=\"sev {}\">{}</span> {}</td><td>{}</td><td>{}</td><td>{}{}<div class=\"why\">{}</div></td></tr>",
                esc(&minute(e.timestamp)),
                esc(&e.severity), esc(&e.severity), e.score,
                esc(&e.kind),
                esc(&a.map(|d| format!("{} {}", d.asset.current_ip().map(|i| i.to_string()).unwrap_or_default(), d.name())).unwrap_or_default()),
                esc(e.raw_details["summary"].as_str().unwrap_or("")),
                if e.acked { " (acknowledged)" } else { "" },
                esc(&reasons),
            ));
        }
        h.push_str("</table>");
    }

    // Lifecycle: things a person has to act on (renew, replace, hunt down).
    let lifecycle: Vec<(&DeviceRow, String)> = data
        .devices
        .iter()
        .filter_map(|d| {
            let m = &d.meta;
            match (m.status.as_deref(), crate::tracking::warranty_state(m, now)) {
                (Some("lost" | "stolen"), _) => Some((d, format!("marked {}", m.status.as_deref().unwrap_or("lost")))),
                (_, Some(("expired", n))) => Some((d, format!("warranty expired {} day(s) ago", -n))),
                (_, Some(("expiring", n))) => Some((d, format!("warranty expires in {n} day(s)"))),
                _ => None,
            }
        })
        .collect();
    if !lifecycle.is_empty() {
        h.push_str("<h2>Lifecycle: needs attention</h2><table><tr><th>Device</th><th>Owner</th><th>Serial</th><th>Issue</th></tr>");
        for (d, why) in lifecycle.iter().take(100) {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
                esc(&d.name()),
                esc(d.meta.owner.as_deref().unwrap_or("")),
                esc(d.meta.serial_number.as_deref().unwrap_or("")),
                esc(why)
            ));
        }
        h.push_str("</table>");
    }

    if !data.agents.is_empty() {
        h.push_str("<h2>Sites</h2><table><tr><th>Name</th><th>Site</th><th>Subnet</th><th>Devices</th><th>Last report</th></tr>");
        for g in &data.agents {
            let n = data.devices.iter().filter(|d| d.asset.agent_id.as_deref() == Some(&g.id)).count();
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{n}</td><td>{}</td></tr>",
                esc(&g.name), esc(g.site.as_deref().unwrap_or("")), esc(&g.subnet), esc(&minute(g.last_report_at))
            ));
        }
        h.push_str("</table>");
    }
    h.push_str(&format!(
        "<p class=\"muted\">Prepared by {}. Risk scores and alert scores are heuristics (0&ndash;100) with the contributing factors listed; they indicate where to look first, not proof of compromise. Device types are guesses from passive and active fingerprints.</p></body></html>",
        esc(&data.brand.product_name)
    ));
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IpRecord, Mac, Metric, OpenPort};
    use crate::store::sqlite::SqliteStore;
    use std::net::Ipv4Addr;

    #[test]
    fn iso_matches_known_instants() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z"); // leap day
        assert_eq!(iso(1_789_933_092), "2026-09-20T19:38:12Z");
        assert_eq!(iso(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn csv_cells_are_quoted_and_neutralised_against_formulas() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("line\nbreak"), "\"line\nbreak\"");
        for evil in ["=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd"] {
            let c = csv_cell(evil);
            assert!(c.trim_start_matches('"').starts_with('\''), "{evil:?} -> {c:?}");
        }
        // a formula that also needs quoting keeps both protections
        assert_eq!(csv_cell("=a,b"), "\"'=a,b\"");
    }

    fn saved(store: &SqliteStore, n: u8, name: &str, ports: &[u16], ty: &str) -> Asset {
        let mut a = Asset::new(Mac([0x00, 0x1b, 0x63, 0, 0, n]), 1000);
        a.vendor = Some("Acme".into());
        a.device_type = ty.into();
        a.hostnames = vec![name.into()];
        a.open_ports = ports.iter().map(|p| OpenPort { port: *p, proto: "tcp".into(), service: None }).collect();
        a.ip_history.push(IpRecord { ip: Ipv4Addr::new(10, 0, 0, n), first_seen: 1000, last_seen: 5000 });
        a.last_seen = 5000;
        store.save_asset(&mut a).unwrap();
        a
    }

    fn data() -> (ReportData, Asset) {
        let s = SqliteStore::open_in_memory().unwrap();
        saved(&s, 1, "printer", &[], "printer");
        let evil = saved(&s, 2, "=cmd|' /C calc'!A0<script>alert(1)</script>", &[23], "iot");
        let now = 10 * 86_400;
        for (ts, sev, score) in [(now - 3600, "high", 90), (now - 30 * 86_400, "low", 35), (now - 60, "info", 0)] {
            let mut e = Event {
                id: 0, agent_id: None, asset_id: evil.id, kind: "new_port".into(), timestamp: ts, severity: sev.into(),
                score, acked: false, raw_details: serde_json::json!({"summary": "<b>x</b>", "reasons": ["+40 r1", "+10 r2"]}),
            };
            s.insert_event(&mut e).unwrap();
        }
        s.insert_metrics(&[Metric { ts: now - 600, agent_id: "".into(), devices_total: 2, devices_online: 2, bytes_out: 5_000_000, bytes_in: 1, alerts: 1 },
                           Metric { ts: now - 300, agent_id: "".into(), devices_total: 2, devices_online: 1, bytes_out: 7_000_000, bytes_in: 1, alerts: 0 }]).unwrap();
        (gather(&s, 7, now).unwrap(), evil)
    }

    #[test]
    fn gather_ranks_by_risk_and_filters_alerts_to_the_period() {
        let (d, evil) = data();
        assert_eq!(d.devices[0].asset.id, evil.id, "the risky IoT device is first");
        assert!(d.devices[0].risk.score > d.devices[1].risk.score);
        assert_eq!(d.alerts.len(), 1, "30-day-old alert and info events are excluded");
        assert_eq!(d.alerts[0].score, 90);
        assert_eq!(d.points.len(), 2);
    }

    #[test]
    fn csv_exports_are_safe_and_complete() {
        let (d, _) = data();
        let a = assets_csv(&d);
        let lines: Vec<&str> = a.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("mac,ip,name"));
        // hostile hostname: neutralised, never a bare leading '='
        assert!(a.contains(",'=cmd|"), "{a}");
        assert!(!a.contains(",=cmd"));
        let al = alerts_csv(&d);
        assert_eq!(al.split("\r\n").filter(|l| !l.is_empty()).count(), 2);
        assert!(al.contains("+40 r1 | +10 r2"));
        assert!(al.contains("1970-01-10T")); // ISO timestamps
    }

    #[test]
    fn html_escapes_everything_from_the_network() {
        let (d, _) = data();
        let h = html(&d);
        assert!(!h.contains("<script>alert"), "script tag leaked into the report");
        assert!(h.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!h.contains("<b>x</b>"));
        assert!(h.contains("&lt;b&gt;x&lt;/b&gt;"));
        assert!(h.contains("<title>Network report</title>"));
        assert!(h.contains("high-risk devices"));
        assert!(h.contains("<polyline"), "trend sparkline rendered");
        // no external resources at all: it must be printable/emailable offline
        assert!(!h.contains("http://") && !h.contains("https://") && !h.contains("<script"));
    }

    #[test]
    fn the_report_lists_findings_with_their_fix_and_escapes_device_names() {
        let s = SqliteStore::open_in_memory().unwrap();
        saved(&s, 1, "<i>cam</i>", &[23], "camera");
        let h = html(&gather(&s, 7, 6000).unwrap());
        assert!(h.contains("Findings: what to fix") && h.contains("Telnet is open") && h.contains("Turn Telnet off and use SSH"));
        assert!(h.contains("&lt;i&gt;cam&lt;/i&gt;") && !h.contains("<i>cam</i>"));
        let quiet = SqliteStore::open_in_memory().unwrap();
        let p = saved(&quiet, 1, "printer", &[], "printer");
        quiet.save_meta(p.id, &AssetMeta { reviewed: true, ..Default::default() }, "t", 1).unwrap();
        assert!(!html(&gather(&quiet, 7, 6000).unwrap()).contains("Findings: what to fix"), "no empty section");
    }

    #[test]
    fn manual_information_flows_into_exports_and_the_report() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = saved(&s, 1, "hp-laser", &[], "unknown");
        let now = 1_789_933_092; // 2026-09-20
        let meta = AssetMeta {
            display_name: Some("Reception printer".into()), serial_number: Some("SN-99".into()), owner: Some("Jana".into()),
            type_override: Some("printer".into()), warranty_expires: Some("2026-10-05".into()), criticality: Some("high".into()),
            tags: vec!["floor-1".into(), "leased".into()], custom: [("Cost centre".to_string(), "CC-7".to_string())].into(), ..Default::default()
        };
        s.save_meta(a.id, &meta, "eda", now).unwrap();
        let d = gather(&s, 7, now).unwrap();
        assert_eq!(d.devices[0].name(), "Reception printer");
        assert_eq!(d.devices[0].asset.device_type, "printer", "override applied");
        let csv = assets_csv(&d);
        assert!(csv.contains("custom.Cost centre"));
        assert!(csv.contains("Reception printer") && csv.contains("SN-99") && csv.contains("floor-1; leased") && csv.contains("expiring"));
        let h = html(&d);
        assert!(h.contains("Lifecycle: needs attention") && h.contains("warranty expires in 15 day(s)"));
        assert!(h.contains("S/N SN-99") && h.contains("owner Jana"));
    }

    #[test]
    fn an_export_can_be_edited_and_reimported_without_changing_anything() {
        let s = SqliteStore::open_in_memory().unwrap();
        let a = saved(&s, 1, "=evil()", &[], "printer");
        let meta = AssetMeta {
            display_name: Some("=SUM(A1)".into()), owner: Some("O'Brien, Jr.".into()), notes: Some("line1\nline2, \"quoted\"".into()),
            tags: vec!["a".into(), "b".into()], custom: [("VLAN".to_string(), "10".to_string())].into(), ..Default::default()
        };
        s.save_meta(a.id, &meta, "eda", 1).unwrap();
        let csv = assets_csv(&gather(&s, 7, 2_000_000).unwrap());
        let (rows, errs) = crate::tracking::parse_import(&csv).unwrap();
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(rows.len(), 1);
        let mut m = s.get_meta(a.id).unwrap().unwrap();
        // applying the re-imported values is a no-op: the round trip is lossless,
        // including the formula guard and quoting
        let changes = crate::tracking::apply_patch(&mut m, &rows[0].patch).unwrap();
        assert!(changes.is_empty(), "{changes:?}");
        assert_eq!(m, meta);
    }

    #[test]
    fn base64_matches_the_rfc_test_vectors() {
        for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn the_report_carries_the_customers_brand_and_never_unescaped() {
        let s = SqliteStore::open_in_memory().unwrap();
        saved(&s, 1, "printer", &[], "printer");
        let mut b = Branding::default();
        b.apply(&serde_json::json!({"product_name": "Acme <b>Guard</b>", "accent": "#dc2626"})).unwrap();
        branding::save(&s, &b, 1).unwrap();
        let png = [&[0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a][..], &[1; 6]].concat();
        s.set_setting(branding::LOGO_KEY, &png, 1).unwrap();
        let h = html(&gather(&s, 7, 1_000_000).unwrap());
        assert!(h.contains("Acme &lt;b&gt;Guard&lt;/b&gt;"), "name escaped");
        assert!(!h.contains("<b>Guard</b>"));
        assert!(h.contains("h1,h2{color:#dc2626}"), "accent applied");
        assert!(h.contains("src=\"data:image/png;base64,iVBORw0KGgo"), "logo embedded as a data URI");
        assert!(!h.contains("http://") && !h.contains("https://") && !h.contains("<script"), "still fully self-contained");
        // the default brand
        let plain = html(&gather(&SqliteStore::open_in_memory().unwrap(), 7, 1_000_000).unwrap());
        assert!(plain.contains("<b>DENIS</b>") && !plain.contains("<img"));
    }

    #[test]
    fn empty_database_still_produces_a_report() {
        let s = SqliteStore::open_in_memory().unwrap();
        let d = gather(&s, 7, 1_000_000).unwrap();
        let h = html(&d);
        assert!(h.contains("No alerts in this period"));
        assert!(h.contains("not enough history yet"));
        assert_eq!(assets_csv(&d).lines().count(), 1);
    }

    #[test]
    fn escape_covers_quotes_too() {
        assert_eq!(esc("a&b<c>\"d\"'e'"), "a&amp;b&lt;c&gt;&quot;d&quot;&#39;e&#39;");
    }
}
