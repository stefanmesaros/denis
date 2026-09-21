//! Asset tracking: validated edits to the manually maintained fields, CSV
//! import, and warranty/lifecycle arithmetic.
//!
//! Everything a person types is untrusted input (it ends up in reports, CSV
//! exports and alerts), so it is length-limited, stripped of control
//! characters, and validated before it is stored.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::model::{AssetMeta, Change, Mac};

pub const STATUSES: &[&str] = &["active", "spare", "retired", "lost", "stolen"];
pub const CRITICALITIES: &[&str] = &["low", "normal", "high", "critical"];

/// Icons the UI can draw. The UI has an SVG for each; an unknown name falls
/// back to a generic one, so adding an icon never breaks older data.
pub const ICONS: &[&str] = &[
    "laptop", "desktop", "server", "phone", "tablet", "printer", "scanner", "router", "switch", "access_point",
    "firewall", "camera", "tv", "media_player", "speaker", "smart_plug", "iot", "sensor", "thermostat", "nas",
    "game_console", "watch", "raspberry_pi", "virtual_machine", "voip_phone", "ups", "plc", "hmi", "rtu",
    "scada", "gateway", "drive", "robot", "building", "apple", "windows", "linux", "android", "unknown",
    // added later: office/IT, network, smart building and home, industrial (keep in step with ui/icons.js)
    "thin_client", "pos", "kiosk", "hypervisor", "database", "storage_array", "kvm", "pdu", "load_balancer", "vpn", "security_appliance", "modem", "mesh_node", "cloud", "projector", "conference", "streaming_stick", "smart_light", "smart_lock", "doorbell", "badge_reader", "alarm_panel", "smoke_detector", "hvac", "smart_hub", "vacuum", "appliance", "printer_3d", "medical", "ev_charger", "inverter", "vehicle", "safety_controller", "protection_relay", "power_meter", "remote_io", "industrial_pc", "cnc", "rfid", "barcode_scanner", "pump", "valve", "motor",
];

/// Purdue reference-model levels (3.5 is the IT/OT demilitarised zone).
pub const PURDUE_LEVELS: &[&str] = &["0", "1", "2", "3", "3.5", "4", "5"];

const MAX_SHORT: usize = 200;
const MAX_NOTES: usize = 4000;
const MAX_TAGS: usize = 20;
const MAX_TAG_LEN: usize = 32;
const MAX_CUSTOM: usize = 30;
const MAX_CUSTOM_KEY: usize = 40;
const MAX_CUSTOM_VAL: usize = 500;

/// Plain text fields, all `Option<String>` on `AssetMeta`.
pub const TEXT_FIELDS: &[&str] = &[
    "display_name", "asset_tag", "serial_number", "model", "manufacturer", "type_override", "os_override",
    "owner", "department", "location", "supplier", "purchase_date", "purchase_price", "warranty_expires",
    "status", "criticality", "notes", "icon", "zone", "purdue_level", "muted_until",
];

fn field_mut<'a>(m: &'a mut AssetMeta, k: &str) -> Option<&'a mut Option<String>> {
    Some(match k {
        "display_name" => &mut m.display_name,
        "asset_tag" => &mut m.asset_tag,
        "serial_number" => &mut m.serial_number,
        "model" => &mut m.model,
        "manufacturer" => &mut m.manufacturer,
        "type_override" => &mut m.type_override,
        "os_override" => &mut m.os_override,
        "owner" => &mut m.owner,
        "department" => &mut m.department,
        "location" => &mut m.location,
        "supplier" => &mut m.supplier,
        "purchase_date" => &mut m.purchase_date,
        "purchase_price" => &mut m.purchase_price,
        "warranty_expires" => &mut m.warranty_expires,
        "status" => &mut m.status,
        "criticality" => &mut m.criticality,
        "notes" => &mut m.notes,
        "icon" => &mut m.icon,
        "zone" => &mut m.zone,
        "purdue_level" => &mut m.purdue_level,
        "muted_until" => &mut m.muted_until,
        _ => return None,
    })
}

pub fn get_field(m: &AssetMeta, k: &str) -> Option<String> {
    let mut c = m.clone();
    field_mut(&mut c, k).and_then(|f| f.clone())
}

fn clean(s: &str, max: usize, multiline: bool) -> Result<String, String> {
    let t = s.trim();
    if t.chars().count() > max {
        return Err(format!("too long (max {max} characters)"));
    }
    if t.chars().any(|c| c.is_control() && !(multiline && (c == '\n' || c == '\t'))) {
        return Err("contains control characters".into());
    }
    Ok(t.replace("\r\n", "\n"))
}

/// `YYYY-MM-DD`, a real calendar date.
pub fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' || !s.chars().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()) {
        return false;
    }
    let (y, m, d): (i64, i64, i64) = (s[0..4].parse().unwrap(), s[5..7].parse().unwrap(), s[8..10].parse().unwrap());
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if leap { 29 } else { 28 },
        _ => return false,
    };
    (1900..=2200).contains(&y) && (1..=dim).contains(&d)
}

/// Days since 1970-01-01 for a valid `YYYY-MM-DD` (civil-from-days inverse).
pub fn days_from_date(s: &str) -> Option<i64> {
    if !valid_date(s) {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (s[0..4].parse().ok()?, s[5..7].parse().ok()?, s[8..10].parse().ok()?);
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// `("expired" | "expiring" | "ok", days_left)`; "expiring" = within 60 days.
pub fn warranty_state(m: &AssetMeta, now: i64) -> Option<(&'static str, i64)> {
    let left = days_from_date(m.warranty_expires.as_deref()?)? - now.div_euclid(86_400);
    Some(match left {
        l if l < 0 => ("expired", l),
        l if l <= 60 => ("expiring", l),
        l => ("ok", l),
    })
}

fn validate_field(key: &str, v: &str) -> Result<(), String> {
    match key {
        "purchase_date" | "warranty_expires" | "muted_until" if !valid_date(v) => Err("must be a date like 2026-09-20".into()),
        "status" if !STATUSES.contains(&v) => Err(format!("must be one of {}", STATUSES.join(", "))),
        "criticality" if !CRITICALITIES.contains(&v) => Err(format!("must be one of {}", CRITICALITIES.join(", "))),
        "type_override" if v.chars().count() > 40 => Err("too long (max 40 characters)".into()),
        "icon" if !ICONS.contains(&v) => Err("unknown icon".into()),
        "purdue_level" if !PURDUE_LEVELS.contains(&v) => Err(format!("must be one of {}", PURDUE_LEVELS.join(", "))),
        _ => Ok(()),
    }
}

fn norm_tags(v: &Value) -> Result<Vec<String>, String> {
    let arr = v.as_array().ok_or("tags must be a list of strings")?;
    let mut out: Vec<String> = Vec::new();
    for t in arr {
        let t = clean(t.as_str().ok_or("tags must be strings")?, MAX_TAG_LEN, false)?.to_lowercase();
        if t.is_empty() {
            continue;
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    if out.len() > MAX_TAGS {
        return Err(format!("at most {MAX_TAGS} tags"));
    }
    Ok(out)
}

fn valid_custom_key(k: &str) -> bool {
    !k.is_empty()
        && k.chars().count() <= MAX_CUSTOM_KEY
        && k.chars().all(|c| c.is_alphanumeric() || matches!(c, ' ' | '_' | '.' | '-'))
}

/// Apply a partial update. `null` or an empty string clears a field; unknown
/// fields are rejected. Atomic: on any error `meta` is left untouched.
pub fn apply_patch(meta: &mut AssetMeta, patch: &Value) -> Result<Vec<Change>, String> {
    let obj = patch.as_object().ok_or("expected a JSON object")?;
    let mut next = meta.clone();
    let mut changes = Vec::new();
    for (key, val) in obj {
        match key.as_str() {
            "tags" => {
                let new = norm_tags(val).map_err(|e| format!("tags: {e}"))?;
                if new != next.tags {
                    changes.push(Change { field: "tags".into(), old: Some(next.tags.join(", ")).filter(|s| !s.is_empty()), new: Some(new.join(", ")).filter(|s| !s.is_empty()) });
                    next.tags = new;
                }
            }
            "custom" => {
                let o = val.as_object().ok_or("custom must be an object")?;
                for (k, v) in o {
                    if !valid_custom_key(k) {
                        return Err(format!("custom field name {k:?} is invalid (letters, digits, space, _ . - only, max {MAX_CUSTOM_KEY})"));
                    }
                    let old = next.custom.get(k).cloned();
                    let new = match v {
                        Value::Null => None,
                        Value::String(s) => Some(clean(s, MAX_CUSTOM_VAL, false).map_err(|e| format!("custom.{k}: {e}"))?).filter(|s| !s.is_empty()),
                        _ => return Err(format!("custom.{k} must be a string or null")),
                    };
                    if old != new {
                        match &new {
                            Some(n) => next.custom.insert(k.clone(), n.clone()),
                            None => next.custom.remove(k),
                        };
                        changes.push(Change { field: format!("custom.{k}"), old, new });
                    }
                }
                if next.custom.len() > MAX_CUSTOM {
                    return Err(format!("at most {MAX_CUSTOM} custom fields"));
                }
            }
            "reviewed" => {
                let new = val.as_bool().ok_or("reviewed must be true or false")?;
                if new != next.reviewed {
                    changes.push(Change { field: "reviewed".into(), old: Some(next.reviewed.to_string()), new: Some(new.to_string()) });
                    next.reviewed = new;
                }
            }
            k if TEXT_FIELDS.contains(&k) => {
                let new = match val {
                    Value::Null => None,
                    Value::String(s) => {
                        let max = if k == "notes" { MAX_NOTES } else { MAX_SHORT };
                        let c = clean(s, max, k == "notes").map_err(|e| format!("{k}: {e}"))?;
                        if c.is_empty() { None } else { validate_field(k, &c).map_err(|e| format!("{k}: {e}"))?; Some(c) }
                    }
                    _ => return Err(format!("{k} must be a string or null")),
                };
                let slot = field_mut(&mut next, k).expect("listed field");
                if *slot != new {
                    changes.push(Change { field: k.into(), old: slot.clone(), new: new.clone() });
                    *slot = new;
                }
            }
            other => return Err(format!("unknown field {other:?}")),
        }
    }
    *meta = next;
    Ok(changes)
}

// ------------------------------------------------------------------ CSV

/// Minimal RFC 4180 reader: quoted fields, doubled quotes, newlines inside quotes,
/// CRLF or LF. Blank lines are skipped.
pub fn parse_csv(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut rows = Vec::new();
    let (mut row, mut field) = (Vec::new(), String::new());
    let mut in_q = false;
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        any = true;
        match (in_q, c) {
            (true, '"') => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_q = false;
                }
            }
            (true, c) => field.push(c),
            (false, '"') if field.is_empty() => in_q = true,
            (false, '"') => return Err("stray quote inside an unquoted field".into()),
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                if row.iter().any(|f| !f.is_empty()) {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
            }
            (false, c) => field.push(c),
        }
    }
    if in_q {
        return Err("unterminated quoted field".into());
    }
    if any && (!field.is_empty() || !row.is_empty()) {
        row.push(field);
        if row.iter().any(|f| !f.is_empty()) {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Columns our own CSV export writes that are *derived*, not editable: a
/// re-imported export must not choke on them.
const READ_ONLY_COLUMNS: &[&str] = &[
    "ip", "name", "vendor", "device_type", "os_guess", "open_ports", "risk_score", "risk_level", "site",
    "first_seen", "last_seen", "private_mac", "gateway", "warranty",
];

#[derive(Debug)]
pub struct ImportRow {
    /// 1-based line number in the file (header is line 1).
    pub line: usize,
    pub mac: Mac,
    pub patch: Value,
}

/// Turn CSV text into per-device patches. `mac` is the key; empty cells leave
/// a field unchanged; `tags` is `;`-separated; `custom.<name>` columns set
/// custom fields. Row-level problems are returned alongside the good rows.
/// Parsed rows plus row-level problems `(line, message)`.
pub type ImportResult = (Vec<ImportRow>, Vec<(usize, String)>);

pub fn parse_import(text: &str) -> Result<ImportResult, String> {
    let rows = parse_csv(text)?;
    let Some((header, body)) = rows.split_first() else {
        return Err("the file is empty".into());
    };
    let cols: Vec<String> = header.iter().map(|h| h.trim().to_lowercase()).collect();
    let mac_col = cols.iter().position(|c| c == "mac").ok_or("a `mac` column is required")?;
    let bad: Vec<&str> = cols
        .iter()
        .filter(|c| {
            !(c.as_str() == "mac" || c.as_str() == "tags" || TEXT_FIELDS.contains(&c.as_str()) || c.starts_with("custom.") || READ_ONLY_COLUMNS.contains(&c.as_str()))
        })
        .map(String::as_str)
        .collect();
    if !bad.is_empty() {
        return Err(format!("unknown column(s): {}", bad.join(", ")));
    }
    if body.len() > 5000 {
        return Err("at most 5000 rows per import".into());
    }

    let (mut good, mut errors) = (Vec::new(), Vec::new());
    for (i, r) in body.iter().enumerate() {
        let line = i + 2;
        let Ok(mac) = r.get(mac_col).map_or("", |s| s.trim()).to_lowercase().parse::<Mac>() else {
            errors.push((line, "invalid MAC address".to_string()));
            continue;
        };
        if !mac.is_valid() {
            errors.push((line, "MAC must be a unicast address".to_string()));
            continue;
        }
        let mut patch = serde_json::Map::new();
        let mut custom = serde_json::Map::new();
        for (c, name) in cols.iter().enumerate() {
            let v = r.get(c).map_or("", |s| s.trim());
            // Undo the export's formula-injection guard so round trips are stable.
            let v = match v.strip_prefix('\'') {
                Some(rest) if rest.starts_with(['=', '+', '-', '@']) => rest,
                _ => v,
            };
            if v.is_empty() {
                continue;
            }
            if name == "tags" {
                patch.insert("tags".into(), Value::Array(v.split([';', ',']).map(|t| Value::String(t.trim().into())).collect()));
            } else if name.starts_with("custom.") {
                // Field names are case-sensitive: take the key from the header as
                // written (only the `custom.` prefix was matched case-insensitively).
                custom.insert(header[c].trim()["custom.".len()..].to_string(), Value::String(v.into()));
            } else if TEXT_FIELDS.contains(&name.as_str()) {
                patch.insert(name.clone(), Value::String(v.into()));
            }
        }
        if !custom.is_empty() {
            patch.insert("custom".into(), Value::Object(custom));
        }
        good.push(ImportRow { line, mac, patch: Value::Object(patch) });
    }
    Ok((good, errors))
}

/// Apply the manual overrides (type, OS, manufacturer) to a discovered asset, so
/// display, risk scoring and exports all see the corrected values. The raw
/// guesses are the caller's to keep if it wants them.
pub fn apply_overrides(asset: &mut crate::model::Asset, meta: &AssetMeta) {
    if let Some(t) = &meta.type_override {
        asset.device_type = t.clone();
    }
    if let Some(o) = &meta.os_override {
        asset.os_guess = Some(o.clone());
    }
    if let Some(m) = &meta.manufacturer {
        asset.vendor = Some(m.clone());
    }
}

/// A locally-administered MAC for an asset that has none yet (`02:54:42:…`).
/// The bit pattern guarantees it cannot collide with a real device.
pub fn synthetic_mac() -> Mac {
    let mut b = [0u8; 3];
    let _ = getrandom::fill(&mut b);
    Mac([0x02, 0x54, 0x42, b[0], b[1], b[2]])
}

/// Group `custom.*` values for CSV export in a stable order.
pub fn custom_columns(all: &[&AssetMeta]) -> Vec<String> {
    let mut keys: BTreeMap<String, ()> = BTreeMap::new();
    for m in all {
        for k in m.custom.keys() {
            keys.insert(k.clone(), ());
        }
    }
    keys.into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn patches_set_clear_and_report_changes() {
        let mut m = AssetMeta::default();
        let ch = apply_patch(&mut m, &json!({"serial_number": " SN-123 ", "owner": "Jana", "notes": "line1\nline2"})).unwrap();
        assert_eq!(m.serial_number.as_deref(), Some("SN-123"), "trimmed");
        assert_eq!(ch.len(), 3);
        // clearing with null or empty string
        let ch = apply_patch(&mut m, &json!({"owner": null, "serial_number": ""})).unwrap();
        assert_eq!((m.owner.clone(), m.serial_number.clone()), (None, None));
        assert_eq!(ch.len(), 2);
        assert_eq!(ch.iter().find(|c| c.field == "owner").unwrap().old.as_deref(), Some("Jana"));
        // setting the same value is not a change
        assert!(apply_patch(&mut m, &json!({"notes": "line1\nline2"})).unwrap().is_empty());
    }

    #[test]
    fn validation_is_strict_and_atomic() {
        let mut m = AssetMeta { owner: Some("keep".into()), ..Default::default() };
        for (patch, why) in [
            (json!({"owner": "new", "warranty_expires": "2026-02-30"}), "impossible date"),
            (json!({"owner": "new", "warranty_expires": "20/09/2026"}), "wrong date format"),
            (json!({"owner": "new", "status": "borrowed"}), "unknown status"),
            (json!({"owner": "new", "criticality": "urgent"}), "unknown criticality"),
            (json!({"owner": "new", "bogus": "x"}), "unknown field"),
            (json!({"owner": "new", "manual": true}), "manual is not settable"),
            (json!({"owner": "new", "icon": "../../etc/passwd"}), "icon must be from the list"),
            (json!({"owner": "new", "purdue_level": "7"}), "purdue level must be from the list"),
            (json!({"owner": "new\u{7}bell"}), "control char"),
            (json!({"owner": "x".repeat(201)}), "too long"),
            (json!({"owner": 5}), "wrong type"),
            (json!({"tags": "a,b"}), "tags must be a list"),
            (json!({"custom": {"bad/key": "x"}}), "bad custom key"),
            (json!({"custom": {"k": 5}}), "custom value type"),
        ] {
            assert!(apply_patch(&mut m, &patch).is_err(), "{why}");
            assert_eq!(m.owner.as_deref(), Some("keep"), "{why}: nothing may be applied on error");
        }
        assert!(apply_patch(&mut m, &json!(["not", "an", "object"])).is_err());
        // limits
        let many: Vec<String> = (0..21).map(|i| format!("t{i}")).collect();
        assert!(apply_patch(&mut m, &json!({"tags": many})).is_err());
        let custom: serde_json::Map<String, Value> = (0..31).map(|i| (format!("k{i}"), json!("v"))).collect();
        assert!(apply_patch(&mut m, &json!({"custom": custom})).is_err());
    }

    #[test]
    fn icons_and_ot_fields_accept_only_known_values() {
        let mut m = AssetMeta::default();
        apply_patch(&mut m, &json!({"icon": "plc", "purdue_level": "3.5", "zone": "Line 3 cell"})).unwrap();
        assert_eq!((m.icon.as_deref(), m.purdue_level.as_deref(), m.zone.as_deref()), (Some("plc"), Some("3.5"), Some("Line 3 cell")));
        // every advertised icon is valid, and clearing returns to automatic
        for i in ICONS {
            apply_patch(&mut m, &json!({ "icon": i })).unwrap();
        }
        apply_patch(&mut m, &json!({"icon": null})).unwrap();
        assert_eq!(m.icon, None);
    }

    #[test]
    fn tags_are_normalised_and_custom_fields_editable() {
        let mut m = AssetMeta::default();
        apply_patch(&mut m, &json!({"tags": [" Server ", "server", "Rack-2", ""], "custom": {"Cost centre": "CC-42", "VLAN": "10"}})).unwrap();
        assert_eq!(m.tags, ["server", "rack-2"]);
        assert_eq!(m.custom["Cost centre"], "CC-42");
        let ch = apply_patch(&mut m, &json!({"custom": {"VLAN": null, "Cost centre": "CC-43"}})).unwrap();
        assert_eq!(ch.len(), 2);
        assert!(!m.custom.contains_key("VLAN"));
        assert_eq!(m.custom["Cost centre"], "CC-43");
    }

    #[test]
    fn dates_and_warranty_arithmetic() {
        assert!(valid_date("2024-02-29") && !valid_date("2023-02-29") && !valid_date("2026-13-01") && !valid_date("2026-9-1"));
        assert_eq!(days_from_date("1970-01-01"), Some(0));
        assert_eq!(days_from_date("2000-03-01"), Some(11_017));
        let now = days_from_date("2026-09-20").unwrap() * 86_400 + 5;
        let m = |d: &str| AssetMeta { warranty_expires: Some(d.into()), ..Default::default() };
        assert_eq!(warranty_state(&m("2026-09-19"), now), Some(("expired", -1)));
        assert_eq!(warranty_state(&m("2026-09-20"), now), Some(("expiring", 0)));
        assert_eq!(warranty_state(&m("2026-11-19"), now), Some(("expiring", 60)));
        assert_eq!(warranty_state(&m("2026-11-20"), now), Some(("ok", 61)));
        assert_eq!(warranty_state(&AssetMeta::default(), now), None);
    }

    #[test]
    fn csv_parser_handles_quotes_newlines_crlf_and_bom() {
        let r = parse_csv("\u{feff}a,b,c\r\n1,\"x, y\",\"say \"\"hi\"\"\"\r\n\r\n2,\"multi\nline\",\n").unwrap();
        assert_eq!(r, vec![vec!["a", "b", "c"], vec!["1", "x, y", "say \"hi\""], vec!["2", "multi\nline", ""]]);
        assert!(parse_csv("a,\"unterminated").is_err());
        assert!(parse_csv("a,b\"c").is_err());
        assert_eq!(parse_csv("").unwrap().len(), 0);
        assert_eq!(parse_csv("x").unwrap(), vec![vec!["x"]]);
    }

    #[test]
    fn import_maps_columns_and_reports_row_errors() {
        let text = "MAC,serial_number,owner,tags,custom.VLAN,ip,name\n\
                    3C:22:FB:00:00:01,SN1,Jana,\"a; b\",10,10.0.0.1,ignored\n\
                    not-a-mac,SN2,,,,,\n\
                    01:00:5e:00:00:01,SN3,,,,,\n\
                    3c:22:fb:00:00:02,,'=cmd,,,,\n";
        let (ok, errs) = parse_import(text).unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].mac.to_string(), "3c:22:fb:00:00:01");
        assert_eq!(ok[0].patch, json!({"serial_number": "SN1", "owner": "Jana", "tags": ["a", "b"], "custom": {"VLAN": "10"}}));
        assert_eq!(errs.iter().map(|e| e.0).collect::<Vec<_>>(), [3, 4]);
        // the export's formula guard is undone; empty cells change nothing
        assert_eq!(ok[1].patch, json!({"owner": "=cmd"}));
        // structural errors reject the whole file
        assert!(parse_import("serial_number\nx").unwrap_err().contains("mac"));
        assert!(parse_import("mac,colour\n3c:22:fb:00:00:01,red").unwrap_err().contains("colour"));
        assert!(parse_import("").is_err());
    }

    #[test]
    fn synthetic_macs_are_private_and_unicast() {
        let m = synthetic_mac();
        assert!(m.is_valid() && m.is_locally_administered());
        assert_ne!(synthetic_mac(), synthetic_mac());
    }

    /// Import files and edit payloads are user-supplied: garbage must be
    /// rejected with an error, never a panic.
    #[test]
    fn random_text_never_panics_the_csv_and_patch_parsers() {
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        let alphabet: Vec<char> = "abc,\"\n\r;'=+-@ \t\u{feff}\u{0}é中😀mac.custom".chars().collect();
        for _ in 0..20_000 {
            let len = (next() % 80) as usize;
            let text: String = (0..len).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
            let _ = parse_csv(&text);
            let _ = parse_import(&text);
            let _ = parse_import(&format!("mac,owner,tags,custom.x\n{text}"));
            let mut m = AssetMeta::default();
            let _ = apply_patch(&mut m, &serde_json::from_str(&text).unwrap_or(Value::String(text.clone())));
            let _ = apply_patch(&mut m, &json!({"owner": text.clone(), "tags": [text.clone()], "custom": {text.clone(): text}}));
        }
    }

    /// The UI draws icons from ui/icons.js; every icon the server accepts must exist there,
    /// and every drawing must be selectable, or users would see the "unknown" shape.
    #[test]
    fn the_server_and_ui_agree_on_the_icon_set() {
        let js = include_str!("../ui/icons.js");
        let body = &js[js.find("const ICON_SHAPES = {").unwrap()..js.find("/** Names offered").unwrap()];
        let drawn: Vec<&str> = body
            .lines()
            .filter_map(|l| l.strip_prefix("  ").and_then(|l| l.split_once(": [[")).map(|(k, _)| k))
            .collect();
        for i in ICONS {
            assert!(drawn.contains(i), "server offers icon {i} but ui/icons.js does not draw it");
        }
        for d in &drawn {
            assert!(ICONS.contains(d), "ui/icons.js draws {d} but the server would refuse it");
        }
        let mut sorted = ICONS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ICONS.len(), "duplicate icon names");
    }

    /// Every type the guesser/edit form offers has a matching icon (or falls back knowingly).
    #[test]
    fn every_ot_type_is_also_offered_as_a_device_type() {
        for t in crate::fingerprint::OT_TYPES {
            assert!(crate::fingerprint::DEVICE_TYPES.contains(t), "{t}");
        }
    }
}
