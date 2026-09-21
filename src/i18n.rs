//! The console's translations (`ui/i18n/*.json`, generated from `tools/i18n/*.tsv`) are checked here so a
//! missing or broken translation fails the build instead of showing up as English text in a German menu.
//!
//! What is verified: every language has the same keys with the same `{placeholders}`; the JSON files match
//! the `.tsv` sources they are generated from; and every English string the console can show is in the
//! catalog: the `tr('…')` calls in the scripts, the static text of `index.html`, and what the server sends
//! (rules, findings, advice, compliance, device types).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

const LANGS: [&str; 4] = ["de", "fr", "es", "sk"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn catalog(lang: &str) -> BTreeMap<String, String> {
    serde_json::from_str(&read(&format!("ui/i18n/{lang}.json"))).unwrap_or_else(|e| panic!("{lang}.json: {e}"))
}

fn placeholders(s: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = s;
    while let Some(i) = rest.find('{') {
        let Some(j) = rest[i..].find('}') else { break };
        let name = &rest[i + 1..i + j];
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            out.insert(name.to_string());
        }
        rest = &rest[i + j + 1..];
    }
    out
}

/// The English strings passed to `tr('…')` in a script.
fn tr_literals(js: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = js;
    while let Some(i) = rest.find("tr('") {
        let word_start = i == 0 || !rest.as_bytes()[i - 1].is_ascii_alphanumeric() && rest.as_bytes()[i - 1] != b'_';
        rest = &rest[i + 4..];
        if !word_start {
            continue;
        }
        let mut s = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => s.extend(chars.next()),
                '\'' => break,
                c => s.push(c),
            }
        }
        out.push(s);
    }
    out
}

fn unescape_html(s: &str) -> String {
    s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'")
}

/// Text nodes and `placeholder`/`title`/`aria-label` values of `index.html`, as the page translator sees them.
fn html_strings(html: &str) -> Vec<String> {
    let mut body = html.to_string();
    while let (Some(a), Some(b)) = (body.find("<script"), body.find("</script>")) {
        body.replace_range(a..b + 9, "");
    }
    let mut out = Vec::new();
    let mut rest = body.as_str();
    while let Some(i) = rest.find('>') {
        rest = &rest[i + 1..];
        let end = rest.find('<').unwrap_or(rest.len());
        let text = &rest[..end];
        if !text.contains('>') {
            out.push(unescape_html(&text.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
    }
    for attr in ["placeholder=\"", "title=\"", "aria-label=\""] {
        let mut rest = body.as_str();
        while let Some(i) = rest.find(attr) {
            rest = &rest[i + attr.len()..];
            if let Some(j) = rest.find('"') {
                out.push(unescape_html(&rest[..j]));
            }
        }
    }
    out.retain(|t| t.len() >= 2 && t.as_bytes().windows(2).any(|w| w[0].is_ascii_alphabetic() && w[1].is_ascii_alphabetic()));
    // command-line flags and header names are shown as they are
    out.retain(|t| !t.starts_with("--") && !t.starts_with("Authorization:"));
    out
}

fn assert_translated(cat: &BTreeMap<String, String>, what: &str, keys: impl IntoIterator<Item = String>) {
    let missing: Vec<String> = keys.into_iter().filter(|k| !cat.contains_key(k)).collect();
    assert!(missing.is_empty(), "{what}: {} string(s) without a translation (add them to tools/i18n/*.tsv and run python3 tools/i18n/build.py):\n{}", missing.len(), missing.join("\n"));
}

#[test]
fn every_language_has_the_same_keys_and_placeholders() {
    let de = catalog("de");
    assert!(de.len() > 500, "the German catalog is suspiciously small: {}", de.len());
    for lang in LANGS {
        let cat = catalog(lang);
        assert_eq!(cat.keys().collect::<Vec<_>>(), de.keys().collect::<Vec<_>>(), "{lang} has different keys than de");
        for (k, v) in &cat {
            assert!(!v.trim().is_empty(), "{lang}: empty translation of {k:?}");
            assert_eq!(placeholders(k), placeholders(v), "{lang}: placeholders differ for {k:?}");
        }
    }
}

#[test]
fn the_json_catalogs_are_the_ones_generated_from_the_sources() {
    let mut expected: HashMap<&str, BTreeMap<String, String>> = LANGS.iter().map(|l| (*l, BTreeMap::new())).collect();
    let mut files: Vec<_> = std::fs::read_dir(root().join("tools/i18n")).unwrap().filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "tsv")).collect();
    files.sort();
    assert!(!files.is_empty());
    for f in files {
        for line in std::fs::read_to_string(&f).unwrap().lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split(" || ").map(str::trim).collect();
            assert_eq!(cols.len(), 5, "{}: {line}", f.display());
            for (lang, text) in LANGS.iter().zip(&cols[1..]) {
                expected.get_mut(lang).unwrap().insert(cols[0].to_string(), (*text).to_string());
            }
        }
    }
    for lang in LANGS {
        assert!(expected[lang] == catalog(lang), "ui/i18n/{lang}.json is out of date: run python3 tools/i18n/build.py");
    }
}

#[test]
fn every_string_the_scripts_and_pages_show_is_translated() {
    let cat = catalog("de");
    for script in ["app.js", "admin.js", "rules.js", "main.js", "icons.js"] {
        assert_translated(&cat, script, tr_literals(&read(&format!("ui/{script}"))));
    }
    assert_translated(&cat, "index.html", html_strings(&read("ui/index.html")));
    // the icon chooser's group titles and every icon name are passed to tr() as variables
    let icons = read("ui/icons.js");
    let cats = &icons[icons.find("const ICON_CATEGORIES = [").expect("categories")..];
    let mut shown: Vec<String> = cats.lines().filter_map(|l| l.strip_prefix("  ['")).filter_map(|l| l.split("', [").next().map(String::from)).collect();
    shown.push("Other".into());
    let shapes = &icons[..icons.find("const NAV_SHAPES").expect("shapes")];
    shown.extend(shapes.lines().filter_map(|l| l.strip_prefix("  ")).filter(|l| l.contains(": [[")).filter_map(|l| l.split(':').next()).filter(|n| n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')).map(|n| n.replace('_', " ")));
    assert!(shown.len() > 100, "the icon scanner found only {} names", shown.len());
    assert_translated(&cat, "icons.js", shown);
    // the scanner itself works: it finds strings with escapes and ignores look-alikes
    assert_eq!(tr_literals("a(tr('It\\'s {n}'), str('x'), tr('b'))"), vec!["It's {n}", "b"]);
}

#[test]
fn everything_the_server_sends_for_display_is_translated() {
    let cat = catalog("de");
    let mut keys: Vec<String> = Vec::new();
    for r in crate::rules::RULE_INFO {
        keys.extend([r.title, r.summary].map(String::from));
        keys.push(r.needs.to_string());
    }
    for p in crate::rules::PARAMS {
        keys.extend([p.label, p.unit, p.help].map(String::from));
    }
    keys.extend(crate::detect::ADVICE.iter().map(|(_, a)| a.to_string()));
    keys.extend(crate::findings::texts().into_iter().map(String::from));
    for list in [crate::fingerprint::DEVICE_TYPES, crate::tracking::STATUSES, crate::tracking::CRITICALITIES] {
        keys.extend(list.iter().map(|s| s.to_string()));
    }
    keys.extend(crate::tracking::ICONS.iter().filter(|i| **i != "windows").map(|i| i.replace('_', " ")));
    keys.extend(crate::risk::texts().into_iter().map(String::from));
    keys.extend([crate::engine::NOTE_PASSIVE_ONLY, crate::engine::NOTE_FLOWS, crate::engine::NOTE_VIEWER].map(String::from));
    keys.extend(["low", "medium", "high", "critical", "info", "none", "viewer", "editor", "admin"].map(String::from));
    keys.retain(|k| k != "windows");
    assert_translated(&cat, "server strings", keys);
    assert_translated(&cat, "update stages", crate::update::STAGES.iter().map(|s| s.to_string()));
    // compliance: run the assessment with everything off and everything on, so every branch is seen
    let mut shown: BTreeSet<String> = BTreeSet::new();
    for on in [false, true] {
        let assets = vec![];
        let metas = HashMap::new();
        let r = crate::compliance::assess(&crate::compliance::Inputs {
            assets: &assets, metas: &metas, now: 0, passive_discovery: on, active_discovery: on, traffic_analysis: on, learning_finished: on,
            rules_enabled: usize::from(on), rules_total: 3, channels_enabled: 0, exports_configured: 0, users: 1, users_with_passkey: 0, admins: 1, admins_with_passkey: 0,
        });
        shown.insert(r.disclaimer.to_string());
        for m in r.measures {
            shown.extend([m.label.to_string(), m.detail.to_string()]);
        }
        for c in r.controls {
            shown.extend([c.title, c.evidence, c.note].map(String::from));
        }
    }
    assert_translated(&cat, "compliance", shown);
}
