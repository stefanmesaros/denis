//! End-of-support dates and known-exploited vulnerabilities, matched against the software versions that service
//! banners give away (see `banners.rs`).
//!
//! **Where the data comes from.** `data/vulndata.json` is built by `tools/build-vulndata.py` from three public sources:
//! endoflife.date (support dates per release), the CISA Known Exploited Vulnerabilities catalog, and NVD (the version
//! ranges of those CVEs, kept only when they are clean single-product ranges). It ships inside the program. Only the
//! support dates can additionally be refreshed from endoflife.date by the console (off by default; nothing about your
//! network is sent). The KEV list arrives with new DENIS releases.
//!
//! **What is claimed.** Only what a banner's own version number supports: "this version's support ended on …" and
//! "this version is in the range affected by a vulnerability that is being exploited". A distribution can patch a
//! flaw without changing the version number, so a match on a banner that names a distribution is worded as *may be*
//! affected, and never as confirmed.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use crate::banners::Software;
use crate::store::Store;

const BUNDLED: &str = include_str!("../data/vulndata.json");
pub const OVERLAY_KEY: &str = "vulndata.eol";
pub const SETTINGS_KEY: &str = "vulndata";
/// A release whose support ends within this many days is announced.
pub const SOON_DAYS: i64 = 90;

// ------------------------------------------------------------------------------------------ versions

/// A version as banners and advisories write it: numbers, then perhaps a letter (`1.0.1f`) or a portable-release
/// suffix (`9.6p1`, which is the same release as `9.6` for judging what it is affected by).
#[derive(Clone, Debug)]
pub struct Ver {
    nums: Vec<u64>,
    suffix: String,
}

impl Ver {
    pub fn parse(s: &str) -> Option<Ver> {
        let s = s.trim();
        // NVD writes some versions as `1.0.1:beta1`: the main part is what is compared
        let s = s.split(':').next().unwrap_or(s);
        let end = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
        let (num, rest) = s.split_at(end);
        let num = num.trim_end_matches('.');
        if num.is_empty() {
            return None;
        }
        let nums: Option<Vec<u64>> = num.split('.').map(|p| p.parse().ok()).collect();
        let rest = rest.to_ascii_lowercase();
        let portable = rest.strip_prefix('p').is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()));
        Some(Ver { nums: nums?, suffix: if portable { String::new() } else { rest } })
    }
}

impl PartialEq for Ver {
    fn eq(&self, o: &Ver) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}

impl Eq for Ver {}

impl Ord for Ver {
    fn cmp(&self, o: &Ver) -> Ordering {
        for i in 0..self.nums.len().max(o.nums.len()) {
            let (a, b) = (self.nums.get(i).copied().unwrap_or(0), o.nums.get(i).copied().unwrap_or(0));
            if a != b {
                return a.cmp(&b);
            }
        }
        self.suffix.cmp(&o.suffix)
    }
}

impl PartialOrd for Ver {
    fn partial_cmp(&self, o: &Ver) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

// ---------------------------------------------------------------------------------------------- data

/// `false` (supported), `true` (ended, date unknown) or `"2025-04-23"`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Eol {
    Flag(bool),
    Date(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cycle {
    pub cycle: String,
    pub eol: Eol,
    #[serde(default)]
    pub latest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Range {
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub from_incl: bool,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub to_incl: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Kev {
    pub cve: String,
    pub name: String,
    pub added: String,
    pub product: String,
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub ransomware: bool,
}

/// One CISA ICS-CERT advisory, matched only by vendor name (see `Intel::ics`) — a coarser,
/// more conservative signal than the version-matched `kev` list above: a passively observed
/// vendor name (from the IEEE OUI registry, or an industrial protocol's own identity read)
/// cannot confirm a firmware version, so this never claims a specific CVE applies, only that
/// the manufacturer has an open advisory worth checking against the device's actual firmware.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IcsAdvisory {
    /// e.g. `"ICSA-24-123-01"`.
    pub id: String,
    pub title: String,
    /// As CISA writes it, e.g. `"Siemens"`; matched case-insensitively, either direction, against
    /// a device's own vendor string (`"Siemens AG"` matches `"Siemens"`).
    pub vendor: String,
    pub published: String,
    #[serde(default)]
    pub cves: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Data {
    /// When the data was built (`YYYY-MM-DD`).
    pub generated: String,
    #[serde(default)]
    pub kev_catalog_version: Option<String>,
    pub eol: BTreeMap<String, Vec<Cycle>>,
    pub kev: Vec<Kev>,
    /// FIRST.org EPSS score (0.0-1.0: modelled probability of exploitation in the next 30 days)
    /// for a `kev` CVE above, when available. Purely informational context alongside a `kev`
    /// finding; never changes whether one fires.
    #[serde(default)]
    pub epss: BTreeMap<String, f32>,
    #[serde(default)]
    pub ics: Vec<IcsAdvisory>,
}

impl Range {
    pub fn contains(&self, v: &Ver) -> bool {
        if let Some(x) = &self.exact {
            return Ver::parse(x).is_some_and(|e| e == *v);
        }
        if let Some(lo) = self.from.as_deref().and_then(Ver::parse) {
            if v < &lo || (v == &lo && !self.from_incl) {
                return false;
            }
        }
        if let Some(hi) = self.to.as_deref().and_then(Ver::parse) {
            if v > &hi || (v == &hi && !self.to_incl) {
                return false;
            }
        }
        self.from.is_some() || self.to.is_some()
    }
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` date.
pub fn days_of(date: &str) -> Option<i64> {
    let mut it = date.get(..10)?.split('-');
    let (y, m, d): (i64, i64, i64) = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// What the support dates say about one version.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EolStatus {
    pub cycle: String,
    /// `ended` or `soon`.
    pub state: &'static str,
    /// The day support ended or will end, when the source gives it.
    pub date: Option<String>,
    /// Days until it ends (`soon` only).
    pub days_left: Option<i64>,
}

pub struct Intel {
    pub data: Data,
    /// When the support dates were last refreshed from endoflife.date (`None`: the bundled ones are used).
    pub refreshed_at: Option<i64>,
}

/// The data the findings are judged by right now: the bundled data, or that with refreshed support dates laid over it.
/// Set at start-up and after a refresh (`reload`); everything that computes findings reads it, so they all agree.
static CURRENT: std::sync::RwLock<Option<std::sync::Arc<Intel>>> = std::sync::RwLock::new(None);

pub fn current() -> std::sync::Arc<Intel> {
    if let Some(i) = CURRENT.read().unwrap().as_ref() {
        return i.clone();
    }
    let i = std::sync::Arc::new(Intel::bundled());
    *CURRENT.write().unwrap() = Some(i.clone());
    i
}

/// Read the refreshed support dates (if any) from the database and use them from now on.
pub fn reload(store: &dyn Store) {
    *CURRENT.write().unwrap() = Some(std::sync::Arc::new(Intel::load(store)));
}

fn bundled() -> &'static Data {
    static D: OnceLock<Data> = OnceLock::new();
    D.get_or_init(|| serde_json::from_str(BUNDLED).expect("data/vulndata.json is valid (checked by a test)"))
}

impl Intel {
    /// What ships in the program.
    pub fn bundled() -> Intel {
        Intel { data: bundled().clone(), refreshed_at: None }
    }

    /// The bundled data, with support dates refreshed from endoflife.date laid over it when there are newer ones.
    pub fn load(store: &dyn Store) -> Intel {
        let mut i = Intel::bundled();
        if let Some(o) = store.get_setting(OVERLAY_KEY).ok().flatten().and_then(|b| serde_json::from_slice::<Overlay>(&b).ok()) {
            let newer = days_of(&i.data.generated).is_none_or(|g| o.fetched_at / 86_400 >= g);
            if newer {
                for (product, cycles) in o.eol {
                    if !cycles.is_empty() {
                        i.data.eol.insert(product, cycles);
                    }
                }
                i.refreshed_at = Some(o.fetched_at);
            }
        }
        i
    }

    /// Support status of a version, if the release is one the source knows.
    pub fn eol(&self, product: &str, version: &str, today: i64) -> Option<EolStatus> {
        let v = Ver::parse(version)?;
        let cycles = self.data.eol.get(product)?;
        // the longest cycle that is a prefix of the version (`1.1.1` beats `1.1`)
        let best = cycles
            .iter()
            .filter_map(|c| Ver::parse(&c.cycle).filter(|cv| cv.suffix.is_empty() && cv.nums.len() <= v.nums.len() && cv.nums.iter().zip(&v.nums).all(|(a, b)| a == b)).map(|cv| (cv.nums.len(), c)))
            .max_by_key(|(n, _)| *n)?
            .1;
        match &best.eol {
            Eol::Flag(false) => None,
            Eol::Flag(true) => Some(EolStatus { cycle: best.cycle.clone(), state: "ended", date: None, days_left: None }),
            Eol::Date(d) => {
                let end = days_of(d)?;
                if end <= today {
                    Some(EolStatus { cycle: best.cycle.clone(), state: "ended", date: Some(d.clone()), days_left: None })
                } else if end - today <= SOON_DAYS {
                    Some(EolStatus { cycle: best.cycle.clone(), state: "soon", date: Some(d.clone()), days_left: Some(end - today) })
                } else {
                    None
                }
            }
        }
    }

    /// Known-exploited vulnerabilities whose affected range contains this version.
    pub fn kev(&self, product: &str, version: &str) -> Vec<&Kev> {
        let Some(v) = Ver::parse(version) else { return Vec::new() };
        self.data.kev.iter().filter(|k| k.product == product && k.ranges.iter().any(|r| r.contains(&v))).collect()
    }

    pub fn products(&self) -> Vec<&str> {
        self.data.eol.keys().map(String::as_str).collect()
    }

    /// ICS-CERT advisories for a device's own vendor string (see `IcsAdvisory` for why this is
    /// vendor-only, not version-matched). Empty vendor never matches anything.
    pub fn ics(&self, device_vendor: &str) -> Vec<&IcsAdvisory> {
        let dv = device_vendor.trim().to_ascii_lowercase();
        if dv.is_empty() {
            return Vec::new();
        }
        self.data
            .ics
            .iter()
            .filter(|a| {
                let av = a.vendor.to_ascii_lowercase();
                !av.is_empty() && (dv.contains(&av) || av.contains(&dv))
            })
            .collect()
    }

    pub fn epss(&self, cve: &str) -> Option<f32> {
        self.data.epss.get(cve).copied()
    }
}

// ----------------------------------------------------------------------------------------- refreshing

/// Support dates refreshed from endoflife.date, kept beside the bundled data.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Overlay {
    pub fetched_at: i64,
    pub eol: BTreeMap<String, Vec<Cycle>>,
}

/// Whether the console fetches fresh support dates by itself (every week). Off unless an administrator switches it on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Settings {
    pub refresh_eol: bool,
}

pub fn settings(store: &dyn Store) -> Settings {
    store.get_setting(SETTINGS_KEY).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save_settings(store: &dyn Store, s: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(s)?, now)
}

/// Parse and validate one product's answer from endoflife.date (`[{"cycle": "1.28", "eol": "2026-04-14", ...}, ...]`).
pub fn parse_product(body: &[u8]) -> Result<Vec<Cycle>> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| anyhow!("not JSON: {e}"))?;
    let list = v.as_array().ok_or_else(|| anyhow!("not a list of releases"))?;
    if list.is_empty() || list.len() > 500 {
        bail!("an unreasonable number of releases ({})", list.len());
    }
    let mut out = Vec::new();
    for item in list {
        let cycle = item["cycle"].as_str().or_else(|| item["cycle"].as_f64().map(|_| "")).unwrap_or("");
        // cycles are strings ("1.28"), but a few products write a bare number
        let cycle = if cycle.is_empty() { item["cycle"].to_string().trim_matches('"').to_string() } else { cycle.to_string() };
        let eol = match &item["eol"] {
            serde_json::Value::Bool(b) => Eol::Flag(*b),
            serde_json::Value::String(s) if days_of(s).is_some() => Eol::Date(s.clone()),
            _ => continue, // no support information for this release
        };
        if cycle.is_empty() || cycle.len() > 40 || Ver::parse(&cycle).is_none() {
            continue;
        }
        out.push(Cycle { cycle, eol, latest: item["latest"].as_str().filter(|s| s.len() <= 40).map(String::from) });
    }
    if out.is_empty() {
        bail!("no usable releases in the answer");
    }
    Ok(out)
}

/// Fetch every product's support dates from `base` (`https://endoflife.date`). Blocking. All or nothing: a product
/// that fails leaves the bundled dates for that product only, and the outcome says which.
pub fn fetch_overlay(base: &str, products: &[&str], now: i64) -> Result<(Overlay, Vec<String>)> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(20))).http_status_as_error(true).build().into();
    let mut overlay = Overlay { fetched_at: now, eol: BTreeMap::new() };
    let mut failed = Vec::new();
    for p in products {
        let url = format!("{}/api/{}.json", base.trim_end_matches('/'), p);
        let got = agent
            .get(&url)
            .header("User-Agent", concat!("denis/", env!("CARGO_PKG_VERSION")))
            .call()
            .map_err(|e| anyhow!("{e}"))
            .and_then(|mut r| r.body_mut().with_config().limit(1_000_000).read_to_vec().map_err(|e| anyhow!("{e}")))
            .and_then(|b| parse_product(&b));
        match got {
            Ok(c) => {
                overlay.eol.insert((*p).to_string(), c);
            }
            Err(e) => failed.push(format!("{p}: {e}")),
        }
    }
    if overlay.eol.is_empty() {
        bail!("could not fetch any support dates ({})", failed.join("; "));
    }
    Ok((overlay, failed))
}

/// Refresh now and keep the result. Returns how many products were refreshed and the ones that failed.
pub fn refresh_now(store: &dyn Store, base: &str, now: i64) -> Result<(usize, Vec<String>)> {
    let intel = Intel::load(store);
    let products: Vec<&str> = intel.products();
    let (overlay, failed) = fetch_overlay(base, &products, now)?;
    let n = overlay.eol.len();
    // keep what an earlier refresh got for a product that failed this time
    let mut merged = store.get_setting(OVERLAY_KEY).ok().flatten().and_then(|b| serde_json::from_slice::<Overlay>(&b).ok()).unwrap_or_default();
    merged.fetched_at = now;
    merged.eol.extend(overlay.eol);
    store.set_setting(OVERLAY_KEY, &serde_json::to_vec(&merged)?, now)?;
    reload(store);
    Ok((n, failed))
}

pub const EOL_URL: &str = "https://endoflife.date";

/// One line for what software a device runs, for the findings: `OpenSSH 8.9p1`.
pub fn product_name(key: &str) -> &'static str {
    match key {
        "openssh" => "OpenSSH",
        "dropbear" => "Dropbear",
        "nginx" => "nginx",
        "apache-http-server" => "Apache HTTP Server",
        "php" => "PHP",
        "openssl" => "OpenSSL",
        "lighttpd" => "lighttpd",
        "iis" => "Microsoft IIS",
        "exim" => "Exim",
        "proftpd" => "ProFTPD",
        "vsftpd" => "vsftpd",
        _ => "software",
    }
}

/// What the findings say about one piece of software on one device.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Evidence {
    pub asset_id: i64,
    pub product: &'static str,
    pub version: String,
    /// `eol`, `eol_soon`, `kev` or `ics`.
    pub kind: &'static str,
    pub cycle: Option<String>,
    pub date: Option<String>,
    pub days_left: Option<i64>,
    pub cve: Option<String>,
    pub name: Option<String>,
    /// The banner names a distribution: the fix may already be in, under the same version number.
    pub backport: bool,
    pub ransomware: bool,
    /// `kev` only: FIRST.org's EPSS score, if known (see `IcsAdvisory`/`Data::epss`).
    pub epss: Option<f32>,
    /// `ics` only: the device's own vendor string that matched, and the advisory's id.
    pub vendor: Option<String>,
    pub advisory_id: Option<String>,
}

/// The evidence one device's banners give, judged against `intel`.
pub fn evidence_for(asset_id: i64, software: &[Software], intel: &Intel, today: i64) -> Vec<Evidence> {
    let mut out = Vec::new();
    for s in software {
        let base = |kind: &'static str| Evidence {
            asset_id, product: product_name(s.product), version: s.version.clone(), kind, cycle: None, date: None, days_left: None, cve: None, name: None,
            backport: s.distro, ransomware: false, epss: None, vendor: None, advisory_id: None,
        };
        if let Some(e) = intel.eol(s.product, &s.version, today) {
            out.push(Evidence { cycle: Some(e.cycle), date: e.date, days_left: e.days_left, ..base(if e.state == "ended" { "eol" } else { "eol_soon" }) });
        }
        for k in intel.kev(s.product, &s.version) {
            out.push(Evidence { cve: Some(k.cve.clone()), name: Some(k.name.clone()), date: Some(k.added.clone()), ransomware: k.ransomware, epss: intel.epss(&k.cve), ..base("kev") });
        }
    }
    out
}

/// ICS-CERT advisory evidence for an industrial device, matched only by vendor (see
/// `Intel::ics`). `None`/empty vendor yields nothing.
pub fn ics_evidence_for(asset_id: i64, device_vendor: Option<&str>, intel: &Intel) -> Vec<Evidence> {
    let Some(vendor) = device_vendor else { return Vec::new() };
    intel
        .ics(vendor)
        .into_iter()
        .map(|a| Evidence {
            asset_id,
            product: "",
            version: String::new(),
            kind: "ics",
            cycle: None,
            date: Some(a.published.clone()),
            days_left: None,
            cve: a.cves.first().cloned(),
            name: Some(a.title.clone()),
            backport: false,
            ransomware: false,
            epss: None,
            vendor: Some(a.vendor.clone()),
            advisory_id: Some(a.id.clone()),
        })
        .collect()
}

/// Background task: read the refreshed support dates at start, and fetch new ones every week when an administrator asked for that.
pub async fn run(store: std::sync::Arc<dyn Store>) {
    let s = store.clone();
    let _ = tokio::task::spawn_blocking(move || reload(&*s)).await;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    loop {
        tick.tick().await;
        let s = store.clone();
        let done = tokio::task::spawn_blocking(move || -> Result<Option<(usize, Vec<String>)>> {
            if !settings(&*s).refresh_eol {
                return Ok(None);
            }
            let now = crate::model::now_ts();
            let last = s.get_setting(OVERLAY_KEY)?.and_then(|b| serde_json::from_slice::<Overlay>(&b).ok()).map_or(0, |o| o.fetched_at);
            if now - last < 7 * 86_400 {
                return Ok(None);
            }
            refresh_now(&*s, EOL_URL, now).map(Some)
        })
        .await;
        match done {
            Ok(Ok(Some((n, failed)))) => tracing::info!("support dates refreshed for {n} products{}", if failed.is_empty() { String::new() } else { format!(" ({} failed)", failed.len()) }),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("refreshing support dates failed: {e:#}"),
            Err(e) => tracing::warn!("refreshing support dates failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ver(s: &str) -> Ver {
        Ver::parse(s).unwrap_or_else(|| panic!("{s}"))
    }

    #[test]
    fn the_bundled_data_is_valid_and_has_what_the_findings_need() {
        let d = Intel::bundled().data;
        assert!(days_of(&d.generated).is_some());
        for p in ["nginx", "apache-http-server", "php", "openssl", "exim", "proftpd"] {
            assert!(d.eol.get(p).is_some_and(|c| !c.is_empty()), "{p}");
        }
        assert!(d.kev.len() >= 5 && d.kev.iter().all(|k| k.cve.starts_with("CVE-") && !k.ranges.is_empty() && days_of(&k.added).is_some()));
        // every range parses, and every product a range names is one a banner can give
        for k in &d.kev {
            for r in &k.ranges {
                for v in [&r.exact, &r.from, &r.to].into_iter().flatten() {
                    assert!(Ver::parse(v).is_some(), "{} {v}", k.cve);
                }
            }
        }
        // EPSS and ICS advisories both round-trip through the real, bundled file
        assert!(!d.epss.is_empty() && d.epss.values().all(|s| (0.0..=1.0).contains(s)));
        assert!(!d.ics.is_empty() && d.ics.iter().all(|a| a.id.starts_with("ICSA-") && !a.vendor.is_empty() && days_of(&a.published).is_some()));
    }

    #[test]
    fn versions_compare_the_way_people_expect() {
        assert!(ver("2.4.49") < ver("2.4.50") && ver("2.4.9") < ver("2.4.10"), "numbers, not text");
        assert!(ver("1.0.1") < ver("1.0.1f") && ver("1.0.1e") < ver("1.0.1f") && ver("1.0.1f") < ver("1.0.2"), "OpenSSL's letters");
        assert_eq!(ver("9.6p1"), ver("9.6"), "the portable-release suffix is the same release");
        assert_eq!(ver("4.9"), ver("4.9.0"), "missing parts are zero");
        assert_eq!(ver("1.0.2k-fips"), ver("1.0.2k-fips"));
        assert!(ver("7.4p1") < ver("8.0") && ver("8.9p1") > ver("8.8"));
        assert_eq!(ver("1.0.1:beta1"), ver("1.0.1"), "NVD's update field is not part of the comparison");
        for bad in ["", "abc", ".", "x1.2"] {
            assert!(Ver::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn ranges_include_and_exclude_their_ends() {
        let r = |from: Option<&str>, fi: bool, to: Option<&str>, ti: bool| Range { exact: None, from: from.map(String::from), from_incl: fi, to: to.map(String::from), to_incl: ti };
        let apache = r(Some("2.4.17"), true, Some("2.4.38"), true);
        assert!(apache.contains(&ver("2.4.17")) && apache.contains(&ver("2.4.38")) && apache.contains(&ver("2.4.30")));
        assert!(!apache.contains(&ver("2.4.16")) && !apache.contains(&ver("2.4.39")));
        let before = r(None, false, Some("4.70"), false);
        assert!(before.contains(&ver("4.69")) && !before.contains(&ver("4.70")) && !before.contains(&ver("4.71")));
        let exact = Range { exact: Some("2.4.49".into()), from: None, from_incl: false, to: None, to_incl: false };
        assert!(exact.contains(&ver("2.4.49")) && !exact.contains(&ver("2.4.50")));
        assert!(!r(None, false, None, false).contains(&ver("1.0")), "a range with no bounds says nothing");
    }

    fn intel_with(eol: &[(&str, &[(&str, Eol)])], kev: Vec<Kev>) -> Intel {
        Intel {
            data: Data {
                generated: "2026-01-01".into(),
                kev_catalog_version: None,
                eol: eol.iter().map(|(p, cs)| (p.to_string(), cs.iter().map(|(c, e)| Cycle { cycle: c.to_string(), eol: e.clone(), latest: None }).collect())).collect(),
                kev,
                epss: BTreeMap::new(),
                ics: Vec::new(),
            },
            refreshed_at: None,
        }
    }

    fn day(s: &str) -> i64 {
        days_of(s).unwrap()
    }

    #[test]
    fn support_dates_are_matched_by_the_longest_release_that_fits_and_say_when_it_ended_or_will() {
        let i = intel_with(
            &[("openssl", &[("3.0", Eol::Date("2026-09-07".into())), ("1.1.1", Eol::Date("2023-09-11".into())), ("1.1", Eol::Date("2019-09-11".into()))]), ("nginx", &[("1.28", Eol::Date("2026-04-14".into())), ("1.30", Eol::Flag(false)), ("1.20", Eol::Flag(true))])],
            vec![],
        );
        let today = day("2026-09-21");
        let e = i.eol("openssl", "1.1.1w", today).unwrap();
        assert_eq!((e.cycle.as_str(), e.state, e.date.as_deref()), ("1.1.1", "ended", Some("2023-09-11")), "1.1.1 wins over 1.1");
        assert_eq!(i.eol("openssl", "3.0.13", today).unwrap().state, "ended", "ended two weeks ago");
        assert_eq!(i.eol("openssl", "3.0.13", day("2026-08-01")).map(|e| (e.state, e.days_left)), Some(("soon", Some(37))), "within 90 days");
        assert_eq!(i.eol("openssl", "3.0.13", day("2026-01-01")), None, "far away: not a finding");
        assert_eq!(i.eol("nginx", "1.30.2", today), None, "supported");
        assert_eq!(i.eol("nginx", "1.20.1", today).map(|e| (e.state, e.date)), Some(("ended", None)), "ended, date unknown");
        assert_eq!(i.eol("nginx", "1.28.3", today).unwrap().state, "ended");
        // what is not known is not claimed
        assert_eq!(i.eol("nginx", "1.99.0", today), None, "a release the source does not list");
        assert_eq!(i.eol("nginx", "not-a-version", today), None);
        assert_eq!(i.eol("lighttpd", "1.4.55", today), None, "a product with no support dates");
    }

    #[test]
    fn a_known_exploited_vulnerability_needs_the_version_to_be_in_its_range() {
        let k = |cve: &str, product: &str, ranges: Vec<Range>| Kev { cve: cve.into(), name: format!("{cve} name"), added: "2021-11-03".into(), product: product.into(), ranges, ransomware: false };
        let exact = |v: &str| Range { exact: Some(v.into()), from: None, from_incl: false, to: None, to_incl: false };
        let i = intel_with(&[], vec![k("CVE-2021-41773", "apache-http-server", vec![exact("2.4.49")]), k("CVE-2019-10149", "exim", vec![Range { exact: None, from: Some("4.87".into()), from_incl: true, to: Some("4.91".into()), to_incl: true }])]);
        assert_eq!(i.kev("apache-http-server", "2.4.49").len(), 1);
        assert!(i.kev("apache-http-server", "2.4.51").is_empty() && i.kev("nginx", "2.4.49").is_empty(), "another version, another product");
        assert_eq!(i.kev("exim", "4.90").len(), 1);
        assert!(i.kev("exim", "4.94.2").is_empty());
        // the evidence says whether a distribution may have patched it
        let sw = |product: &'static str, version: &str, distro: bool| Software { product, version: version.into(), source: "http", distro };
        let ev = evidence_for(7, &[sw("apache-http-server", "2.4.49", true), sw("exim", "4.94.2", false)], &i, day("2026-09-21"));
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].kind, ev[0].cve.as_deref(), ev[0].backport, ev[0].asset_id, ev[0].product), ("kev", Some("CVE-2021-41773"), true, 7, "Apache HTTP Server"));
    }

    #[test]
    fn a_refresh_is_validated_kept_beside_the_bundled_data_and_only_used_when_newer() {
        assert!(parse_product(b"not json").is_err() && parse_product(b"{}").is_err() && parse_product(b"[]").is_err());
        let good = br#"[{"cycle":"1.28","releaseDate":"2025-04-23","eol":"2026-04-14","latest":"1.28.3"},{"cycle":"1.30","eol":false},{"cycle":"weird","eol":"2020-01-01"},{"cycle":"1.9","eol":"nonsense"},{"cycle":1.7,"eol":true}]"#;
        let c = parse_product(good).unwrap();
        assert_eq!(c.iter().map(|c| c.cycle.as_str()).collect::<Vec<_>>(), vec!["1.28", "1.30", "1.7"], "unparseable releases are skipped");
        let store = crate::store::sqlite::SqliteStore::open_in_memory().unwrap();
        assert_eq!(Intel::load(&store).refreshed_at, None);
        let overlay = Overlay { fetched_at: 4_000_000_000, eol: [("nginx".to_string(), c.clone())].into_iter().collect() };
        store.set_setting(OVERLAY_KEY, &serde_json::to_vec(&overlay).unwrap(), 1).unwrap();
        let i = Intel::load(&store);
        assert_eq!(i.refreshed_at, Some(4_000_000_000));
        assert_eq!(i.data.eol["nginx"], c, "the refreshed dates replace the bundled ones for that product");
        assert!(i.data.eol.contains_key("php"), "and the others stay");
        // dates older than the bundled data do not win
        let stale = Overlay { fetched_at: 1_000_000, eol: overlay.eol.clone() };
        store.set_setting(OVERLAY_KEY, &serde_json::to_vec(&stale).unwrap(), 1).unwrap();
        assert_eq!(Intel::load(&store).refreshed_at, None);
    }

    #[test]
    fn refreshing_fetches_each_product_and_reports_the_ones_that_failed() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in l.incoming().take(3) {
                let mut s = stream.unwrap();
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, body) = if req.contains("/api/nginx.json") { ("200 OK", r#"[{"cycle":"1.28","eol":"2026-04-14"}]"#) } else if req.contains("/api/php.json") { ("200 OK", r#"<html>a captive portal</html>"#) } else { ("404 Not Found", "{}") };
                let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        let store = crate::store::sqlite::SqliteStore::open_in_memory().unwrap();
        let (n, failed) = refresh_now_for(&store, &base, &["nginx", "php", "exim"], 4_100_000_000).unwrap();
        assert_eq!(n, 1);
        assert_eq!(failed.len(), 2, "{failed:?}");
        assert!(failed.iter().any(|f| f.starts_with("php:")) && failed.iter().any(|f| f.starts_with("exim:")));
        let i = Intel::load(&store);
        assert_eq!(i.refreshed_at, Some(4_100_000_000));
        assert_eq!(i.data.eol["nginx"][0].cycle, "1.28");
    }

    /// `refresh_now` for a chosen set of products (the test cannot hit the real site).
    fn refresh_now_for(store: &dyn Store, base: &str, products: &[&str], now: i64) -> Result<(usize, Vec<String>)> {
        let (overlay, failed) = fetch_overlay(base, products, now)?;
        let n = overlay.eol.len();
        store.set_setting(OVERLAY_KEY, &serde_json::to_vec(&overlay)?, now)?;
        Ok((n, failed))
    }

    #[test]
    fn dates_are_read_correctly() {
        assert_eq!(days_of("1970-01-01"), Some(0));
        assert_eq!(days_of("2000-03-01"), Some(11_017));
        assert_eq!(days_of("2026-09-21T10:00:00Z"), days_of("2026-09-21"));
        assert!(days_of("2026-13-01").is_none() && days_of("x").is_none() && days_of("").is_none());
        assert_eq!(day("2026-09-22") - day("2026-09-21"), 1);
        assert_eq!(day("2028-03-01") - day("2028-02-28"), 2, "a leap year");
    }

    fn intel_with_ics(ics: Vec<IcsAdvisory>) -> Intel {
        Intel { data: Data { generated: "2026-01-01".into(), kev_catalog_version: None, eol: BTreeMap::new(), kev: Vec::new(), epss: BTreeMap::new(), ics }, refreshed_at: None }
    }

    fn advisory(vendor: &str) -> IcsAdvisory {
        IcsAdvisory { id: "ICSA-24-001-01".into(), title: "A PLC vulnerability".into(), vendor: vendor.into(), published: "2026-01-01".into(), cves: vec!["CVE-2026-0001".into()] }
    }

    #[test]
    fn ics_advisories_match_by_vendor_only_case_insensitively_either_direction() {
        let i = intel_with_ics(vec![advisory("Siemens")]);
        assert_eq!(i.ics("Siemens AG").len(), 1, "a longer device vendor string contains the advisory's shorter one");
        assert_eq!(i.ics("SIEMENS").len(), 1, "case-insensitive");
        assert_eq!(i.ics("Rockwell Automation").len(), 0);
        assert_eq!(i.ics("").len(), 0, "an empty vendor never matches anything");
    }

    #[test]
    fn ics_evidence_never_claims_a_version_and_carries_the_advisory_id() {
        let i = intel_with_ics(vec![advisory("Schneider Electric")]);
        let ev = ics_evidence_for(7, Some("Schneider Electric Industries"), &i);
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].asset_id, ev[0].kind, ev[0].version.as_str(), ev[0].advisory_id.as_deref(), ev[0].cve.as_deref()), (7, "ics", "", Some("ICSA-24-001-01"), Some("CVE-2026-0001")));
        assert!(ics_evidence_for(7, None, &i).is_empty());
        assert!(ics_evidence_for(7, Some("Unrelated Corp"), &i).is_empty());
    }

    #[test]
    fn epss_enriches_kev_evidence_when_known_and_is_absent_otherwise() {
        let kev = Kev { cve: "CVE-2026-0002".into(), name: "test".into(), added: "2026-01-01".into(), product: "nginx".to_string(), ranges: vec![Range { exact: Some("1.0.0".into()), from: None, from_incl: false, to: None, to_incl: false }], ransomware: false };
        let mut epss = BTreeMap::new();
        epss.insert("CVE-2026-0002".to_string(), 0.87);
        let i = Intel { data: Data { generated: "2026-01-01".into(), kev_catalog_version: None, eol: BTreeMap::new(), kev: vec![kev], epss, ics: Vec::new() }, refreshed_at: None };
        let sw = [Software { product: "nginx", version: "1.0.0".into(), source: "http", distro: false }];
        let ev = evidence_for(1, &sw, &i, 0);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].epss, Some(0.87));
        assert_eq!(i.epss("CVE-nope"), None);
    }
}
