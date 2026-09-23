//! Backups of the database, taken by hand or on a schedule, kept in the `backups` folder
//! next to it and downloadable from the console (administrators only: a backup holds
//! everything, including password hashes).
//!
//! The updater keeps its own `denis-before-<version>-…` backups in the same folder; they are
//! listed here but pruned by the updater, not by the schedule.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::engine::Shared;
use crate::store::Store;

pub const SETTINGS_KEY: &str = "backups";
pub const MAX_KEEP: u32 = 60;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// `off`, `every8h`, `every12h`, `daily` or `weekly`.
    pub schedule: String,
    /// How many scheduled backups to keep (older ones are removed; manual and update backups are not).
    pub keep: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { schedule: "daily".into(), keep: 7 }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(self.schedule.as_str(), "off" | "every8h" | "every12h" | "daily" | "weekly") {
            return Err("schedule must be off, every8h, every12h, daily or weekly");
        }
        if !(1..=MAX_KEEP).contains(&self.keep) {
            return Err("keep must be between 1 and 60");
        }
        Ok(())
    }

    pub fn interval(&self) -> Option<i64> {
        schedule_interval(&self.schedule)
    }
}

pub fn load(store: &dyn Store) -> Result<Settings> {
    Ok(match store.get_setting(SETTINGS_KEY)? {
        Some(b) => serde_json::from_slice(&b).ok().filter(|s: &Settings| s.validate().is_ok()).unwrap_or_default(),
        None => Settings::default(),
    })
}

pub fn save(store: &dyn Store, s: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(s)?, now)
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BackupFile {
    pub name: String,
    /// `auto`, `manual` or `update`.
    pub kind: &'static str,
    pub size: u64,
    /// Unix seconds.
    pub modified: i64,
}

pub fn dir(db_path: &Path) -> PathBuf {
    crate::update::backups_dir(db_path)
}

fn kind_of(name: &str) -> Option<&'static str> {
    // the name is what we made ourselves: a fixed prefix, then a stamp or a version, then `.db`
    let ok_chars = name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    if !ok_chars || name.contains("..") || !name.ends_with(".db") {
        return None;
    }
    if name.starts_with("denis-auto-") {
        Some("auto")
    } else if name.starts_with("denis-manual-") {
        Some("manual")
    } else if name.starts_with("denis-before-") {
        Some("update")
    } else {
        None
    }
}

/// Newest first.
pub fn list(db_path: &Path) -> Vec<BackupFile> {
    let Ok(rd) = std::fs::read_dir(dir(db_path)) else { return Vec::new() };
    let mut out: Vec<BackupFile> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let kind = kind_of(&name)?;
            let meta = e.metadata().ok().filter(|m| m.is_file())?;
            let modified = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
            Some(BackupFile { name, kind, size: meta.len(), modified })
        })
        .collect();
    out.sort_by(|a, b| b.modified.cmp(&a.modified).then(b.name.cmp(&a.name)));
    out
}

/// The path of one of our backup files, or `None` if the name is not one (this is what stops `../` tricks).
pub fn path_of(db_path: &Path, name: &str) -> Option<PathBuf> {
    kind_of(name)?;
    let p = dir(db_path).join(name);
    p.is_file().then_some(p)
}

/// Make a backup now (`kind` is `auto` or `manual`). Refuses when the disk could not hold it.
pub fn create(store: &dyn Store, db_path: &Path, kind: &str, now: i64) -> Result<BackupFile> {
    let d = dir(db_path);
    std::fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
    let need = store.stats(false)?.db_bytes.max(0) as u64;
    if let Some((free, _)) = crate::health::disk_space(&d) {
        if free < need.saturating_mul(2) {
            anyhow::bail!("not enough free disk space for a backup ({} free, about {} needed)", crate::health::human_bytes(free), crate::health::human_bytes(need));
        }
    }
    let stamp = crate::report::iso(now).replace(['-', ':'], "");
    let mut name = format!("denis-{kind}-{stamp}.db");
    let mut n = 1;
    while d.join(&name).exists() {
        n += 1;
        name = format!("denis-{kind}-{stamp}-{n}.db");
    }
    store.backup_to(&d.join(&name))?;
    let size = std::fs::metadata(d.join(&name))?.len();
    Ok(BackupFile { name, kind: if kind == "auto" { "auto" } else { "manual" }, size, modified: now })
}

/// Remove the oldest scheduled backups beyond `keep`.
pub fn prune_auto(db_path: &Path, keep: usize) -> usize {
    let mut removed = 0;
    for old in list(db_path).into_iter().filter(|b| b.kind == "auto").skip(keep) {
        if std::fs::remove_file(dir(db_path).join(&old.name)).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// When the newest backup of any kind was made.
pub fn latest(db_path: &Path) -> Option<i64> {
    list(db_path).first().map(|b| b.modified)
}

pub fn is_due(s: &Settings, last_scheduled: Option<i64>, now: i64) -> bool {
    due_by(s.interval(), last_scheduled, now)
}

/// The same rule `is_due` applies, generalised to any interval — used for the independent
/// upload-to-MSP schedule below, and for the "off"/"manual" case (`interval = None`, never due).
fn due_by(interval: Option<i64>, last: Option<i64>, now: i64) -> bool {
    interval.is_some_and(|every| last.is_none_or(|t| now - t >= every))
}

fn schedule_interval(schedule: &str) -> Option<i64> {
    match schedule {
        "every8h" => Some(8 * 3600),
        "every12h" => Some(12 * 3600),
        "daily" => Some(86_400),
        "weekly" => Some(7 * 86_400),
        _ => None, // "off" / "manual"
    }
}

/// How often an install's own scheduled backups are also pushed to an MSP (`--backup-upstream`),
/// independent of how often a local backup is made above: a customer might make local backups
/// daily but only push a subset upstream, say. Whatever the newest local backup is at the moment
/// this is due, that is what gets sent — this never triggers a new backup by itself.
pub const UPLOAD_SETTINGS_KEY: &str = "backups.upload_schedule";
const UPLOAD_LAST_KEY: &str = "backups.upload_last";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UploadSettings {
    /// `manual`, `every8h`, `every12h`, `daily` or `weekly`. "manual" never auto-uploads — use
    /// the "Upload now" button instead (or none at all, if `--backup-upstream` is not set).
    pub schedule: String,
}

impl Default for UploadSettings {
    fn default() -> Self {
        // Matches the *previous* behaviour for anyone still on the (also daily-by-default) local
        // schedule: upgrading changes nothing for a default install.
        UploadSettings { schedule: "daily".into() }
    }
}

impl UploadSettings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(self.schedule.as_str(), "manual" | "every8h" | "every12h" | "daily" | "weekly") {
            return Err("schedule must be manual, every8h, every12h, daily or weekly");
        }
        Ok(())
    }

    pub fn interval(&self) -> Option<i64> {
        schedule_interval(&self.schedule)
    }
}

pub fn load_upload_settings(store: &dyn Store) -> Result<UploadSettings> {
    Ok(match store.get_setting(UPLOAD_SETTINGS_KEY)? {
        Some(b) => serde_json::from_slice(&b).ok().filter(|s: &UploadSettings| s.validate().is_ok()).unwrap_or_default(),
        None => UploadSettings::default(),
    })
}

pub fn save_upload_settings(store: &dyn Store, s: &UploadSettings, now: i64) -> Result<()> {
    store.set_setting(UPLOAD_SETTINGS_KEY, &serde_json::to_vec(s)?, now)
}

fn last_upload(store: &dyn Store) -> Option<i64> {
    store.get_setting(UPLOAD_LAST_KEY).ok().flatten().and_then(|b| std::str::from_utf8(&b).ok()?.parse().ok())
}

fn set_last_upload(store: &dyn Store, now: i64) {
    let _ = store.set_setting(UPLOAD_LAST_KEY, now.to_string().as_bytes(), now);
}

/// How many of a given customer's uploaded backups an MSP keeps under
/// `backups/from-agents/<agent-id>/` (the oldest are pruned after each new one arrives). This is
/// the MSP's own, purely local setting — it does not reach back to the customer in any way.
pub const AGENT_KEEP_KEY: &str = "backups.keep_per_agent";
pub const DEFAULT_AGENT_KEEP: u32 = 10;

pub fn load_agent_keep(store: &dyn Store) -> u32 {
    store
        .get_setting(AGENT_KEEP_KEY)
        .ok()
        .flatten()
        .and_then(|b| std::str::from_utf8(&b).ok()?.parse::<u32>().ok())
        .filter(|n| (1..=MAX_KEEP).contains(n))
        .unwrap_or(DEFAULT_AGENT_KEEP)
}

pub fn save_agent_keep(store: &dyn Store, keep: u32, now: i64) -> Result<()> {
    anyhow::ensure!((1..=MAX_KEEP).contains(&keep), "keep must be between 1 and {MAX_KEEP}");
    store.set_setting(AGENT_KEEP_KEY, keep.to_string().as_bytes(), now)
}

/// Prune a single customer's uploaded-backups folder down to `keep`, newest first.
pub fn prune_agent_dir(dir: &Path, keep: usize) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let meta = e.metadata().ok().filter(|m| m.is_file())?;
            Some((meta.modified().ok()?, e.path()))
        })
        .collect();
    files.sort_by_key(|(m, _)| std::cmp::Reverse(*m));
    files.into_iter().skip(keep).filter(|(_, p)| std::fs::remove_file(p).is_ok()).count()
}

/// Where an MSP receives this install's own scheduled backups (`--backup-upstream`): outbound
/// push only, the same trust model as an agent reporting to a master. The MSP keeps them so they
/// still have yesterday's device list if this install is ever hit by ransomware.
#[derive(Clone)]
pub struct Upstream {
    /// The MSP's base URL, e.g. `https://msp.example.com:9000`.
    pub url: String,
    /// A token issued by the MSP for this install (`denis agent-token issue`), read once from an
    /// environment variable at start-up — never logged, never stored.
    pub token: String,
}

fn http_client() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(60))).http_status_as_error(false).build().into()
}

/// Send one backup file's bytes to the MSP. The local backup already exists and is kept either
/// way: a failed upload is logged and retried at the next scheduled backup, never fatal.
fn upload(upstream: &Upstream, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let endpoint = format!("{}/api/v1/backup", upstream.url.trim_end_matches('/'));
    let resp = http_client()
        .post(&endpoint)
        .header("Authorization", format!("Bearer {}", upstream.token))
        .header("Content-Type", "application/octet-stream")
        .send(&bytes)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let code = resp.status().as_u16();
    anyhow::ensure!((200..300).contains(&code), "the MSP refused the backup (HTTP {code}): check --backup-upstream and the token");
    Ok(())
}

/// Background task: take the scheduled backup when it is due, and push it upstream if configured.
pub async fn run(store: std::sync::Arc<dyn Store>, shared: std::sync::Arc<Shared>, upstream: Option<Upstream>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(900));
    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    loop {
        tick.tick().await;
        let (s, sh) = (store.clone(), shared.clone());
        let done = tokio::task::spawn_blocking(move || -> Result<Option<BackupFile>> {
            let settings = load(&*s)?;
            let last = list(&sh.db_path).iter().filter(|b| b.kind == "auto").map(|b| b.modified).max();
            let now = crate::model::now_ts();
            if !is_due(&settings, last, now) {
                return Ok(None);
            }
            let made = create(&*s, &sh.db_path, "auto", now)?;
            prune_auto(&sh.db_path, settings.keep as usize);
            Ok(Some(made))
        })
        .await;
        match done {
            Ok(Ok(Some(b))) => tracing::info!("scheduled backup written: {} ({})", b.name, crate::health::human_bytes(b.size)),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("scheduled backup failed: {e:#}"),
            Err(e) => tracing::warn!("scheduled backup task failed: {e}"),
        }

        // Independent of whether a *new* local backup was just made above: on its own schedule,
        // push whatever the newest local backup happens to be right now.
        let Some(up) = upstream.clone() else { continue };
        let (s, sh) = (store.clone(), shared.clone());
        let due = tokio::task::spawn_blocking(move || -> Result<Option<PathBuf>> {
            let up_settings = load_upload_settings(&*s)?;
            let now = crate::model::now_ts();
            if !due_by(up_settings.interval(), last_upload(&*s), now) {
                return Ok(None);
            }
            let Some(newest) = list(&sh.db_path).into_iter().next() else { return Ok(None) };
            set_last_upload(&*s, now);
            Ok(Some(dir(&sh.db_path).join(newest.name)))
        })
        .await;
        match due {
            Ok(Ok(Some(path))) => {
                let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                match tokio::task::spawn_blocking(move || upload(&up, &path)).await {
                    Ok(Ok(())) => tracing::info!("backup {name} sent to the MSP"),
                    Ok(Err(e)) => tracing::warn!("could not send backup {name} to the MSP: {e:#}"),
                    Err(e) => tracing::warn!("backup upload task failed: {e}"),
                }
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("checking the backup upload schedule failed: {e:#}"),
            Err(e) => tracing::warn!("backup upload check task failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn only_our_own_backup_names_are_accepted() {
        for ok in ["denis-auto-20260921T100000Z.db", "denis-manual-x.db", "denis-before-0.4.0-rc.1-20260101.db"] {
            assert!(kind_of(ok).is_some(), "{ok}");
        }
        for bad in ["../denis-auto-x.db", "denis-auto-../x.db", "denis-auto-x.db/../../etc/passwd", "denis-auto-x.sqlite", "other.db", "denis-auto-x db.db", "", "denis-auto-\u{0}.db", "/etc/passwd"] {
            assert!(kind_of(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_backup_is_made_listed_pruned_and_found_by_name_only() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("denis.db");
        let store = SqliteStore::open(&db).unwrap();
        let a = create(&store, &db, "auto", 1_000).unwrap();
        let b = create(&store, &db, "auto", 1_000).unwrap();
        assert_ne!(a.name, b.name, "two in the same second do not collide");
        let m = create(&store, &db, "manual", 1_000).unwrap();
        assert!(a.size > 0 && b.size > 0);
        assert_eq!(list(&db).len(), 3);
        assert!(path_of(&db, &m.name).is_some());
        assert!(path_of(&db, "../denis.db").is_none());
        assert!(path_of(&db, "denis-auto-nothing.db").is_none());
        // only scheduled backups are pruned
        assert_eq!(prune_auto(&db, 1), 1);
        let left = list(&db);
        assert_eq!((left.len(), left.iter().filter(|x| x.kind == "manual").count()), (2, 1));
    }

    #[test]
    fn the_schedule_is_due_after_its_interval_and_validated() {
        let d = Settings::default();
        assert!(is_due(&d, None, 10));
        assert!(!is_due(&d, Some(0), 86_399));
        assert!(is_due(&d, Some(0), 86_400));
        assert!(!is_due(&Settings { schedule: "off".into(), keep: 3 }, None, 10));
        assert!(Settings { schedule: "hourly".into(), keep: 3 }.validate().is_err());
        assert!(Settings { schedule: "daily".into(), keep: 0 }.validate().is_err());
        assert!(Settings { schedule: "daily".into(), keep: 61 }.validate().is_err());
        assert!(Settings { schedule: "every8h".into(), keep: 3 }.validate().is_ok());
        assert!(Settings { schedule: "every12h".into(), keep: 3 }.validate().is_ok());
    }

    #[test]
    fn upload_settings_round_trip_and_are_independent_of_the_local_schedule() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(load_upload_settings(&store).unwrap(), UploadSettings::default());
        let s = UploadSettings { schedule: "every8h".into() };
        save_upload_settings(&store, &s, 1).unwrap();
        assert_eq!(load_upload_settings(&store).unwrap(), s);
        assert_eq!(s.interval(), Some(8 * 3600));

        assert!(UploadSettings { schedule: "hourly".into() }.validate().is_err());
        assert!(UploadSettings { schedule: "manual".into() }.validate().is_ok());
        assert_eq!(UploadSettings { schedule: "manual".into() }.interval(), None);

        // a garbled/invalid stored value falls back to the default rather than erroring
        store.set_setting(UPLOAD_SETTINGS_KEY, b"not json", 2).unwrap();
        assert_eq!(load_upload_settings(&store).unwrap(), UploadSettings::default());
    }

    #[test]
    fn a_customers_uploaded_backups_are_pruned_to_the_configured_keep_count() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(load_agent_keep(&store), DEFAULT_AGENT_KEEP);
        save_agent_keep(&store, 2, 1).unwrap();
        assert_eq!(load_agent_keep(&store), 2);
        assert!(save_agent_keep(&store, 0, 1).is_err());
        assert!(save_agent_keep(&store, MAX_KEEP + 1, 1).is_err());

        let tmp = tempfile::tempdir().unwrap();
        for i in 0..5u32 {
            std::fs::write(tmp.path().join(format!("denis-auto-{i}.db")), b"x").unwrap();
            // distinct mtimes, oldest first, so pruning keeps a predictable "newest 2"
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let removed = prune_agent_dir(tmp.path(), 2);
        assert_eq!(removed, 3);
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 2);
    }
}
