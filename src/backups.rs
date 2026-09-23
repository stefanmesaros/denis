//! Backups of the database, taken by hand or on a schedule, kept in the `backups` folder
//! next to it and downloadable from the console (administrators only: a backup holds
//! everything, including password hashes).
//!
//! The updater keeps its own `denis-before-<version>-…` backups in the same folder; they are
//! listed here but pruned by the updater, not by the schedule.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::store::{Store};

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

fn list_in(folder: &Path) -> Vec<BackupFile> {
    let Ok(rd) = std::fs::read_dir(folder) else { return Vec::new() };
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

/// Newest first.
pub fn list(db_path: &Path) -> Vec<BackupFile> {
    list_in(&dir(db_path))
}

/// The path of one of our backup files, or `None` if the name is not one (this is what stops `../` tricks).
pub fn path_of(db_path: &Path, name: &str) -> Option<PathBuf> {
    kind_of(name)?;
    let p = dir(db_path).join(name);
    p.is_file().then_some(p)
}

/// Where an MSP keeps every customer's uploaded backups (`--backup-upstream` on their side), one
/// subfolder per agent id, next to this install's own `backups` folder.
pub fn agents_dir(db_path: &Path) -> PathBuf {
    dir(db_path).join("from-agents")
}

fn agent_id_ok(agent_id: &str) -> bool {
    !agent_id.is_empty() && agent_id.len() <= 64 && agent_id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// One customer's uploaded backups, newest first (empty if that id has never uploaded one, or the
/// id itself is not a valid one — this is what stops `../` tricks in the id).
pub fn list_agent_backups(db_path: &Path, agent_id: &str) -> Vec<BackupFile> {
    if !agent_id_ok(agent_id) {
        return Vec::new();
    }
    list_in(&agents_dir(db_path).join(agent_id))
}

/// Every customer id that has ever uploaded a backup here.
pub fn agent_ids_with_backups(db_path: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(agents_dir(db_path)) else { return Vec::new() };
    let mut ids: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|id| agent_id_ok(id))
        .collect();
    ids.sort();
    ids
}

/// The path of one customer's backup file, or `None` if the id or name is not one of ours (this
/// is what stops `../` tricks in either component).
pub fn path_of_agent(db_path: &Path, agent_id: &str, name: &str) -> Option<PathBuf> {
    if !agent_id_ok(agent_id) {
        return None;
    }
    kind_of(name)?;
    let p = agents_dir(db_path).join(agent_id).join(name);
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

/// One upload-schedule check: sends the newest local backup if the upload schedule is due.
/// Returns the file's name and the send's own result, or `None` when nothing was due. The
/// schedule slot (`UPLOAD_LAST_KEY`) is only consumed on a *successful* send — an MSP that is
/// down, or a bad token, must not silently cost a whole schedule interval; the next tick (the
/// loop calling this checks every 15 minutes, regardless of the schedule itself) tries again.
fn upload_if_due(store: &dyn Store, db_path: &Path, upstream: &Upstream, now: i64) -> Result<Option<(String, Result<()>)>> {
    let up_settings = load_upload_settings(store)?;
    if !due_by(up_settings.interval(), last_upload(store), now) {
        return Ok(None);
    }
    let Some(newest) = list(db_path).into_iter().next() else { return Ok(None) };
    let path = dir(db_path).join(&newest.name);
    let result = upload(upstream, &path);
    if result.is_ok() {
        set_last_upload(store, now);
    }
    Ok(Some((newest.name, result)))
}

/// Background task: take the scheduled backup when it is due, and push it upstream if configured.
pub async fn run(store: std::sync::Arc<dyn Store>, db_path: PathBuf, upstream: Option<Upstream>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(900));
    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    loop {
        tick.tick().await;
        let (s, sh) = (store.clone(), db_path.clone());
        let done = tokio::task::spawn_blocking(move || -> Result<Option<BackupFile>> {
            let settings = load(&*s)?;
            let last = list(&sh).iter().filter(|b| b.kind == "auto").map(|b| b.modified).max();
            let now = crate::model::now_ts();
            if !is_due(&settings, last, now) {
                return Ok(None);
            }
            let made = create(&*s, &sh, "auto", now)?;
            prune_auto(&sh, settings.keep as usize);
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
        let (s, sh) = (store.clone(), db_path.clone());
        let now = crate::model::now_ts();
        match tokio::task::spawn_blocking(move || upload_if_due(&*s, &sh, &up, now)).await {
            Ok(Ok(Some((name, Ok(()))))) => tracing::info!("backup {name} sent to the MSP"),
            Ok(Ok(Some((name, Err(e))))) => tracing::warn!("could not send backup {name} to the MSP: {e:#}"),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!("checking the backup upload schedule failed: {e:#}"),
            Err(e) => tracing::warn!("backup upload task failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SettingsStore;
    use crate::store::sqlite::SqliteStore;
    use std::sync::Arc;

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

    /// A tiny fake MSP: answers every request with whatever status `code` currently holds.
    struct Fake {
        url: String,
        code: Arc<std::sync::atomic::AtomicU16>,
    }

    fn fake() -> Fake {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicU16, Ordering};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let code = Arc::new(AtomicU16::new(200));
        let c2 = code.clone();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut c) = conn else { return };
                // Drain the whole request (headers, then exactly `content-length` body bytes)
                // before answering: an early reply while the client is still writing the backup
                // file's body would abort the connection instead of exercising the real
                // success/failure path this test cares about.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (head_end, len) = loop {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                        let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0usize);
                        break (p + 4, len);
                    }
                };
                while buf.len() < head_end + len {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let code = c2.load(Ordering::SeqCst);
                let _ = write!(c, "HTTP/1.1 {code} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
            }
        });
        Fake { url, code }
    }

    #[test]
    fn a_failed_upload_does_not_consume_the_schedule_slot_so_the_next_tick_retries() {
        use std::sync::atomic::Ordering;
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("denis.db");
        let store = SqliteStore::open(&db).unwrap();
        create(&store, &db, "auto", 1_000).unwrap();
        let f = fake();
        let up = Upstream { url: f.url.clone(), token: "t".into() };
        save_upload_settings(&store, &UploadSettings { schedule: "daily".into() }, 1_000).unwrap();

        // the MSP is down: nothing is marked, so the very next check is still due
        f.code.store(500, Ordering::SeqCst);
        let (name, result) = upload_if_due(&store, &db, &up, 2_000).unwrap().expect("a backup exists and the schedule is due");
        assert!(result.is_err());
        assert_eq!(last_upload(&store), None, "a failed send must not consume the schedule slot");
        assert!(upload_if_due(&store, &db, &up, 2_001).unwrap().is_some(), "the next tick retries immediately, not after a full interval");

        // the MSP comes back: the same due check now succeeds and the slot is consumed
        f.code.store(200, Ordering::SeqCst);
        let (name2, result2) = upload_if_due(&store, &db, &up, 2_002).unwrap().unwrap();
        assert_eq!(name2, name);
        assert!(result2.is_ok());
        assert_eq!(last_upload(&store), Some(2_002));
        // and now it is not due again until the next interval
        assert!(upload_if_due(&store, &db, &up, 2_003).unwrap().is_none());
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

    #[test]
    fn a_customers_backups_are_listed_and_found_by_agent_id_and_name_only() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("denis.db");
        assert_eq!(agent_ids_with_backups(&db), Vec::<String>::new());

        let site = agents_dir(&db).join("customer-a");
        std::fs::create_dir_all(&site).unwrap();
        std::fs::write(site.join("denis-auto-x.db"), b"x").unwrap();
        std::fs::write(site.join("not-ours.txt"), b"x").unwrap(); // ignored: not one of our names

        assert_eq!(agent_ids_with_backups(&db), vec!["customer-a".to_string()]);
        let files = list_agent_backups(&db, "customer-a");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "denis-auto-x.db");
        assert!(list_agent_backups(&db, "does-not-exist").is_empty());
        assert!(list_agent_backups(&db, "../escape").is_empty(), "a bad id is simply empty, not a panic");

        assert!(path_of_agent(&db, "customer-a", "denis-auto-x.db").is_some());
        assert!(path_of_agent(&db, "customer-a", "not-ours.txt").is_none());
        assert!(path_of_agent(&db, "../escape", "denis-auto-x.db").is_none());
        assert!(path_of_agent(&db, "customer-a", "../../denis.db").is_none());
    }
}
