//! The Health page: is DENIS itself in good shape? Packet drops, database size, free disk,
//! how late the sweeps are, and whether there is a recent backup, with a plain sentence for
//! each thing that is wrong.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::Result;
use serde::Serialize;

use crate::backups;
use crate::store::Store;

/// The little slice of the running collector's status this page needs — defined here, not in
/// `engine`, so this module names what it actually uses instead of depending on the whole of
/// `engine::Shared`. `engine::Shared` implements it.
pub trait StatusSource {
    fn snapshot(&self) -> crate::engine::StatusInfo;
    fn db_path(&self) -> &Path;
    fn capture_stats(&self) -> &crate::capture::CaptureStats;
}

impl<T: StatusSource> StatusSource for std::sync::Arc<T> {
    fn snapshot(&self) -> crate::engine::StatusInfo {
        (**self).snapshot()
    }
    fn db_path(&self) -> &Path {
        (**self).db_path()
    }
    fn capture_stats(&self) -> &crate::capture::CaptureStats {
        (**self).capture_stats()
    }
}

/// Fixed sentences with `{name}` placeholders (translated in the console).
pub const W_CAPTURE_DOWN: &str = "The packet capture is not running, so no new devices or traffic are seen. Look at the service log.";
pub const W_DROPS: &str = "The capture is losing packets ({percent}% of {total}). DENIS may be too slow for this traffic, or the mirror port carries more than one machine can process.";
pub const W_SWEEP_LATE: &str = "The last network sweep finished {age} ago, but one is due every {every}. Look at the service log.";
pub const W_NO_SWEEP: &str = "No network sweep has finished since DENIS started {age} ago.";
pub const W_DISK: &str = "Only {free} of {total} is free on the disk that holds the database. When it is full, DENIS stops recording.";
pub const W_NO_BACKUP: &str = "There is no backup yet. Switch the schedule on, or make one now.";
pub const W_OLD_BACKUP: &str = "The newest backup is {age} old.";

pub fn texts() -> [&'static str; 7] {
    [W_CAPTURE_DOWN, W_DROPS, W_SWEEP_LATE, W_NO_SWEEP, W_DISK, W_NO_BACKUP, W_OLD_BACKUP]
}

#[derive(Debug, Serialize)]
pub struct Warning {
    pub text: &'static str,
    pub vars: BTreeMap<&'static str, String>,
}

#[derive(Debug, Serialize)]
pub struct Health {
    pub version: &'static str,
    pub mode: &'static str,
    pub uptime_secs: i64,
    pub db: crate::store::StoreStats,
    /// Free and total bytes of the disk holding the database.
    pub disk: Option<(u64, u64)>,
    /// `None` when this console has no capture of its own (viewer mode).
    pub capture: Option<CaptureHealth>,
    pub sweep: Option<SweepHealth>,
    pub backups: BackupHealth,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Serialize)]
pub struct CaptureHealth {
    pub running: bool,
    pub received: u64,
    pub dropped: u64,
    pub if_dropped: u64,
    pub drop_percent: f64,
}

#[derive(Debug, Serialize)]
pub struct SweepHealth {
    pub interval_secs: u64,
    pub sweeping: bool,
    pub last_started: Option<i64>,
    pub last_finished: Option<i64>,
    /// How many seconds late the next sweep is (0 = on time).
    pub lag_secs: i64,
}

#[derive(Debug, Serialize)]
pub struct BackupHealth {
    pub schedule: String,
    pub keep: u32,
    pub count: usize,
    pub total_bytes: u64,
    pub latest_at: Option<i64>,
}

/// Free and total bytes of the file system that holds `path` (or its nearest existing parent).
pub fn disk_space(path: &Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut p = path;
        while !p.exists() {
            p = p.parent()?;
        }
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
        let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `c` is a valid NUL-terminated path and `v` a properly sized out-parameter.
        if unsafe { libc::statvfs(c.as_ptr(), &mut v) } != 0 {
            return None;
        }
        let frsize = v.f_frsize as u64;
        Some((v.f_bavail as u64 * frsize, v.f_blocks as u64 * frsize))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

pub fn human_bytes(b: u64) -> String {
    match b {
        b if b >= 1_000_000_000 => format!("{:.1} GB", b as f64 / 1e9),
        b if b >= 1_000_000 => format!("{:.1} MB", b as f64 / 1e6),
        b if b >= 1_000 => format!("{:.0} kB", b as f64 / 1e3),
        b => format!("{b} B"),
    }
}

/// `90` -> "1 minute", `7200` -> "2 hours" (English: it fills a sentence that is translated as a whole).
pub fn human_span(secs: i64) -> String {
    let s = secs.max(0);
    let (n, unit) = if s >= 2 * 86_400 { (s / 86_400, "day") } else if s >= 3600 { (s / 3600, "hour") } else { ((s / 60).max(1), "minute") };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

fn warn(text: &'static str, vars: &[(&'static str, String)]) -> Warning {
    Warning { text, vars: vars.iter().cloned().collect() }
}

pub fn gather(store: &dyn Store, shared: &impl StatusSource, now: i64, with_rows: bool) -> Result<Health> {
    let info = shared.snapshot();
    let db = store.stats(with_rows)?;
    let disk = disk_space(shared.db_path());
    let viewer = info.mode == "viewer";
    let mut warnings = Vec::new();

    let capture = (!viewer).then(|| {
        let c = shared.capture_stats();
        let (received, dropped, if_dropped) = (c.received.load(Ordering::Relaxed), c.dropped.load(Ordering::Relaxed), c.if_dropped.load(Ordering::Relaxed));
        let total = received + dropped;
        let drop_percent = if total == 0 { 0.0 } else { dropped as f64 * 100.0 / total as f64 };
        CaptureHealth { running: c.running.load(Ordering::Relaxed), received, dropped, if_dropped, drop_percent }
    });
    if let Some(c) = &capture {
        if !c.running && now - info.started_at > 30 {
            warnings.push(warn(W_CAPTURE_DOWN, &[]));
        }
        // a handful of drops is normal; a steady share is not
        if c.dropped >= 100 && c.drop_percent >= 1.0 {
            warnings.push(warn(W_DROPS, &[("percent", format!("{:.1}", c.drop_percent)), ("total", (c.received + c.dropped).to_string())]));
        }
    }

    let sweep = (!viewer && !info.passive_only).then(|| {
        let every = info.sweep_interval_secs as i64;
        let since = info.last_sweep_finished.unwrap_or(info.started_at);
        // a sweep that is running counts as on time; a finished one is late after one and a half intervals
        let lag = if info.sweeping { 0 } else { (now - since - every).max(0) };
        SweepHealth { interval_secs: info.sweep_interval_secs, sweeping: info.sweeping, last_started: info.last_sweep_started, last_finished: info.last_sweep_finished, lag_secs: lag }
    });
    if let Some(s) = &sweep {
        let late = s.lag_secs > s.interval_secs as i64 / 2 + 60;
        match (late, s.last_finished) {
            (true, Some(t)) => warnings.push(warn(W_SWEEP_LATE, &[("age", human_span(now - t)), ("every", human_span(s.interval_secs as i64))])),
            (true, None) => warnings.push(warn(W_NO_SWEEP, &[("age", human_span(now - info.started_at))])),
            _ => {}
        }
    }

    if let Some((free, total)) = disk {
        if total > 0 && (free < 1_000_000_000 || free * 10 < total) {
            warnings.push(warn(W_DISK, &[("free", human_bytes(free)), ("total", human_bytes(total))]));
        }
    }

    let settings = backups::load(store)?;
    let files = backups::list(shared.db_path());
    let latest_at = files.first().map(|b| b.modified);
    let backups = BackupHealth {
        schedule: settings.schedule.clone(),
        keep: settings.keep,
        count: files.len(),
        total_bytes: files.iter().map(|b| b.size).sum(),
        latest_at,
    };
    if !viewer {
        // late = older than two intervals (and never less than two days); without a schedule, a month
        let limit = settings.interval().map_or(30 * 86_400, |i| (2 * i).max(2 * 86_400));
        match latest_at {
            None if now - info.started_at > 3600 => warnings.push(warn(W_NO_BACKUP, &[])),
            Some(t) if now - t > limit => warnings.push(warn(W_OLD_BACKUP, &[("age", human_span(now - t))])),
            _ => {}
        }
    }

    Ok(Health { version: info.version, mode: info.mode, uptime_secs: now - info.started_at, db, disk, capture, sweep, backups, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_and_sizes_read_naturally() {
        assert_eq!(human_span(30), "1 minute");
        assert_eq!(human_span(600), "10 minutes");
        assert_eq!(human_span(3600), "1 hour");
        assert_eq!(human_span(7200), "2 hours");
        assert_eq!(human_span(3 * 86_400), "3 days");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1_500_000), "1.5 MB");
        assert_eq!(human_bytes(2_400_000_000), "2.4 GB");
    }

    #[test]
    fn the_disk_holding_a_path_can_be_measured_even_before_the_folder_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let (free, total) = disk_space(&tmp.path().join("not").join("yet")).expect("statvfs");
        assert!(total > 0 && free <= total);
    }
}
