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
pub const W_MIRROR_IP: &str = "The mirror interface {name} has an IP address of its own ({ip}). A monitor/SPAN port normally should not: an address there can conflict with a real device and cause outages on the network you are watching, not just on this box. See below to remove it.";
pub const W_DNS: &str = "This machine could not resolve a domain name just now. Check its own DNS settings, or whether the router it uses for DNS is itself working and can reach the internet.";

pub fn texts() -> [&'static str; 9] {
    [W_CAPTURE_DOWN, W_DROPS, W_SWEEP_LATE, W_NO_SWEEP, W_DISK, W_NO_BACKUP, W_OLD_BACKUP, W_MIRROR_IP, W_DNS]
}

/// A DNS resolution attempt from this host, in its own thread so a genuinely broken resolver
/// (the exact thing being checked for) cannot hang the health check that reports it. Cached
/// for a few minutes: this runs on every poll of a page that refreshes every 60 seconds.
///
/// Never actually resolves anything in a test build: this crate's test suite has no business
/// depending on real, live network access (offline, hermetic, and no slower for it).
#[cfg(not(test))]
fn dns_ok(now: i64) -> bool {
    static CACHE: std::sync::Mutex<(i64, bool)> = std::sync::Mutex::new((0, true));
    const TTL: i64 = 300;
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if now - c.0 >= TTL {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::net::ToSocketAddrs;
            let _ = tx.send(("example.com", 0u16).to_socket_addrs().is_ok_and(|mut a| a.next().is_some()));
        });
        c.1 = rx.recv_timeout(std::time::Duration::from_secs(3)).unwrap_or(false);
        c.0 = now;
    }
    c.1
}

#[cfg(test)]
fn dns_ok(_now: i64) -> bool {
    true
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
    /// Mirror/capture-only interfaces that currently have an IPv4 address of their own
    /// (name, address) — see `W_MIRROR_IP`. Empty in the common, correctly configured case.
    pub mirror_ips: Vec<(String, std::net::Ipv4Addr)>,
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

    let mirror_ips: Vec<(String, std::net::Ipv4Addr)> = if info.mirror_interfaces.is_empty() {
        Vec::new()
    } else {
        crate::net::list_interfaces()
            .map(|ifaces| ifaces.into_iter().filter(|i| info.mirror_interfaces.contains(&i.name)).map(|i| (i.name, i.ip)).collect())
            .unwrap_or_default()
    };
    for (name, ip) in &mirror_ips {
        warnings.push(warn(W_MIRROR_IP, &[("name", name.clone()), ("ip", ip.to_string())]));
    }

    if !viewer && !dns_ok(now) {
        warnings.push(warn(W_DNS, &[]));
    }

    Ok(Health { version: info.version, mode: info.mode, uptime_secs: now - info.started_at, db, disk, capture, sweep, backups, mirror_ips, warnings })
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
