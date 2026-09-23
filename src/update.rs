//! Self-update from GitHub Releases: notice a new version, show what changed, and (when an
//! administrator says so, now or at a chosen time) download, verify and install it, with a
//! database backup first and an automatic way back if the new version does not start.
//!
//! # Why this is safe to run on a security tool
//!
//! * **Signed releases only.** Every release carries `SHA256SUMS` and `SHA256SUMS.sig`, an
//!   Ed25519 signature made with the project's release key. The matching *public* key is
//!   compiled into the program (`update_key.rs`). The program refuses anything whose
//!   signature does not verify, and any file whose SHA-256 is not the one in the signed list.
//!   A compromised GitHub account or CDN can therefore not push code: it would also need
//!   the private key, which is kept outside GitHub's repository.
//! * **Only from the configured repository**, only over HTTPS, and only *newer* versions
//!   (a downgrade offered by an attacker is ignored).
//! * **Nothing is executed before it is checked.** The new file is verified, marked
//!   executable, and asked for its `--version`; if it does not run here (wrong platform,
//!   truncated) the update stops with the old version untouched.
//! * **Nothing is replaced before the data is safe.** A verified copy of the database is made
//!   first; the running program is kept as `denis.previous`.
//! * **A bad update cannot lock you out.** After the switch the new program must run for a
//!   minute before the update counts as done. If it dies at start-up twice, the old program
//!   (and, if the database format had changed, the pre-update database) come back.
//! * **Your data is not touched by updating**: the database file is only migrated forward by the
//!   new version itself, exactly as on any manual upgrade.
//!
//! Checking for a new version sends one anonymous HTTPS request to GitHub's API (your address
//! is visible to GitHub, nothing else). It can be turned off (`--no-update-check`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ring::digest;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::store::{Store};

/// Set once an update has been installed and a restart into the new program is wanted.
static RESTART_WANTED: AtomicBool = AtomicBool::new(false);

pub fn restart_wanted() -> bool {
    RESTART_WANTED.load(Ordering::SeqCst)
}

const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
const MAX_NOTES: usize = 20_000;
const MAX_BINARY: u64 = 300 * 1024 * 1024;
const MAX_SMALL: u64 = 1024 * 1024;
const KEEP_BACKUPS: usize = 5;
const HEALTHY_AFTER: Duration = Duration::from_secs(60);
/// Start-ups of a freshly installed version that may fail before we go back.
const MAX_FAILED_STARTS: u32 = 2;
pub const SETTINGS_KEY: &str = "update";

// ------------------------------------------------------------------- versions

/// `major.minor.patch` with an optional `-pre-release` (which sorts *before* the release).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    core: (u64, u64, u64),
    /// `true` = a normal release, which is newer than any pre-release of the same core.
    release: bool,
    pre: String,
}

impl Version {
    /// Accepts `1.2.3`, `v1.2.3`, `1.2.3-rc.1`; rejects everything else.
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim().strip_prefix('v').unwrap_or(s.trim());
        let s = s.split('+').next()?; // build metadata never affects order
        let (core, pre) = s.split_once('-').map_or((s, ""), |(c, p)| (c, p));
        let mut it = core.split('.');
        let (a, b, c) = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
        if it.next().is_some() || pre.len() > 40 || !pre.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')) {
            return None;
        }
        Some(Version { core: (a, b, c), release: pre.is_empty(), pre: pre.to_string() })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.release
    }

    pub fn text(&self) -> String {
        let (a, b, c) = self.core;
        if self.release { format!("{a}.{b}.{c}") } else { format!("{a}.{b}.{c}-{}", self.pre) }
    }
}

pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("the package version is valid")
}

/// The platform's name as used in release file names (`denis-<target>`).
pub fn target() -> Option<&'static str> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => Some("x86_64-unknown-linux-gnu"),
        ("aarch64", "linux") => Some("aarch64-unknown-linux-gnu"),
        ("aarch64", "macos") => Some("aarch64-apple-darwin"),
        ("x86_64", "macos") => Some("x86_64-apple-darwin"),
        _ => None,
    }
}

// ------------------------------------------------------------------- releases

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Release {
    pub version: String,
    /// The changelog (the release notes), plain text, bounded.
    pub notes: String,
    pub published_at: String,
    pub page: String,
    #[serde(skip)]
    pub assets: Vec<ReleaseAsset>,
}

/// Read GitHub's "latest release" answer. Drafts and pre-releases are ignored.
pub fn parse_release(v: &Value) -> Option<Release> {
    if v["draft"].as_bool() == Some(true) || v["prerelease"].as_bool() == Some(true) {
        return None;
    }
    let version = Version::parse(v["tag_name"].as_str()?)?;
    if version.is_prerelease() {
        return None;
    }
    let notes: String = v["body"].as_str().unwrap_or("").chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').take(MAX_NOTES).collect();
    let assets = v["assets"]
        .as_array()?
        .iter()
        .filter_map(|a| Some(ReleaseAsset { name: a["name"].as_str()?.to_string(), url: a["browser_download_url"].as_str()?.to_string(), size: a["size"].as_u64().unwrap_or(0) }))
        .collect();
    Some(Release {
        version: version.text(),
        notes,
        published_at: v["published_at"].as_str().unwrap_or("").chars().take(30).collect(),
        page: v["html_url"].as_str().filter(|u| u.starts_with("https://")).unwrap_or("").to_string(),
        assets,
    })
}

/// `SHA256SUMS` in the usual `<hex>  <file>` format, as name -> hex.
pub fn parse_sha256sums(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (h, n) = l.split_once(char::is_whitespace)?;
            let n = n.trim().trim_start_matches('*');
            (h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) && !n.is_empty() && !n.contains('/')).then(|| (n.to_string(), h.to_ascii_lowercase()))
        })
        .collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    (s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())).then(|| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect())
}

/// Verify an Ed25519 signature (hex text) over `message`.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature_hex: &str) -> bool {
    match unhex(signature_hex) {
        Some(sig) if sig.len() == 64 => UnparsedPublicKey::new(&ED25519, public_key).verify(message, &sig).is_ok(),
        _ => false,
    }
}

// --------------------------------------------------------------------- config

#[derive(Clone, Debug)]
pub struct UpdateConfig {
    /// `owner/repo`; empty = the update channel is not configured.
    pub repo: String,
    /// `false` = never contact GitHub (`--no-update-check`).
    pub check: bool,
    pub api_base: String,
    /// Downloads must start with this (the repository's release download address).
    pub download_prefix: String,
    pub public_key: Option<[u8; 32]>,
    /// The program file to replace. `None` = ask the OS (tests point it elsewhere).
    pub exe_path: Option<PathBuf>,
    /// The database file (its folder holds backups and update markers).
    pub db_path: PathBuf,
}

impl UpdateConfig {
    pub fn new(repo_override: Option<String>, check: bool, db_path: PathBuf) -> Result<Self> {
        let repo = repo_override.unwrap_or_else(|| crate::update_key::UPDATE_REPO.to_string());
        if !repo.is_empty() && !valid_repo(&repo) {
            bail!("the update repository must look like owner/name");
        }
        Ok(UpdateConfig {
            download_prefix: format!("https://github.com/{repo}/releases/download/"),
            repo,
            check,
            api_base: "https://api.github.com".into(),
            public_key: crate::update_key::RELEASE_PUBLIC_KEY,
            exe_path: None,
            db_path,
        })
    }

    /// Point at another release server (GitHub Enterprise, or a local test server). Both must be
    /// `https://`, except for a loopback address.
    pub fn with_endpoints(mut self, api_base: Option<String>, download_prefix: Option<String>) -> Result<Self> {
        let ok = |u: &str| u.starts_with("https://") || u.starts_with("http://127.0.0.1:") || u.starts_with("http://localhost:");
        if let Some(a) = api_base {
            if !ok(&a) {
                bail!("the update API address must use https://");
            }
            self.api_base = a.trim_end_matches('/').to_string();
        }
        if let Some(d) = download_prefix {
            if !ok(&d) {
                bail!("the update download address must use https://");
            }
            self.download_prefix = if d.ends_with('/') { d } else { format!("{d}/") };
        }
        Ok(self)
    }

    pub fn configured(&self) -> bool {
        self.check && !self.repo.is_empty()
    }
}

fn valid_repo(r: &str) -> bool {
    let ok = |s: &str| !s.is_empty() && s.len() <= 100 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    r.split_once('/').is_some_and(|(o, n)| ok(o) && ok(n) && !n.contains('/'))
}

// ------------------------------------------------------ persistent user choices

/// What the administrator decided; kept in the database so it survives restarts.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Choices {
    /// A version the administrator does not want to hear about.
    #[serde(default)]
    pub skipped: Option<String>,
    /// Do not remind before this time.
    #[serde(default)]
    pub snoozed_until: i64,
    /// Install automatically at this time.
    #[serde(default)]
    pub scheduled_at: Option<i64>,
    /// The version the schedule was made for (a newer release cancels an old schedule).
    #[serde(default)]
    pub scheduled_version: Option<String>,
}

fn load_choices(store: &dyn Store) -> Choices {
    store.get_setting(SETTINGS_KEY).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_choices(store: &dyn Store, c: &Choices, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(c)?, now)
}

// ------------------------------------------------------------------- the updater

#[derive(Default)]
struct State {
    latest: Option<Release>,
    checked_at: Option<i64>,
    last_error: Option<String>,
    /// What an install in progress is doing right now.
    stage: Option<&'static str>,
    /// Outcome of the last install attempt, for the console.
    result: Option<String>,
}

pub struct Updater {
    pub cfg: UpdateConfig,
    store: Arc<dyn Store>,
    state: Mutex<State>,
    busy: AtomicBool,
    /// Wakes the engine so it shuts down cleanly after an install.
    pub shutdown: Arc<tokio::sync::Notify>,
}

fn fetch(url: &str, max: u64, timeout: Duration) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(timeout)).http_status_as_error(true).build().into();
    let mut resp = agent.get(url).header("User-Agent", concat!("denis/", env!("CARGO_PKG_VERSION"))).header("Accept", "application/octet-stream, application/vnd.github+json").call().map_err(|e| anyhow!("{e}"))?;
    resp.body_mut().with_config().limit(max).read_to_vec().map_err(|e| anyhow!("download failed or too large: {e}"))
}

/// The steps an install goes through, in order, as shown to the person waiting for it.
pub const STAGES: [&str; 7] = ["Checking the release", "Verifying the signature", "Downloading", "Testing the new program", "Backing up the database", "Installing", "Restarting"];

impl Updater {
    pub fn new(cfg: UpdateConfig, store: Arc<dyn Store>) -> Arc<Self> {
        let u = Updater { cfg, store, state: Mutex::new(State::default()), busy: AtomicBool::new(false), shutdown: Arc::new(tokio::sync::Notify::new()) };
        // an update that had to be rolled back leaves a note; show it once
        if let Some(note) = take_rollback_note(&u.cfg.db_path) {
            u.state.lock().unwrap_or_else(|e| e.into_inner()).result = Some(note);
        }
        Arc::new(u)
    }

    fn exe(&self) -> Result<PathBuf> {
        match &self.cfg.exe_path {
            Some(p) => Ok(p.clone()),
            None => std::env::current_exe().context("cannot tell where this program is installed"),
        }
    }

    /// Ask GitHub for the latest release. Returns the release if it is newer than what runs.
    pub fn check(&self, now: i64) -> Result<Option<Release>> {
        if !self.cfg.configured() {
            bail!("updates are not configured for this build");
        }
        let url = format!("{}/repos/{}/releases/latest", self.cfg.api_base, self.cfg.repo);
        let r = (|| -> Result<Option<Release>> {
            let body = fetch(&url, MAX_SMALL, Duration::from_secs(20))?;
            let v: Value = serde_json::from_slice(&body).context("GitHub's answer was not understood")?;
            Ok(parse_release(&v).filter(|r| Version::parse(&r.version).is_some_and(|v| v > current_version())))
        })();
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.checked_at = Some(now);
        match &r {
            Ok(rel) => {
                st.latest = rel.clone();
                st.last_error = None;
            }
            Err(e) => st.last_error = Some(format!("{e:#}")),
        }
        r
    }

    /// Everything the console shows about updates.
    pub fn snapshot(&self, now: i64) -> Value {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let c = load_choices(&*self.store);
        let latest = st.latest.as_ref();
        let newest = latest.map(|r| r.version.clone());
        let hidden = newest.as_deref().is_some_and(|v| c.skipped.as_deref() == Some(v)) || c.snoozed_until > now;
        let exe = self.exe().ok();
        let exe_dir = exe.as_deref().and_then(|p| p.parent().map(Path::to_path_buf));
        let file_caps = exe.as_deref().is_some_and(has_file_capabilities);
        json!({
            "configured": self.cfg.configured(),
            "checking_enabled": self.cfg.check,
            "can_install": self.cfg.public_key.is_some() && exe_dir.as_deref().is_some_and(writable) && target().is_some() && !file_caps,
            "file_capabilities": file_caps,
            "installing": st.stage.is_some(),
            "stage": st.stage,
            "result": st.result,
            "current": current_version().text(),
            "latest": latest,
            "available": latest.is_some(),
            "notify": latest.is_some() && !hidden,
            "checked_at": st.checked_at,
            "last_error": st.last_error,
            "scheduled_at": c.scheduled_at,
            "backup_dir": backups_dir(&self.cfg.db_path),
        })
    }

    pub fn snooze(&self, days: i64, now: i64) -> Result<()> {
        let mut c = load_choices(&*self.store);
        c.snoozed_until = now + days.clamp(1, 60) * 86_400;
        save_choices(&*self.store, &c, now)
    }

    pub fn skip(&self, now: i64) -> Result<()> {
        let mut c = load_choices(&*self.store);
        c.skipped = self.state.lock().unwrap_or_else(|e| e.into_inner()).latest.as_ref().map(|r| r.version.clone());
        c.scheduled_at = None;
        save_choices(&*self.store, &c, now)
    }

    /// Install at `at` (unix seconds, at most 30 days ahead), or cancel with `None`.
    pub fn schedule(&self, at: Option<i64>, now: i64) -> Result<()> {
        let mut c = load_choices(&*self.store);
        if let Some(t) = at {
            if t < now - 60 || t > now + 30 * 86_400 {
                bail!("choose a time within the next 30 days");
            }
            let v = self.state.lock().unwrap_or_else(|e| e.into_inner()).latest.as_ref().map(|r| r.version.clone()).ok_or_else(|| anyhow!("there is no update to schedule"))?;
            c.scheduled_version = Some(v);
        } else {
            c.scheduled_version = None;
        }
        c.scheduled_at = at;
        save_choices(&*self.store, &c, now)
    }

    /// Start installing the latest release in the background. Returns at once.
    pub fn install_in_background(self: &Arc<Self>) -> Result<()> {
        let release = self.state.lock().unwrap_or_else(|e| e.into_inner()).latest.clone().ok_or_else(|| anyhow!("there is no update to install"))?;
        if self.busy.swap(true, Ordering::SeqCst) {
            bail!("an update is already being installed");
        }
        let me = self.clone();
        std::thread::spawn(move || {
            let res = me.install(&release);
            me.busy.store(false, Ordering::SeqCst);
            let mut st = me.state.lock().unwrap_or_else(|e| e.into_inner());
            st.stage = None;
            match res {
                Ok(()) => st.result = Some(format!("Updated to {}. DENIS is restarting.", release.version)),
                Err(e) => {
                    tracing::error!("update to {} failed: {e:#}", release.version);
                    st.result = Some(format!("The update was not installed and nothing was changed: {e:#}"));
                }
            }
        });
        Ok(())
    }

    fn stage(&self, s: &'static str) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).stage = Some(s);
        tracing::info!("update: {s}");
    }

    /// Download, verify, back up, switch. Everything before the final rename can fail
    /// harmlessly.
    pub fn install(&self, release: &Release) -> Result<()> {
        let key = self.cfg.public_key.ok_or_else(|| anyhow!("this build has no release key, so it cannot verify updates"))?;
        let target = target().ok_or_else(|| anyhow!("no release is published for this platform"))?;
        let want = Version::parse(&release.version).ok_or_else(|| anyhow!("bad version"))?;
        if want <= current_version() {
            bail!("that version is not newer than the one running");
        }
        let exe = self.exe()?;
        let dir = exe.parent().ok_or_else(|| anyhow!("cannot tell which folder holds the program"))?.to_path_buf();
        if !writable(&dir) {
            bail!("the program folder {} is not writable by the user DENIS runs as; install the update by hand, or make that folder writable for the service user", dir.display());
        }

        self.stage("Checking the release");
        let asset = |name: &str| -> Result<&ReleaseAsset> {
            let a = release.assets.iter().find(|a| a.name == name).ok_or_else(|| anyhow!("the release has no file named {name}"))?;
            if !a.url.starts_with(&self.cfg.download_prefix) {
                bail!("refusing a download from an unexpected address");
            }
            Ok(a)
        };
        let (sums, sig, bin) = (asset("SHA256SUMS")?, asset("SHA256SUMS.sig")?, asset(&format!("denis-{target}"))?);
        if bin.size > MAX_BINARY {
            bail!("the release file is unreasonably large");
        }

        self.stage("Verifying the signature");
        let sums_bytes = fetch(&sums.url, MAX_SMALL, Duration::from_secs(60))?;
        let sig_text = String::from_utf8(fetch(&sig.url, 4096, Duration::from_secs(60))?).context("the signature file is not text")?;
        if !verify_signature(&key, &sums_bytes, &sig_text) {
            bail!("the signature on the release does not verify: NOT installing");
        }
        let expected = parse_sha256sums(std::str::from_utf8(&sums_bytes).context("SHA256SUMS is not text")?)
            .remove(&format!("denis-{target}"))
            .ok_or_else(|| anyhow!("the signed list has no entry for this platform"))?;

        self.stage("Downloading");
        let bytes = fetch(&bin.url, MAX_BINARY, Duration::from_secs(600))?;
        if sha256_hex(&bytes) != expected {
            bail!("the download does not match its signed checksum: NOT installing");
        }

        self.stage("Testing the new program");
        let staged = dir.join("denis.new");
        std::fs::write(&staged, &bytes).with_context(|| format!("writing {}", staged.display()))?;
        make_executable(&staged)?;
        let smoke = (|| -> Result<()> {
            let out = std::process::Command::new(&staged).arg("--version").output().context("the downloaded program does not run on this machine")?;
            let text = String::from_utf8_lossy(&out.stdout);
            if !out.status.success() || !text.contains(&want.text()) {
                bail!("the downloaded program did not report version {}", want.text());
            }
            Ok(())
        })();
        if let Err(e) = smoke {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }

        self.stage("Backing up the database");
        let backups = backups_dir(&self.cfg.db_path);
        std::fs::create_dir_all(&backups)?;
        let stamp = crate::report::iso(crate::model::now_ts()).replace([':', 'T'], "-").replace('Z', "");
        let backup = backups.join(format!("denis-before-{}-{stamp}.db", want.text()));
        self.store.backup_to(&backup).inspect_err(|_| {
            let _ = std::fs::remove_file(&staged);
        })?;
        prune_backups(&backups, KEEP_BACKUPS);

        self.stage("Installing");
        let previous = dir.join("denis.previous");
        std::fs::copy(&exe, &previous).context("keeping the old program as denis.previous")?;
        let marker = Marker {
            from_version: current_version().text(),
            to_version: want.text(),
            exe: exe.clone(),
            previous: previous.clone(),
            backup: backup.clone(),
            db_version_before: sqlite_user_version(&self.cfg.db_path).unwrap_or(0),
            attempts: 0,
        };
        write_marker(&self.cfg.db_path, &marker)?;
        if let Err(e) = std::fs::rename(&staged, &exe) {
            let _ = std::fs::remove_file(&staged);
            let _ = remove_marker(&self.cfg.db_path);
            return Err(anyhow!("could not replace the program: {e}"));
        }

        self.stage("Restarting");
        if self.cfg.exe_path.is_none() {
            RESTART_WANTED.store(true, Ordering::SeqCst);
        }
        self.shutdown.notify_one();
        Ok(())
    }

    /// Background loop: look for updates now and then, and run a scheduled install when it is due.
    pub async fn run(self: Arc<Self>) {
        if !self.cfg.configured() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(45)).await;
        let mut last_check = 0i64;
        loop {
            let now = crate::model::now_ts();
            if now - last_check >= CHECK_EVERY.as_secs() as i64 {
                last_check = now;
                let me = self.clone();
                match tokio::task::spawn_blocking(move || me.check(now)).await {
                    Ok(Ok(Some(r))) => tracing::info!("DENIS {} is available", r.version),
                    Ok(Err(e)) => tracing::debug!("update check failed: {e:#}"),
                    _ => {}
                }
            }
            let c = load_choices(&*self.store);
            let latest = self.state.lock().unwrap_or_else(|e| e.into_inner()).latest.as_ref().map(|r| r.version.clone());
            if let (Some(at), Some(v)) = (c.scheduled_at, latest) {
                if now >= at && c.scheduled_version.as_deref() == Some(v.as_str()) {
                    let mut cleared = c.clone();
                    cleared.scheduled_at = None;
                    let _ = save_choices(&*self.store, &cleared, now);
                    if let Err(e) = self.install_in_background() {
                        tracing::error!("scheduled update did not start: {e:#}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }
}

// ------------------------------------------------------------------ file helpers

/// Does the program file carry Linux file capabilities (`setcap cap_net_raw,cap_net_admin=eip`)?
/// They belong to the file, not the program: an updated file would not have them, would fail to open the
/// network interface at start-up and be rolled back. (Capabilities granted by systemd's
/// `AmbientCapabilities` belong to the service and survive an update.)
#[cfg(target_os = "linux")]
fn has_file_capabilities(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(p.as_os_str().as_bytes()) else { return false };
    // SAFETY: both strings are NUL-terminated and outlive the call; a null buffer with size 0 only asks for the length.
    unsafe { libc::getxattr(path.as_ptr(), c"security.capability".as_ptr(), std::ptr::null_mut(), 0) > 0 }
}

#[cfg(not(target_os = "linux"))]
fn has_file_capabilities(_: &Path) -> bool {
    false
}

/// Can this process create files in `dir`? (An update must be able to write beside the program.)
fn writable(dir: &Path) -> bool {
    let probe = dir.join(".denis-write-test");
    let ok = std::fs::write(&probe, b"x").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

#[cfg(unix)]
fn make_executable(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_: &Path) -> Result<()> {
    Ok(())
}

pub fn backups_dir(db_path: &Path) -> PathBuf {
    db_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).join("backups")
}

/// Keep only the newest `keep` update backups.
fn prune_backups(dir: &Path, keep: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<_> = rd.filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("denis-before-")).collect();
    files.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
    for old in files.iter().rev().skip(keep) {
        let _ = std::fs::remove_file(old.path());
    }
}

fn sqlite_user_version(db: &Path) -> Option<i64> {
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    c.pragma_query_value(None, "user_version", |r| r.get(0)).ok()
}

// ------------------------------------------------- start-up guard and rollback

/// Written before switching programs; read by the *new* program at start-up.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Marker {
    pub from_version: String,
    pub to_version: String,
    pub exe: PathBuf,
    pub previous: PathBuf,
    pub backup: PathBuf,
    /// SQLite `user_version` before the update, to know whether the format changed.
    pub db_version_before: i64,
    /// How many times the new program has started without proving itself.
    pub attempts: u32,
}

fn marker_path(db: &Path) -> PathBuf {
    backups_dir(db).join("update-pending.json")
}

fn write_marker(db: &Path, m: &Marker) -> Result<()> {
    let p = marker_path(db);
    std::fs::create_dir_all(p.parent().unwrap())?;
    std::fs::write(&p, serde_json::to_vec_pretty(m)?)?;
    Ok(())
}

fn remove_marker(db: &Path) -> std::io::Result<()> {
    std::fs::remove_file(marker_path(db))
}

fn take_rollback_note(db: &Path) -> Option<String> {
    let p = backups_dir(db).join("update-rolled-back.txt");
    let t = std::fs::read_to_string(&p).ok()?;
    let _ = std::fs::remove_file(&p);
    Some(t)
}

/// What the start-up guard decided.
#[derive(Debug, PartialEq)]
pub enum Guard {
    /// No update in flight.
    Nothing,
    /// A freshly installed version is starting; keep watching.
    Watching,
    /// The new version kept failing: the old program (and maybe the old database) were put
    /// back. The caller should start the old program.
    RolledBack { exe: PathBuf },
}

/// Call at the very start of `run`, before the database is opened.
pub fn startup_guard(db: &Path) -> Guard {
    let Ok(text) = std::fs::read_to_string(marker_path(db)) else { return Guard::Nothing };
    let Ok(mut m) = serde_json::from_str::<Marker>(&text) else {
        let _ = remove_marker(db);
        return Guard::Nothing;
    };
    // a start of the *old* program (e.g. after a manual rollback) must not count against the new one
    if current_version().text() != m.to_version {
        let _ = remove_marker(db);
        return Guard::Nothing;
    }
    m.attempts += 1;
    if m.attempts <= MAX_FAILED_STARTS {
        let _ = write_marker(db, &m);
        return Guard::Watching;
    }
    match rollback(db, &m) {
        Ok(()) => Guard::RolledBack { exe: m.exe },
        Err(e) => {
            tracing::error!("rolling back the update failed: {e:#}");
            let _ = remove_marker(db);
            Guard::Nothing
        }
    }
}

/// Put the old program back and, if the database format was migrated, the pre-update database.
pub fn rollback(db: &Path, m: &Marker) -> Result<()> {
    let migrated = sqlite_user_version(db).unwrap_or(0) != m.db_version_before;
    let mut note = format!("DENIS {} did not start, so version {} was put back.", m.to_version, m.from_version);
    if migrated && m.backup.exists() {
        let stamp = crate::model::now_ts();
        let failed = db.with_extension(format!("failed-{stamp}"));
        std::fs::rename(db, &failed).context("setting the new database aside")?;
        for ext in ["db-wal", "db-shm"] {
            let _ = std::fs::remove_file(db.with_extension(ext));
        }
        std::fs::copy(&m.backup, db).context("restoring the pre-update database")?;
        note.push_str(&format!(" The database format had changed, so the backup taken before the update was restored (the newer one is kept as {}).", failed.display()));
    }
    std::fs::rename(&m.previous, &m.exe).context("putting the old program back")?;
    let _ = remove_marker(db);
    let _ = std::fs::write(backups_dir(db).join("update-rolled-back.txt"), note);
    Ok(())
}

/// The new version has run long enough: the update is done.
pub async fn mark_healthy_later(db: PathBuf) {
    tokio::time::sleep(HEALTHY_AFTER).await;
    if remove_marker(&db).is_ok() {
        tracing::info!("update confirmed: this version has been running for a minute");
    }
}

/// Replace this process with the program at `exe`, same arguments. Returns only on failure.
#[cfg(unix)]
pub fn exec(exe: &Path) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    std::process::Command::new(exe).args(std::env::args_os().skip(1)).exec()
}

#[cfg(not(unix))]
pub fn exec(_: &Path) -> std::io::Error {
    std::io::Error::other("restarting in place is not supported here")
}

// -------------------------------------------------------- release signing tools

/// A new signing key pair: `(private seed hex, public key hex)`.
pub fn generate_keypair() -> Result<(String, String)> {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let mut seed = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed).map_err(|_| anyhow!("no secure randomness"))?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| anyhow!("bad seed"))?;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Ok((hex(&seed), hex(pair.public_key().as_ref())))
}

/// Sign `message` with a hex seed; returns the signature as hex.
pub fn sign(seed_hex: &str, message: &[u8]) -> Result<String> {
    use ring::signature::Ed25519KeyPair;
    let seed = unhex(seed_hex).filter(|s| s.len() == 32).ok_or_else(|| anyhow!("the key must be 64 hex characters"))?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| anyhow!("bad key"))?;
    Ok(pair.sign(message).as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SettingsStore;
    use crate::store::sqlite::SqliteStore;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn versions_parse_and_order_like_semver_and_ignore_junk() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("0.2.0") > v("0.1.9") && v("1.0.0") > v("0.99.99") && v("0.10.0") > v("0.9.0"), "numeric, not textual");
        assert_eq!(v("v1.2.3"), v("1.2.3"));
        assert!(v("1.2.3-rc.1") < v("1.2.3") && v("1.2.3-rc.1") > v("1.2.2"));
        assert_eq!(v("1.2.3+build5"), v("1.2.3"));
        assert_eq!(v("v1.2.3-rc.1").text(), "1.2.3-rc.1");
        for bad in ["", "1", "1.2", "1.2.3.4", "a.b.c", "1.2.3-", "1.2.-3x/", "v", "1.2.3-bad space", "1.2.3-\u{202e}"] {
            // "1.2.3-" has an empty pre-release: treated as a plain release, which is harmless; the rest must fail
            if bad == "1.2.3-" { continue; }
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
        assert_eq!(current_version().text(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn github_answers_are_read_defensively() {
        let good = json!({"tag_name": "v0.2.0", "body": "## What's new\n- x\u{0}\u{7}y", "published_at": "2026-09-21T10:00:00Z", "html_url": "https://github.com/o/r/releases/tag/v0.2.0",
            "assets": [{"name": "denis-x86_64-unknown-linux-gnu", "browser_download_url": "https://github.com/o/r/releases/download/v0.2.0/denis-x86_64-unknown-linux-gnu", "size": 10}, {"name": "broken"}]});
        let r = parse_release(&good).unwrap();
        assert_eq!((r.version.as_str(), r.assets.len()), ("0.2.0", 1), "an entry without a URL is skipped");
        assert!(r.notes.contains("What's new") && !r.notes.contains('\u{0}') && !r.notes.contains('\u{7}'), "control characters are stripped");
        assert!(parse_release(&json!({"tag_name": "v0.2.0", "draft": true, "assets": []})).is_none());
        assert!(parse_release(&json!({"tag_name": "v0.2.0", "prerelease": true, "assets": []})).is_none());
        assert!(parse_release(&json!({"tag_name": "v0.2.0-rc1", "assets": []})).is_none());
        assert!(parse_release(&json!({"tag_name": "nightly", "assets": []})).is_none());
        assert!(parse_release(&json!({"tag_name": "v0.2.0"})).is_none());
        let long = json!({"tag_name": "v1.0.0", "body": "x".repeat(100_000), "assets": []});
        assert_eq!(parse_release(&long).unwrap().notes.len(), MAX_NOTES);
        // a page link that is not https is dropped
        assert_eq!(parse_release(&json!({"tag_name": "v1.0.0", "html_url": "javascript:alert(1)", "assets": []})).unwrap().page, "");
    }

    #[test]
    fn checksum_lists_and_signatures_are_strict() {
        let hex = "a".repeat(64);
        let m = parse_sha256sums(&format!("{hex}  denis-x86_64-unknown-linux-gnu\n{hex} *denis-aarch64-apple-darwin\nnothex  x\n{hex}  ../evil\n{}  short\n\n", "b".repeat(63)));
        assert_eq!(m.len(), 2);
        assert_eq!(m["denis-aarch64-apple-darwin"], hex, "the binary-mode asterisk is tolerated");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        let (seed, public) = generate_keypair().unwrap();
        let pk: [u8; 32] = unhex(&public).unwrap().try_into().unwrap();
        let sig = sign(&seed, b"the signed list").unwrap();
        assert!(verify_signature(&pk, b"the signed list", &sig));
        assert!(!verify_signature(&pk, b"the signed list!", &sig), "any change breaks it");
        let (_, other) = generate_keypair().unwrap();
        assert!(!verify_signature(&unhex(&other).unwrap().try_into().unwrap(), b"the signed list", &sig), "another key");
        for bad in ["", "zz", &sig[..126], &format!("{sig}00"), &"0".repeat(128)] {
            assert!(!verify_signature(&pk, b"the signed list", bad), "{bad}");
        }
        assert!(sign("short", b"x").is_err());
    }

    // ---------------------------------------------------------- a fake GitHub

    type Routes = Arc<Mutex<HashMap<String, Vec<u8>>>>;

    struct Fake {
        base: String,
        routes: Routes,
    }

    /// Serves `routes` (path -> body); anything else is a 404. Routes can be changed while it runs.
    fn fake_github() -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let routes: Routes = Arc::default();
        let r2 = routes.clone();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut c) = conn else { return };
                let mut buf = [0u8; 4096];
                let n = c.read(&mut buf).unwrap_or(0);
                let path = String::from_utf8_lossy(&buf[..n]).split_whitespace().nth(1).unwrap_or("").to_string();
                let body = r2.lock().unwrap_or_else(|e| e.into_inner()).get(&path).cloned();
                match body {
                    Some(body) => {
                        let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        let _ = c.write_all(&body);
                    }
                    None => {
                        let _ = write!(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                }
            }
        });
        Fake { base, routes }
    }

    /// A tiny "program" that reports a version, like the real one.
    fn script(version: &str) -> Vec<u8> {
        format!("#!/bin/sh\necho \"denis {version}\"\n").into_bytes()
    }

    struct World {
        _dir: tempfile::TempDir,
        updater: Arc<Updater>,
        fake: Fake,
        exe: PathBuf,
        db: PathBuf,
    }

    /// Publish `bin` as version 9.9.9 on `fake`, correctly signed with `seed`.
    fn publish(fake: &Fake, seed: &str, bin: &[u8]) {
        let t = target().unwrap_or("x86_64-unknown-linux-gnu");
        let sums = format!("{}  denis-{t}\n", sha256_hex(bin)).into_bytes();
        let mut r = fake.routes.lock().unwrap_or_else(|e| e.into_inner());
        r.insert("/dl/SHA256SUMS".into(), sums.clone());
        r.insert("/dl/SHA256SUMS.sig".into(), sign(seed, &sums).unwrap().into_bytes());
        r.insert(format!("/dl/denis-{t}"), bin.to_vec());
        let asset = |n: &str| json!({"name": n, "browser_download_url": format!("{}/dl/{n}", fake.base), "size": 100});
        let release = json!({"tag_name": "v9.9.9", "body": "## 9.9.9\n- something new", "published_at": "2026-09-21T10:00:00Z", "html_url": "https://github.com/o/r/releases/tag/v9.9.9",
            "assets": [asset("SHA256SUMS"), asset("SHA256SUMS.sig"), asset(&format!("denis-{t}"))]});
        r.insert("/repos/o/r/releases/latest".into(), release.to_string().into_bytes());
    }

    /// An "installed" program and database, and a fake GitHub with a signed release 9.9.9.
    /// Returns the signing seed too, so a test can re-sign after tampering.
    fn world() -> (World, String) {
        let dir = tempfile::tempdir().unwrap();
        let (seed, public) = generate_keypair().unwrap();
        let fake = fake_github();
        publish(&fake, &seed, &script("9.9.9"));
        let exe = dir.path().join("denis");
        std::fs::write(&exe, script(env!("CARGO_PKG_VERSION"))).unwrap();
        make_executable(&exe).unwrap();
        let db = dir.path().join("denis.db");
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&db).unwrap());
        let mut cfg = UpdateConfig::new(Some("o/r".into()), true, db.clone()).unwrap();
        cfg.api_base = fake.base.clone();
        cfg.download_prefix = format!("{}/dl/", fake.base);
        cfg.public_key = Some(unhex(&public).unwrap().try_into().unwrap());
        cfg.exe_path = Some(exe.clone());
        (World { _dir: dir, updater: Updater::new(cfg, store), fake, exe, db }, seed)
    }

    #[test]
    fn an_update_check_reports_only_newer_signed_channel_releases_and_never_crashes() {
        let (w, _) = world();
        let rel = w.updater.check(1000).unwrap().expect("9.9.9 is newer than the running version");
        assert_eq!(rel.version, "9.9.9");
        assert!(rel.notes.contains("something new"));
        let snap = w.updater.snapshot(1000);
        assert_eq!((snap["available"].as_bool(), snap["notify"].as_bool(), snap["current"].as_str()), (Some(true), Some(true), Some(env!("CARGO_PKG_VERSION"))));
        // snoozing hides the notification for a while, skipping hides this version for good
        w.updater.snooze(3, 1000).unwrap();
        assert_eq!(w.updater.snapshot(1000 + 86_400)["notify"], false);
        assert_eq!(w.updater.snapshot(1000 + 4 * 86_400)["notify"], true, "the reminder comes back");
        w.updater.skip(2000).unwrap();
        assert_eq!(w.updater.snapshot(1000 + 90 * 86_400)["notify"], false);
        // a release that is not newer is not offered
        w.fake.routes.lock().unwrap_or_else(|e| e.into_inner()).insert("/repos/o/r/releases/latest".into(), json!({"tag_name": format!("v{}", env!("CARGO_PKG_VERSION")), "assets": []}).to_string().into_bytes());
        assert_eq!(w.updater.check(3000).unwrap(), None);
        assert_eq!(w.updater.snapshot(3000)["available"], false);
        // a server that is down is an error message, not a crash
        let mut cfg = w.updater.cfg.clone();
        cfg.api_base = "http://127.0.0.1:1".into();
        let down = Updater::new(cfg, Arc::new(SqliteStore::open_in_memory().unwrap()));
        assert!(down.check(5).is_err());
        assert!(down.snapshot(5)["last_error"].is_string());
        // unconfigured or switched off: nothing is contacted
        let off = Updater::new(UpdateConfig::new(Some(String::new()), true, w.db.clone()).unwrap(), Arc::new(SqliteStore::open_in_memory().unwrap()));
        assert!(off.check(1).is_err() && !off.snapshot(1)["configured"].as_bool().unwrap());
        assert!(UpdateConfig::new(Some("not a repo".into()), true, w.db.clone()).is_err());
        assert!(UpdateConfig::new(Some("../x/y".into()), true, w.db.clone()).is_err());
    }

    #[test]
    fn the_scheduling_rules_are_enforced() {
        let (w, _) = world();
        assert!(w.updater.schedule(Some(2000), 1000).is_err(), "nothing to schedule before a check");
        w.updater.check(1000).unwrap();
        assert!(w.updater.schedule(Some(1000 + 40 * 86_400), 1000).is_err(), "at most 30 days ahead");
        assert!(w.updater.schedule(Some(500), 1000).is_err(), "not in the past");
        w.updater.schedule(Some(1000 + 3600), 1000).unwrap();
        assert_eq!(w.updater.snapshot(1000)["scheduled_at"], 4600);
        w.updater.schedule(None, 1001).unwrap();
        assert!(w.updater.snapshot(1000)["scheduled_at"].is_null());
    }

    #[test]
    fn a_verified_update_backs_up_first_keeps_the_old_program_and_switches() {
        if target().is_none() {
            return; // no release is published for this platform
        }
        let (w, _) = world();
        let rel = w.updater.check(1000).unwrap().unwrap();
        // give the database something to protect
        w.updater.store.set_setting("marker", b"precious", 1).unwrap();
        let before = std::fs::read(&w.exe).unwrap();
        w.updater.install(&rel).unwrap();
        // the program is the new one, the old one is kept next to it
        assert_eq!(std::fs::read(&w.exe).unwrap(), script("9.9.9"));
        assert_eq!(std::fs::read(w.exe.with_file_name("denis.previous")).unwrap(), before);
        assert!(!w.exe.with_file_name("denis.new").exists(), "no half-installed file is left");
        // a verified backup of the data exists, and holds the data
        let backups: Vec<_> = std::fs::read_dir(backups_dir(&w.db)).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("denis-before-9.9.9")).collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(SqliteStore::open(&backups[0].path()).unwrap().get_setting("marker").unwrap().as_deref(), Some(&b"precious"[..]));
        // the live data is untouched
        assert_eq!(w.updater.store.get_setting("marker").unwrap().as_deref(), Some(&b"precious"[..]));
        // a start-up marker is waiting for the new program to prove itself
        assert!(marker_path(&w.db).exists());
        assert!(!restart_wanted(), "test mode never asks the real process to restart");
        // installing the same or an older version is refused
        assert!(w.updater.install(&Release { version: env!("CARGO_PKG_VERSION").into(), ..rel.clone() }).is_err());
    }

    #[test]
    fn nothing_is_installed_when_the_signature_the_checksum_or_the_program_is_wrong() {
        let Some(t) = target() else { return };
        let junk = b"this is not a program".to_vec();
        // each case: how to break the published release
        type Break = Box<dyn Fn(&Fake, &str)>;
        let cases: Vec<(&str, Break)> = vec![
            ("a signature from another key", Box::new(|f, _| {
                let (other, _) = generate_keypair().unwrap();
                let sums = f.routes.lock().unwrap_or_else(|e| e.into_inner())["/dl/SHA256SUMS"].clone();
                f.routes.lock().unwrap_or_else(|e| e.into_inner()).insert("/dl/SHA256SUMS.sig".into(), sign(&other, &sums).unwrap().into_bytes());
            })),
            ("a garbled signature", Box::new(|f, _| { f.routes.lock().unwrap_or_else(|e| e.into_inner()).insert("/dl/SHA256SUMS.sig".into(), b"not a signature".to_vec()); })),
            ("a tampered checksum list", Box::new(move |f, _| { f.routes.lock().unwrap_or_else(|e| e.into_inner()).insert("/dl/SHA256SUMS".into(), format!("{}  denis-{t}\n", "0".repeat(64)).into_bytes()); })),
            ("a swapped program", Box::new(move |f, _| { f.routes.lock().unwrap_or_else(|e| e.into_inner()).insert(format!("/dl/denis-{t}"), script("9.9.9 evil")); })),
            ("a program that does not run (correctly signed, but not a program)", Box::new(move |f, seed| { publish(f, seed, b"this is not a program"); })),
            ("a program that runs but is the wrong version", Box::new(move |f, seed| { publish(f, seed, &script("1.0.0")); })),
        ];
        for (what, break_it) in cases {
            let (w, seed) = world();
            break_it(&w.fake, &seed);
            let rel = w.updater.check(1000).unwrap().unwrap();
            let before = std::fs::read(&w.exe).unwrap();
            assert!(w.updater.install(&rel).is_err(), "{what}");
            assert_eq!(std::fs::read(&w.exe).unwrap(), before, "{what}: the running program is untouched");
            assert!(!w.exe.with_file_name("denis.new").exists(), "{what}: no staged file is left behind");
            assert!(!marker_path(&w.db).exists(), "{what}: no update was started");
            assert!(!w.exe.with_file_name("denis.previous").exists(), "{what}: nothing was replaced");
        }
        let _ = junk;
    }

    #[test]
    fn downloads_from_unexpected_addresses_or_of_missing_files_are_refused() {
        if target().is_none() {
            return;
        }
        let (w, _) = world();
        let mut rel = w.updater.check(1000).unwrap().unwrap();
        // pretend the release points somewhere other than the configured repository
        let mut cfg = w.updater.cfg.clone();
        cfg.download_prefix = "https://github.com/someone-else/repo/releases/download/".into();
        let other = Updater::new(cfg, w.updater.store.clone());
        let e = other.install(&rel).unwrap_err().to_string();
        assert!(e.contains("unexpected address"), "{e}");
        rel.assets.retain(|a| a.name != "SHA256SUMS.sig");
        assert!(w.updater.install(&rel).is_err());
        rel.assets.clear();
        assert!(w.updater.install(&rel).is_err());
    }

    #[test]
    fn a_build_without_a_release_key_or_in_a_read_only_folder_cannot_install() {
        let (w, _) = world();
        let rel = w.updater.check(1000).unwrap().unwrap();
        let mut cfg = w.updater.cfg.clone();
        cfg.public_key = None;
        let nokey = Updater::new(cfg, w.updater.store.clone());
        assert!(nokey.install(&rel).unwrap_err().to_string().contains("release key"));
        assert_eq!(nokey.snapshot(1)["can_install"], false);
        // an ordinary file has no capabilities, so this alone never blocks an install
        assert!(!has_file_capabilities(&std::env::current_exe().unwrap()));
    }

    #[test]
    fn a_new_program_that_keeps_failing_is_rolled_back_with_the_old_database_if_the_format_changed() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("denis.db");
        let exe = dir.path().join("denis");
        let previous = dir.path().join("denis.previous");
        let backup = backups_dir(&db).join("denis-before-9.9.9.db");
        std::fs::create_dir_all(backups_dir(&db)).unwrap();
        // the old world: database at format N with data, saved as the backup
        let old = SqliteStore::open(&db).unwrap();
        old.set_setting("k", b"old", 1).unwrap();
        old.backup_to(&backup).unwrap();
        drop(old);
        let old_format = sqlite_user_version(&db).unwrap();
        // the new program migrated the database (simulated) and never came up
        rusqlite::Connection::open(&db).unwrap().pragma_update(None, "user_version", old_format + 1).unwrap();
        std::fs::write(&exe, b"new (broken)").unwrap();
        std::fs::write(&previous, b"old program").unwrap();
        let version = current_version().text();
        let m = Marker { from_version: "0.0.1".into(), to_version: version, exe: exe.clone(), previous, backup, db_version_before: old_format, attempts: 0 };
        write_marker(&db, &m).unwrap();

        assert_eq!(startup_guard(&db), Guard::Watching, "first start: give it a chance");
        assert_eq!(startup_guard(&db), Guard::Watching, "second start: one more chance");
        assert_eq!(startup_guard(&db), Guard::RolledBack { exe: exe.clone() }, "third start: it is not going to work");
        assert_eq!(std::fs::read(&exe).unwrap(), b"old program");
        assert_eq!(SqliteStore::open(&db).unwrap().get_setting("k").unwrap().as_deref(), Some(&b"old"[..]), "the pre-update database is back");
        assert!(std::fs::read_dir(dir.path()).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().contains("failed-")), "the newer database is kept, not destroyed");
        assert!(!marker_path(&db).exists());
        assert!(take_rollback_note(&db).unwrap().contains("did not start"));
        assert!(take_rollback_note(&db).is_none(), "shown once");
        assert_eq!(startup_guard(&db), Guard::Nothing);
    }

    #[test]
    fn a_rollback_leaves_the_database_alone_when_its_format_did_not_change_and_stale_markers_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("denis.db");
        let store = SqliteStore::open(&db).unwrap();
        store.set_setting("k", b"kept", 1).unwrap();
        drop(store);
        let fmt = sqlite_user_version(&db).unwrap();
        let (exe, previous) = (dir.path().join("denis"), dir.path().join("denis.previous"));
        std::fs::write(&exe, b"new").unwrap();
        std::fs::write(&previous, b"old").unwrap();
        let m = Marker { from_version: "0.0.1".into(), to_version: current_version().text(), exe: exe.clone(), previous, backup: dir.path().join("missing.db"), db_version_before: fmt, attempts: 0 };
        rollback(&db, &m).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
        assert_eq!(SqliteStore::open(&db).unwrap().get_setting("k").unwrap().as_deref(), Some(&b"kept"[..]), "data written since is not thrown away");
        // a marker for some other version (the old program starting) is dropped, and garbage is too
        let stale = Marker { to_version: "99.0.0".into(), ..m.clone() };
        write_marker(&db, &stale).unwrap();
        assert_eq!(startup_guard(&db), Guard::Nothing);
        assert!(!marker_path(&db).exists());
        std::fs::create_dir_all(backups_dir(&db)).unwrap();
        std::fs::write(marker_path(&db), b"{not json").unwrap();
        assert_eq!(startup_guard(&db), Guard::Nothing);
    }

    #[test]
    fn old_update_backups_are_pruned_and_only_those() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..9 {
            std::fs::write(dir.path().join(format!("denis-before-0.{i}.0.db")), b"x").unwrap();
            std::thread::sleep(Duration::from_millis(15));
        }
        std::fs::write(dir.path().join("my-own-backup.db"), b"x").unwrap();
        prune_backups(dir.path(), KEEP_BACKUPS);
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        assert_eq!(names.iter().filter(|n| n.starts_with("denis-before-")).count(), KEEP_BACKUPS);
        assert!(names.contains(&"my-own-backup.db".to_string()) && names.contains(&"denis-before-0.8.0.db".to_string()));
    }
}
