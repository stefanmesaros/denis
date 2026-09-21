//! The engine. One collector (capture thread + aggregator + active scheduler)
//! is shared by both deployment shapes:
//!
//! * `run`: standalone / master. Collector + detector + web UI, and optionally
//!   an ingest listener that accepts remote agents.
//! * `agent`: collector + reporter that pushes to a master.
//!
//! A small network needs only `run`; agents are added per extra site.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use serde::Serialize;
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

use crate::agent::{self, AgentConfig};
use crate::auth::Auth;
use crate::capture::{self, CaptureThread};
use crate::detect::{DetectConfig, Detector};
use crate::ingest::{self, Ingest};
use crate::inventory::{Flushed, Inventory};
use crate::model::{now_ts, FlowBatch, Mac, Observation, Signal};
use crate::net::{self, Iface};
use crate::notify::{self, Alerts};
use crate::parse::Ctx;
use crate::store::sqlite::SqliteStore;
use crate::store::{EventQuery, Store};
use crate::{active, trends, web};

/// Everything the collector needs; shared by `run` and `agent`.
pub struct CollectorConfig {
    pub iface: Option<String>,
    pub db: PathBuf,
    /// How often to re-run the ARP sweep.
    pub sweep_interval: Duration,
    /// Minimum time between port scans of the same host.
    pub rescan_interval: Duration,
    /// Never transmit: capture only.
    pub passive_only: bool,
    pub scan_timeout: Duration,
    /// Max simultaneous connect() attempts (macOS defaults to 256 fds/process).
    pub scan_concurrency: usize,
    /// Account traffic to/from outside the subnet (input to the anomaly rules)
    /// and decode industrial protocols between local devices.
    pub flows: bool,
    /// Address ranges that must never be probed (fragile equipment, other
    /// people's networks). They are still *observed* passively.
    pub exclude: Vec<Ipv4Net>,
    /// Delay between ARP requests of a sweep. 2 ms is fine for IT; OT networks
    /// use much gentler pacing.
    pub arp_pace: Duration,
}

impl CollectorConfig {
    /// May we send anything to this address?
    pub fn may_probe(&self, ip: Ipv4Addr) -> bool {
        !self.exclude.iter().any(|n| n.contains(&ip))
    }
}

impl Default for CollectorConfig {
    fn default() -> Self {
        CollectorConfig {
            iface: None,
            db: PathBuf::from("denis.db"),
            sweep_interval: Duration::from_secs(300),
            rescan_interval: Duration::from_secs(1800),
            passive_only: false,
            scan_timeout: Duration::from_millis(800),
            scan_concurrency: 64,
            flows: false,
            exclude: Vec::new(),
            arp_pace: Duration::from_millis(2),
        }
    }
}

pub struct Config {
    pub collector: CollectorConfig,
    pub listen: SocketAddr,
    /// Accept remote agents here (each authenticates with its own token). Off by default.
    pub ingest_listen: Option<SocketAddr>,
    /// Skip login. Development/testing only; refused on a non-loopback UI address.
    pub no_auth: bool,
    /// Mark the session cookie `Secure` (when a TLS-terminating proxy is in front).
    pub secure_cookie: bool,
    pub detect: DetectConfig,
    pub webhook: Option<String>,
    pub webhook_min_score: i32,
    /// The address people type to reach the console (`https://denis.example.com`): pins where
    /// passkeys are valid. Without it passkeys work only on `http://localhost`.
    pub public_url: Option<String>,
    /// Public host names a reverse proxy on this machine forwards (see `web::AppState`).
    pub allowed_hosts: Vec<String>,
    /// PEM certificate chain and private key: serve the UI and the agent port over HTTPS.
    pub tls: TlsMode,
    /// File of known-bad IPv4 addresses/networks for the `threat_list_match` rule.
    pub threat_list: Option<std::path::PathBuf>,
    /// Update channel (GitHub Releases); see `update`.
    pub update: Option<crate::update::UpdateConfig>,
    /// Send alerts to a SIEM as syslog/CEF.
    pub syslog: Option<crate::syslog::SyslogConfig>,
    /// Export events, audit log, trends and inventory to OpenObserve.
    pub openobserve: Option<crate::sink::SinkConfig>,
    /// Trend samples older than this are deleted.
    pub retention_days: i64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            collector: CollectorConfig::default(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            ingest_listen: None,
            no_auth: false,
            secure_cookie: false,
            detect: DetectConfig::default(),
            webhook: None,
            webhook_min_score: 60,
            openobserve: None,
            syslog: None,
            update: None,
            threat_list: None,
            tls: TlsMode::Off,
            allowed_hosts: vec![],
            public_url: None,
            retention_days: 90,
        }
    }
}

/// Status notes shown in the header (the console translates them; see `i18n.rs`).
pub const NOTE_PASSIVE_ONLY: &str = "passive-only: no packets are transmitted";
pub const NOTE_FLOWS: &str = "flow accounting on: anomaly rules see only traffic that crosses this interface";
pub const NOTE_VIEWER: &str = "viewer mode: showing a database, nothing is captured or detected";

#[derive(Serialize, Clone)]
pub struct StatusInfo {
    pub version: &'static str,
    pub mode: &'static str,
    pub interface: String,
    pub ip: Ipv4Addr,
    pub mac: Mac,
    pub subnet: String,
    pub gateway: Option<Ipv4Addr>,
    pub started_at: i64,
    pub passive_only: bool,
    pub flows_enabled: bool,
    pub ingest_listen: Option<String>,
    pub sweep_interval_secs: u64,
    pub sweeping: bool,
    pub last_sweep_started: Option<i64>,
    pub last_sweep_finished: Option<i64>,
    /// Until this time new devices/destinations are learned, not alerted on.
    pub learning_ends_at: Option<i64>,
    pub min_score: i32,
    pub notes: Vec<String>,
    pub frames_matched: u64,
    /// Health of each configured export (OpenObserve, syslog).
    pub exports: Vec<crate::sink::ExportStatus>,
}

/// A request to scan these devices again right now (to confirm that a finding was fixed).
pub struct RescanRequest {
    pub ips: Vec<Ipv4Addr>,
    pub reply: tokio::sync::oneshot::Sender<Vec<(Ipv4Addr, RescanOutcome)>>,
}

/// What a rescan of one address found.
#[derive(Clone, Debug, PartialEq)]
pub enum RescanOutcome {
    /// It answered: these TCP ports are open now.
    Scanned(Vec<crate::model::OpenPort>),
    /// Nothing answered (off, asleep, blocking everything): a scan proves nothing.
    Unreachable,
    /// The operator excluded this address from probing (`--exclude`).
    Excluded,
}

/// Where an erase request's outcome is sent back.
type EraseReply = tokio::sync::oneshot::Sender<Result<(), String>>;

/// State shared between the engine tasks and the web layer.
pub struct Shared {
    info: Mutex<StatusInfo>,
    frames: Arc<AtomicU64>,
    exports: Mutex<Vec<Arc<Mutex<crate::sink::ExportStatus>>>>,
    /// Detection settings from the command line, before portal overrides (for the Rules screen).
    detect_base: Mutex<Option<DetectConfig>>,
    /// Set by `run`: asks the engine to erase the data *and* its own in-memory state together.
    erase_tx: Mutex<Option<mpsc::Sender<EraseReply>>>,
    /// Asks the collector to scan devices again (`None` when it cannot: viewer mode, passive-only).
    rescan_tx: Mutex<Option<mpsc::Sender<RescanRequest>>>,
    /// The console's certificate, when it is served over TLS.
    tls: Mutex<Option<Arc<crate::tls::TlsHandle>>>,
    /// The self-updater (`None` in viewer mode).
    updater: Mutex<Option<Arc<crate::update::Updater>>>,
    /// Delivery health of each notification channel (see `channels`).
    pub channel_status: crate::channels::StatusMap,
    /// Wakes the scheduler for an immediate sweep + full port rescan.
    pub scan_now: Notify,
    /// What the packet capture reports (drops, mostly).
    pub capture_stats: Arc<capture::CaptureStats>,
    /// The database file (its folder holds the backups).
    pub db_path: std::path::PathBuf,
}

impl Shared {
    pub fn snapshot(&self) -> StatusInfo {
        let mut s = self.info.lock().unwrap().clone();
        s.frames_matched = self.frames.load(Ordering::Relaxed);
        s.exports = self.exports.lock().unwrap().iter().map(|e| e.lock().unwrap().clone()).collect();
        s
    }

    /// The command-line detection settings, once the detector exists.
    pub fn detect_base(&self) -> Option<DetectConfig> {
        self.detect_base.lock().unwrap().clone()
    }

    /// The console's TLS certificate handle, when it is served over TLS.
    pub fn tls(&self) -> Option<Arc<crate::tls::TlsHandle>> {
        self.tls.lock().unwrap().clone()
    }

    #[cfg(test)]
    pub fn set_tls_for_test(&self, h: Arc<crate::tls::TlsHandle>) {
        *self.tls.lock().unwrap() = Some(h);
    }

    /// The updater, when this process runs one.
    pub fn updater(&self) -> Option<Arc<crate::update::Updater>> {
        self.updater.lock().unwrap().clone()
    }

    /// Erase all inventory data. When a collector is running it does the work (so its memory is
    /// reset together with the database, and nothing is written back); otherwise (`denis serve`)
    /// `None` is returned and the caller erases the database itself.
    pub async fn erase_via_engine(&self) -> Option<Result<(), String>> {
        let tx = self.erase_tx.lock().unwrap().clone()?;
        let (reply, answer) = tokio::sync::oneshot::channel();
        tx.send(reply).await.ok()?;
        Some(answer.await.unwrap_or_else(|_| Err("the engine did not answer".into())))
    }

    /// Tests: stand in for the collector's rescanner.
    #[cfg(test)]
    pub fn set_rescanner_for_test(&self, tx: mpsc::Sender<RescanRequest>) {
        *self.rescan_tx.lock().unwrap() = Some(tx);
    }

    /// Scan these addresses again now and report what each one shows. `None` when this program cannot probe
    /// (viewer mode, or `--passive-only`) or the collector did not answer in time.
    pub async fn rescan(&self, ips: Vec<Ipv4Addr>) -> Option<Vec<(Ipv4Addr, RescanOutcome)>> {
        let tx = self.rescan_tx.lock().unwrap().clone()?;
        let (reply, answer) = tokio::sync::oneshot::channel();
        tx.send(RescanRequest { ips, reply }).await.ok()?;
        tokio::time::timeout(Duration::from_secs(60), answer).await.ok()?.ok()
    }

    fn update(&self, f: impl FnOnce(&mut StatusInfo)) {
        f(&mut self.info.lock().unwrap());
    }
}

/// A running collector and the streams it produces.
struct Collector {
    iface: Iface,
    inv: Arc<Mutex<Inventory>>,
    shared: Arc<Shared>,
    capture: CaptureThread,
    /// Closed flow / conversation windows.
    flow_rx: mpsc::Receiver<FlowBatch>,
    /// New assets and signals from each flush (assets already stored, with ids).
    new_rx: mpsc::UnboundedReceiver<Flushed>,
    scheduler: JoinHandle<()>,
    aggregator: JoinHandle<()>,
}

impl Collector {
    async fn start(cfg: &CollectorConfig, store: Arc<dyn Store>, mode: &'static str) -> Result<Collector> {
        let iface = net::select(cfg.iface.as_deref())?;
        let gateway = net::default_gateway().filter(|g| iface.net.contains(g));
        tracing::info!(
            "monitoring {} ({}) {} gateway={}",
            iface.name,
            iface.mac,
            iface.net,
            gateway.map(|g| g.to_string()).unwrap_or_else(|| "?".into())
        );
        let inv = Arc::new(Mutex::new(Inventory::new(crate::store::real_assets(&*store)?, gateway, None)));
        tracing::info!("{} known assets loaded from {}", inv.lock().unwrap().len(), cfg.db.display());

        // Open capture before anything else so a privilege problem is the first,
        // clearest error rather than a half-started daemon.
        let cap = capture::open(&iface, cfg.flows)?;

        let frames = Arc::new(AtomicU64::new(0));
        let mut notes = Vec::new();
        if cfg.passive_only {
            notes.push(NOTE_PASSIVE_ONLY.to_string());
        }
        if cfg.flows {
            notes.push(NOTE_FLOWS.to_string());
        }
        let shared = Arc::new(Shared {
            info: Mutex::new(StatusInfo {
                version: env!("CARGO_PKG_VERSION"),
                mode,
                interface: iface.name.clone(),
                ip: iface.ip,
                mac: iface.mac,
                subnet: iface.net.to_string(),
                gateway,
                started_at: now_ts(),
                passive_only: cfg.passive_only,
                flows_enabled: cfg.flows,
                ingest_listen: None,
                sweep_interval_secs: cfg.sweep_interval.as_secs(),
                sweeping: false,
                last_sweep_started: None,
                last_sweep_finished: None,
                learning_ends_at: None,
                min_score: 0,
                notes,
                frames_matched: 0,
                exports: Vec::new(),
            }),
            frames: frames.clone(),
            exports: Mutex::new(Vec::new()),
            detect_base: Mutex::new(None),
            channel_status: Default::default(),
            erase_tx: Mutex::new(None),
        rescan_tx: Mutex::new(None),
            updater: Mutex::new(None),
            tls: Mutex::new(None),
            scan_now: Notify::new(),
            capture_stats: Default::default(),
            db_path: cfg.db.clone(),
        });

        let (tx, mut rx) = mpsc::channel::<Observation>(4096);
        let (flow_tx, flow_rx) = mpsc::channel::<FlowBatch>(256);
        let (new_tx, new_rx) = mpsc::unbounded_channel::<Flushed>();
        let ctx = Ctx {
            subnet: iface.net,
            own_mac: iface.mac,
            own_ip: iface.ip,
            flows: cfg.flows,
            // Industrial decoding needs the same wide capture as flow accounting.
            ot: cfg.flows,
        };
        let capture = capture::spawn(cap, ctx, tx.clone(), frames, shared.capture_stats.clone());

        inv.lock().unwrap().apply(
            Observation::SelfHost {
                mac: iface.mac,
                ip: iface.ip,
                hostname: net::local_hostname(),
            },
            now_ts(),
        );

        // Aggregator: the only writer of the inventory.
        let (agg_inv, agg_store) = (inv.clone(), store);
        let aggregator = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tokio::select! {
                    obs = rx.recv() => match obs {
                        Some(Observation::Flows(f)) => {
                            if flow_tx.try_send(f).is_err() {
                                tracing::warn!("flow consumer is behind; dropping a window");
                            }
                        }
                        Some(obs) => agg_inv.lock().unwrap().apply(obs, now_ts()),
                        None => break,
                    },
                    _ = tick.tick() => {
                        let new = agg_inv.lock().unwrap().flush_now(&*agg_store);
                        if !new.is_empty() {
                            let _ = new_tx.send(new);
                        }
                    }
                }
            }
            let new = agg_inv.lock().unwrap().flush_now(&*agg_store);
            if !new.is_empty() {
                let _ = new_tx.send(new);
            }
        });

        if !cfg.passive_only {
            // confirming a fix: scan chosen devices again on request (never industrial devices: the caller filters
            // them, and excluded ranges are refused here)
            let (rescan_tx, rescan_rx) = mpsc::channel::<RescanRequest>(4);
            *shared.rescan_tx.lock().unwrap() = Some(rescan_tx);
            tokio::spawn(rescanner(cfg.exclude.clone(), cfg.scan_timeout, cfg.scan_concurrency, rescan_rx, tx.clone()));
        }

        let scheduler = tokio::spawn(schedule(
            SchedCfg {
                exclude: cfg.exclude.clone(),
                arp_pace: cfg.arp_pace,
                sweep_interval: cfg.sweep_interval,
                rescan_interval: cfg.rescan_interval,
                passive_only: cfg.passive_only,
                scan_timeout: cfg.scan_timeout,
                scan_concurrency: cfg.scan_concurrency,
            },
            iface.clone(),
            inv.clone(),
            tx,
            shared.clone(),
        ));

        Ok(Collector {
            iface,
            inv,
            shared,
            capture,
            flow_rx,
            new_rx,
            scheduler,
            aggregator,
        })
    }

    /// Stop everything and wait for the final database flush.
    async fn shutdown(self) {
        self.scheduler.abort();
        self.capture.stop(); // drops the capture's sender clone
        // The aborted scheduler held the last other sender, so the channel is
        // now closed and the aggregator performs its final flush.
        let _ = tokio::time::timeout(Duration::from_secs(5), self.aggregator).await;
    }
}

/// Reload the threat list when the file changed (a cron job may refresh it). A broken
/// new version is refused and the previous list stays in force.
fn refresh_threat_list(path: &std::path::Path, last: &mut Option<std::time::SystemTime>, det: &Mutex<Detector>) {
    let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified()) else { return };
    if *last == Some(modified) {
        return;
    }
    *last = Some(modified);
    match crate::threat::ThreatList::load(path) {
        Ok(list) => {
            tracing::info!("threat list reloaded: {} entries", list.entries);
            det.lock().unwrap().set_threat_list(list);
        }
        Err(e) => tracing::warn!("threat list not reloaded (keeping the old one): {e:#}"),
    }
}

/// Pick up rule settings an administrator saved in the portal: if the stored
/// value changed since `applied`, rebuild the configuration and hand it to the detector.
fn refresh_rules(store: &dyn Store, base: &DetectConfig, det: &Mutex<Detector>, applied: &mut Option<Vec<u8>>) {
    let Ok(now_stored) = store.get_setting(crate::rules::KEY) else { return };
    if now_stored == *applied {
        return;
    }
    let overrides = crate::rules::load(store).unwrap_or_default();
    det.lock().unwrap().set_config(overrides.apply(base));
    tracing::info!("detection rules updated from the portal");
    *applied = now_stored;
}

/// The one-time administrator password, shown on this terminal only.
fn print_first_start(pw: &str) {
    let line = |t: String| format!("  │ {t:<59} │");
    eprintln!(
        "\n  ┌─ FIRST START {}┐\n{}\n{}\n{}\n{}\n{}\n  └{}┘\n",
        "─".repeat(46),
        line("Created the administrator account:".into()),
        line("  username: admin".into()),
        line(format!("  password: {pw}")),
        line("It is shown only once and must be changed at first login.".into()),
        line("Lost it? Run:  denis user reset admin".into()),
        "─".repeat(61),
    );
}

/// How the console and the agent port are protected.
#[derive(Clone, Debug, Default)]
pub enum TlsMode {
    /// Plain HTTP (behind a reverse proxy or an SSH tunnel).
    #[default]
    Off,
    /// Certificate and key files the administrator maintains.
    Files(std::path::PathBuf, std::path::PathBuf),
    /// DENIS keeps the certificate in `dir`: generated automatically, replaceable by upload.
    Managed { dir: std::path::PathBuf, names: Vec<String> },
}

/// Settings of `denis serve`.
pub struct ServeConfig {
    pub db: std::path::PathBuf,
    pub listen: SocketAddr,
    pub no_auth: bool,
    pub public_url: Option<String>,
}

/// Web console over an existing database, with **no capture, no probing and no detection**.
/// For looking at a backup or a copy, for training and demonstrations, and for reviewing
/// an installation's data on another machine. Everything that reads or edits the register
/// works; live discovery does not.
pub async fn serve_only(cfg: ServeConfig) -> Result<()> {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&cfg.db)?);
    if cfg.no_auth && !cfg.listen.ip().is_loopback() {
        anyhow::bail!("--insecure-no-auth is only allowed when the UI listens on a loopback address");
    }
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.with_context(|| format!("binding web UI on {}", cfg.listen))?;
    let shared = Arc::new(Shared {
        info: Mutex::new(StatusInfo {
            version: env!("CARGO_PKG_VERSION"),
            mode: "viewer",
            interface: "-".into(),
            ip: Ipv4Addr::UNSPECIFIED,
            mac: Mac([0; 6]),
            subnet: "-".into(),
            gateway: None,
            started_at: now_ts(),
            passive_only: true,
            flows_enabled: false,
            ingest_listen: None,
            sweep_interval_secs: 300,
            sweeping: false,
            last_sweep_started: None,
            last_sweep_finished: None,
            learning_ends_at: None,
            min_score: DetectConfig::default().min_score,
            notes: vec![NOTE_VIEWER.into()],
            frames_matched: 0,
            exports: Vec::new(),
        }),
        frames: Arc::new(AtomicU64::new(0)),
        exports: Mutex::new(Vec::new()),
        detect_base: Mutex::new(Some(DetectConfig::default())),
        channel_status: Default::default(),
        erase_tx: Mutex::new(None),
        rescan_tx: Mutex::new(None),
        updater: Mutex::new(None),
        tls: Mutex::new(None),
        scan_now: Notify::new(),
        capture_stats: Default::default(),
        db_path: cfg.db.clone(),
    });
    let auth = Arc::new(Auth::new(store.clone()));
    *auth.passkey_cfg.lock().unwrap() = crate::passkey::Config::from_settings(cfg.public_url.as_deref(), cfg.listen, false).map_err(|e| anyhow::anyhow!(e))?;
    if cfg.no_auth {
        tracing::warn!("authentication is DISABLED (--insecure-no-auth): anyone who can reach the UI has full control");
    } else if let Some(pw) = auth.bootstrap(now_ts())? {
        print_first_start(&pw);
    }
    tracing::info!("viewer console on http://{} (no capture)", cfg.listen);
    web::serve(
        listener,
        web::AppState {
            store,
            shared,
            loopback_only: cfg.listen.ip().is_loopback(),
            allowed_hosts: Vec::new(),
            auth,
            no_auth: cfg.no_auth,
            secure_cookie: false,
        },
    )
    .await?;
    Ok(())
}

/// Standalone / master mode.
pub async fn run(cfg: Config) -> Result<()> {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&cfg.collector.db)?);
    if cfg.no_auth && !cfg.listen.ip().is_loopback() {
        anyhow::bail!("--insecure-no-auth is only allowed when the UI listens on a loopback address");
    }

    // Bind every port *before* the collector starts: a failed start (port
    // already taken, e.g. by a previous instance) must not have probed the network.
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding web UI on {}", cfg.listen))?;
    // Validate the certificate before anything is transmitted on the network.
    let tls: Option<Arc<crate::tls::TlsHandle>> = match &cfg.tls {
        TlsMode::Off => None,
        TlsMode::Files(cert, key) => Some(Arc::new(crate::tls::TlsHandle { config: crate::tls::load(cert, key).await?, dir: None, names: Vec::new() })),
        TlsMode::Managed { dir, names } => {
            let (d, n) = (dir.clone(), names.clone());
            let generated = tokio::task::spawn_blocking(move || crate::certs::ensure(&d, &n, now_ts())).await??;
            let config = crate::tls::load(&dir.join(crate::certs::SERVER_CERT), &dir.join(crate::certs::SERVER_KEY)).await?;
            let info = crate::certs::info(dir)?;
            tracing::info!(
                "TLS certificate ({}{}): {} · valid until {} · SHA-256 {}",
                info.source, if generated { ", just created" } else { "" }, info.subject, crate::report::iso(info.not_after)[..10].to_string(), info.fingerprint
            );
            if info.source == "generated" {
                tracing::info!("browsers will warn about the certificate until you trust {} (or upload your own in the console)", dir.join(crate::certs::CA_CERT).display());
            }
            Some(Arc::new(crate::tls::TlsHandle { config, dir: Some(dir.clone()), names: names.clone() }))
        }
    };

    let ingest_listener = match cfg.ingest_listen {
        Some(addr) => Some(
            tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding agent ingest on {addr}"))?,
        ),
        None => None,
    };

    let mode = if cfg.ingest_listen.is_some() { "master" } else { "standalone" };
    let mut coll = Collector::start(&cfg.collector, store.clone(), mode).await?;

    // --- detection
    let now = now_ts();
    let mut detect_cfg = cfg.detect.clone();
    // "Silent" needs the collector to keep last_seen fresh; a purely passive
    // collector can't tell "quiet" from "gone".
    detect_cfg.presence_enabled &= !cfg.collector.passive_only;
    coll.shared.detect_base.lock().unwrap().replace(detect_cfg.clone());
    let base_detect = detect_cfg.clone();
    // settings saved in the portal apply from the very first event
    let saved_rules = store.get_setting(crate::rules::KEY)?;
    let detect_cfg = crate::rules::load(&*store)?.apply(&detect_cfg);
    let mut det = Detector::new(detect_cfg, store.load_baselines()?, now);
    let mut threat_mtime = None;
    if let Some(path) = &cfg.threat_list {
        let list = crate::threat::ThreatList::load(path)?;
        tracing::info!("threat list loaded: {} entries from {}", list.entries, path.display());
        threat_mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        det.set_threat_list(list);
    }
    let threat_path = cfg.threat_list.clone();
    det.load_presence(store.load_presence()?);
    det.load_conversations(store.list_conversations()?);
    let local_start = crate::store::real_assets(&*store)?
        .iter()
        .filter(|a| a.agent_id.is_none())
        .map(|a| a.first_seen)
        .min();
    det.set_learning_start(None, local_start.unwrap_or(now));
    for a in store.list_agents()? {
        det.set_learning_start(Some(&a.id), a.first_seen);
    }
    let learning_ends = local_start.unwrap_or(now) + cfg.detect.learning_secs;
    coll.shared.update(|s| {
        s.learning_ends_at = Some(learning_ends);
        s.min_score = cfg.detect.min_score;
        s.ingest_listen = cfg.ingest_listen.map(|a| a.to_string());
    });
    if learning_ends > now {
        tracing::info!(
            "learning period: new devices and destinations are learned, not alerted on, for another {}",
            human(learning_ends - now)
        );
    }
    let detector = Arc::new(Mutex::new(det));
    // "Erase all data" from the console: database, collector memory and detector memory together.
    {
        let (tx, mut rx) = mpsc::channel::<EraseReply>(2);
        *coll.shared.erase_tx.lock().unwrap() = Some(tx);
        let (s, d, inv, shared) = (store.clone(), detector.clone(), coll.inv.clone(), coll.shared.clone());
        let learning = cfg.detect.learning_secs;
        tokio::spawn(async move {
            while let Some(reply) = rx.recv().await {
                let now = now_ts();
                // hold both locks so no task can write the old state back mid-way
                let mut inv = inv.lock().unwrap();
                let mut det = d.lock().unwrap();
                let res = s.erase_inventory().map_err(|e| format!("{e:#}"));
                if res.is_ok() {
                    inv.clear();
                    det.reset(now);
                    det.set_learning_start(None, now);
                    shared.update(|st| st.learning_ends_at = Some(now + learning));
                }
                drop((inv, det));
                let _ = reply.send(res);
            }
        });
    }
    let webhook = cfg
        .webhook
        .clone()
        .map(|url| (notify::spawn_webhook(url), cfg.webhook_min_score));
    let alerts = Arc::new(Alerts::new(store.clone(), webhook));

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    // self-update: look for new releases, install when told to (with a backup first)
    let mut restart_signal = None;
    if let Some(uc) = cfg.update.clone() {
        let up = crate::update::Updater::new(uc, store.clone());
        restart_signal = Some(up.shutdown.clone());
        *coll.shared.updater.lock().unwrap() = Some(up.clone());
        tasks.push(tokio::spawn(up.run()));
        tasks.push(tokio::spawn(crate::update::mark_healthy_later(cfg.collector.db.clone())));
    }

    // notification channels configured in the console (Slack, Teams, e-mail, PagerDuty, …)
    {
        let d = Arc::new(crate::channels::Dispatcher::new(
            coll.shared.channel_status.clone(),
            net::local_hostname().unwrap_or_default(),
            Duration::from_secs(1),
        ));
        tasks.push(tokio::spawn(crate::channels::run(d, store.clone())));
    }

    // saved reports on a schedule
    tasks.push(tokio::spawn(crate::reports::run(store.clone(), coll.shared.clone())));
    // scheduled backups of the database
    tasks.push(tokio::spawn(crate::backups::run(store.clone(), coll.shared.clone())));

    if let Some(sc) = cfg.syslog.clone() {
        let sl = Arc::new(crate::syslog::Syslog::new(sc));
        tracing::info!("sending alerts as syslog/CEF to {}", sl.status.lock().unwrap().target);
        coll.shared.exports.lock().unwrap().push(sl.status.clone());
        tasks.push(tokio::spawn(crate::syslog::run(sl, store.clone())));
    }

    if let Some(oc) = cfg.openobserve.clone() {
        let cleartext = oc.cleartext_remote();
        let sink = Arc::new(crate::sink::Sink::new(oc)?);
        if cleartext {
            tracing::warn!("OpenObserve export uses plain http:// to another host: the credentials and data are not encrypted in transit");
        }
        tracing::info!("exporting events, audit log, trends and inventory to OpenObserve at {}", sink.status.lock().unwrap().target);
        coll.shared.exports.lock().unwrap().push(sink.status.clone());
        tasks.push(tokio::spawn(crate::sink::run(sink, store.clone())));
    }

    // flow windows from the embedded collector -> detector
    let mut flow_rx = std::mem::replace(&mut coll.flow_rx, mpsc::channel(1).1);
    let (d, s, al) = (detector.clone(), store.clone(), alerts.clone());
    tasks.push(tokio::spawn(async move {
        while let Some(batch) = flow_rx.recv().await {
            let now = now_ts();
            let mut ev = d.lock().unwrap().ingest_flows(None, &batch.flows, &*s, now);
            ev.extend(d.lock().unwrap().ingest_conversations(None, &batch.convs, &*s, now));
            al.emit(ev);
        }
    }));

    // newly stored local assets and collector signals -> detector
    let mut new_rx = std::mem::replace(&mut coll.new_rx, mpsc::unbounded_channel().1);
    let (d, s, al) = (detector.clone(), store.clone(), alerts.clone());
    tasks.push(tokio::spawn(async move {
        while let Some(flushed) = new_rx.recv().await {
            let now = now_ts();
            // A device somebody registered by hand is known, not "new".
            let mut ev: Vec<_> = flushed
                .new_assets
                .iter()
                .filter(|a| !s.get_meta(a.id).ok().flatten().is_some_and(|m| m.manual))
                .flat_map(|a| d.lock().unwrap().on_new_asset(a, now))
                .collect();
            ev.extend(d.lock().unwrap().ingest_signals(None, &flushed.signals, &*s, now));
            al.emit(ev);
        }
    }));

    // periodic detector work + baseline persistence
    let (d, s, al) = (detector.clone(), store.clone(), alerts.clone());
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut n = 0u64;
        let mut applied_rules = saved_rules;
        loop {
            tick.tick().await;
            n += 1;
            refresh_rules(&*s, &base_detect, &d, &mut applied_rules);
            if n.is_multiple_of(12) {
                if let Some(p) = &threat_path {
                    refresh_threat_list(p, &mut threat_mtime, &d);
                }
            }
            let ev = d.lock().unwrap().tick(&*s, now_ts());
            al.emit(ev);
            if n.is_multiple_of(6) {
                if let Err(e) = d.lock().unwrap().flush(&*s) {
                    tracing::error!("saving baselines failed: {e:#}");
                }
            }
        }
    }));

    // "went silent" checks, trend samples and retention, every few minutes
    let online_window = cfg.collector.sweep_interval.as_secs() as i64 * 2 + 60;
    let retention = cfg.retention_days.max(1) * 86_400;
    let (d, s, al) = (detector.clone(), store.clone(), alerts.clone());
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        let mut last_sample = now_ts() / trends::SAMPLE_SECS * trends::SAMPLE_SECS;
        let mut last_prune = 0i64;
        let mut last_session_prune = 0i64;
        loop {
            tick.tick().await;
            let now = now_ts();
            if now - last_session_prune >= 3600 {
                let _ = s.prune_sessions(now);
                last_session_prune = now;
            }
            let ts = now / trends::SAMPLE_SECS * trends::SAMPLE_SECS;
            if ts <= last_sample {
                continue;
            }
            let ev = d.lock().unwrap().tick_presence(&*s, now);
            al.emit(ev);

            let traffic = d.lock().unwrap().take_traffic();
            let result = (|| -> anyhow::Result<()> {
                let assets = crate::store::real_assets(&*s)?;
                let alerts = s.list_events(&EventQuery { limit: 5000, alerts_only: true, ..Default::default() })?;
                let fresh: Vec<_> = alerts.into_iter().filter(|e| e.timestamp > last_sample).collect();
                s.insert_metrics(&trends::build_metrics(&assets, &traffic, &fresh, online_window, now))?;
                if now - last_prune >= 3600 {
                    s.prune_metrics(now - retention)?;
                    last_prune = now;
                }
                Ok(())
            })();
            match result {
                Ok(()) => last_sample = ts,
                Err(e) => tracing::error!("recording trend sample failed: {e:#}"),
            }
        }
    }));

    // --- web UI (loopback, no auth) and, optionally, the agent ingest listener
    let auth = Arc::new(Auth::new(store.clone()));
    let passkeys = crate::passkey::Config::from_settings(cfg.public_url.as_deref(), cfg.listen, !matches!(cfg.tls, TlsMode::Off)).map_err(|e| anyhow::anyhow!(e))?;
    match &passkeys {
        Some(p) => tracing::info!("passkeys enabled for {}", p.origins.join(", ")),
        None => tracing::info!("passkeys are off (set --public-url https://your-address to enable them)"),
    }
    *auth.passkey_cfg.lock().unwrap() = passkeys;
    if !cfg.no_auth {
        if let Some(pw) = auth.bootstrap(now_ts())? {
            print_first_start(&pw);
        }
    } else {
        tracing::warn!("authentication is DISABLED (--insecure-no-auth): anyone who can reach the UI has full control");
    }
    *coll.shared.tls.lock().unwrap() = tls.clone();
    let web_state = web::AppState {
        store: store.clone(),
        shared: coll.shared.clone(),
        loopback_only: cfg.listen.ip().is_loopback(),
        allowed_hosts: {
            // the public address a proxy forwards is, by definition, an expected Host
            let mut h = cfg.allowed_hosts.clone();
            if let Some(host) = cfg.public_url.as_deref().and_then(|u| u.split_once("://")).map(|(_, r)| r.trim_end_matches('/')).map(|a| a.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(a, |(h, _)| h).to_string()) {
                h.push(host);
            }
            h
        },
        auth: auth.clone(),
        no_auth: cfg.no_auth,
        // over HTTPS the cookie must never travel in clear
        secure_cookie: cfg.secure_cookie || tls.is_some(),
    };
    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!("web UI on {scheme}://{}", cfg.listen);
    let server = match &tls {
        Some(h) => {
            match (&cfg.tls, &h.dir) {
                (TlsMode::Files(c, k), _) => tasks.push(crate::tls::spawn_reloader(h.config.clone(), c.clone(), k.clone())),
                (_, Some(_)) => tasks.push(crate::tls::spawn_managed_reloader(h.clone())),
                _ => {}
            }
            tokio::spawn(web::serve_tls(listener, web_state, h.config.clone()))
        }
        None => tokio::spawn(web::serve(listener, web_state)),
    };

    if let (Some(addr), Some(l)) = (cfg.ingest_listen, ingest_listener) {
        let ing = Arc::new(Ingest::new(store.clone(), detector.clone(), alerts.clone(), auth.clone()));
        let rc = tls.as_ref().map(|h| h.config.clone());
        if rc.is_some() {
            tracing::info!("accepting agents on https://{addr} (per-agent bearer tokens)");
        } else {
            tracing::info!("accepting agents on http://{addr} (per-agent bearer tokens; TLS is off (--no-tls): use a tunnel or a TLS proxy across untrusted networks)");
        }
        tasks.push(tokio::spawn(async move {
            let res = match rc {
                Some(rc) => crate::tls::serve(l, ingest::router(ing), rc).await,
                None => axum::serve(l, ingest::router(ing).into_make_service_with_connect_info::<SocketAddr>()).await,
            };
            if let Err(e) = res {
                tracing::error!("ingest listener exited: {e}");
            }
        }));
    }

    let restart = async {
        match &restart_signal {
            Some(n) => n.notified().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
        _ = restart => tracing::info!("shutting down to start the updated version"),
        r = server => tracing::error!("web server exited: {r:?}"),
    }
    for t in &tasks {
        t.abort();
    }
    coll.shutdown().await;
    if let Err(e) = detector.lock().unwrap().flush(&*store) {
        tracing::error!("saving baselines failed: {e:#}");
    }
    Ok(())
}

pub struct AgentRunConfig {
    pub collector: CollectorConfig,
    pub agent: AgentConfig,
}

/// Remote agent mode: collect locally, push to the master.
pub async fn run_agent(cfg: AgentRunConfig) -> Result<()> {
    let (base, token) = (cfg.agent.master_url.clone(), cfg.agent.token.clone());
    let client = agent::http_client(cfg.agent.ca_cert.as_deref())?;
    tokio::task::spawn_blocking(move || agent::check_master(&client, &base, &token)).await??;
    tracing::info!("master reachable at {}", cfg.agent.master_url);

    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&cfg.collector.db)?);
    let mut coll = Collector::start(&cfg.collector, store, "agent").await?;
    let mut agent_cfg = cfg.agent;
    agent_cfg.meta.subnet = coll.iface.net.to_string();

    // The agent only forwards; judging happens at the master.
    let mut new_rx = std::mem::replace(&mut coll.new_rx, mpsc::unbounded_channel().1);
    let (sig_tx, sig_rx) = mpsc::unbounded_channel::<Vec<Signal>>();
    let drain = tokio::spawn(async move {
        while let Some(f) = new_rx.recv().await {
            if !f.signals.is_empty() {
                let _ = sig_tx.send(f.signals);
            }
        }
    });
    let flow_rx = std::mem::replace(&mut coll.flow_rx, mpsc::channel(1).1);
    let reporter = tokio::spawn(agent::run(agent_cfg, coll.inv.clone(), flow_rx, sig_rx));

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    reporter.abort();
    drain.abort();
    coll.shutdown().await;
    Ok(())
}

fn human(secs: i64) -> String {
    match secs {
        s if s >= 3600 => format!("{:.1} h", s as f64 / 3600.0),
        s if s >= 60 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

struct SchedCfg {
    exclude: Vec<Ipv4Net>,
    arp_pace: Duration,
    sweep_interval: Duration,
    rescan_interval: Duration,
    passive_only: bool,
    scan_timeout: Duration,
    scan_concurrency: usize,
}

async fn schedule(
    cfg: SchedCfg,
    iface: Iface,
    inv: Arc<Mutex<Inventory>>,
    tx: mpsc::Sender<Observation>,
    shared: Arc<Shared>,
) {
    let mut force = false;
    loop {
        if !cfg.passive_only {
            shared.update(|s| {
                s.sweeping = true;
                s.last_sweep_started = Some(now_ts());
            });
            if let Err(e) = sweep_cycle(&cfg, &iface, &inv, &tx, force).await {
                tracing::warn!("sweep failed: {e:#}");
                shared.update(|s| s.notes.push(format!("sweep failed: {e:#}")));
            }
            shared.update(|s| {
                s.sweeping = false;
                s.last_sweep_finished = Some(now_ts());
                s.notes.truncate(5);
            });
        }
        force = false;
        tokio::select! {
            _ = tokio::time::sleep(cfg.sweep_interval) => {}
            _ = shared.scan_now.notified() => force = !cfg.passive_only,
        }
    }
}

/// Answers "scan these devices again": each address is probed like a normal port scan, and what it shows is both
/// reported back and fed into the inventory (so the register shows the fresh port list too).
async fn rescanner(exclude: Vec<Ipv4Net>, timeout: Duration, concurrency: usize, mut rx: mpsc::Receiver<RescanRequest>, tx: mpsc::Sender<Observation>) {
    while let Some(req) = rx.recv().await {
        let sem = Arc::new(Semaphore::new(concurrency.max(1)));
        let mut out = Vec::new();
        for ip in req.ips.into_iter().take(200) {
            if exclude.iter().any(|n| n.contains(&ip)) {
                out.push((ip, RescanOutcome::Excluded));
                continue;
            }
            let (open, mut answered) = active::scan_host_probe(ip, sem.clone(), timeout).await;
            if !answered {
                // some hosts drop every connection but answer a ping
                answered = active::icmp_sweep(&[ip], Duration::from_millis(800)).await.unwrap_or(0) > 0;
            }
            if answered {
                let _ = tx.send(Observation::Ports { ip, open: open.clone() }).await;
                out.push((ip, RescanOutcome::Scanned(open)));
            } else {
                out.push((ip, RescanOutcome::Unreachable));
            }
        }
        let _ = req.reply.send(out);
    }
}

/// Remove excluded addresses from a sweep's target list.
fn probe_targets(targets: Vec<Ipv4Addr>, exclude: &[Ipv4Net]) -> Vec<Ipv4Addr> {
    targets.into_iter().filter(|ip| !exclude.iter().any(|n| n.contains(ip))).collect()
}

async fn sweep_cycle(
    cfg: &SchedCfg,
    iface: &Iface,
    inv: &Arc<Mutex<Inventory>>,
    tx: &mpsc::Sender<Observation>,
    force_ports: bool,
) -> Result<()> {
    let started = now_ts();
    let (targets, clamped) = net::sweep_targets(iface.net, iface.ip);
    let targets = probe_targets(targets, &cfg.exclude);
    if clamped {
        tracing::warn!("{} is large; sweeping only our /24", iface.net);
    }
    tracing::info!("ARP sweep of {} addresses", targets.len());
    let (i, t, pace) = (iface.clone(), targets, cfg.arp_pace);
    tokio::task::spawn_blocking(move || active::arp_sweep(&i, &t, pace)).await??;
    // Replies flow through the capture thread; give the last ones time to land.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let live = inv.lock().unwrap().live_hosts(started);
    tracing::info!("{} hosts answered", live.len());

    // Never send anything to excluded ranges, and never ping or port-scan
    // industrial devices (some PLC firmware falls over on unexpected connections).
    let probeable: Vec<&crate::inventory::LiveHost> = live
        .iter()
        .filter(|h| !cfg.exclude.iter().any(|n| n.contains(&h.ip)))
        .collect();
    let skipped_ot = probeable.iter().filter(|h| h.ot).count();
    if skipped_ot > 0 {
        tracing::info!("{skipped_ot} industrial device(s) are observed passively only (never pinged or port-scanned)");
    }
    let ips: Vec<Ipv4Addr> = probeable.iter().filter(|h| !h.ot).map(|h| h.ip).collect();
    match active::icmp_sweep(&ips, Duration::from_millis(800)).await {
        Ok(n) => tracing::info!("ICMP: {n}/{} answered", ips.len()),
        Err(e) => tracing::warn!("ICMP sweep skipped: {e:#}"),
    }

    let cutoff = started - cfg.rescan_interval.as_secs() as i64;
    let to_scan: Vec<Ipv4Addr> = probeable
        .iter()
        .filter(|h| !h.ot && (force_ports || h.ports_scanned_at.is_none_or(|t| t <= cutoff)))
        .map(|h| h.ip)
        .collect();
    if to_scan.is_empty() {
        return Ok(());
    }
    tracing::info!("port-scanning {} hosts", to_scan.len());
    let sem = Arc::new(Semaphore::new(cfg.scan_concurrency));
    let mut set = JoinSet::new();
    for ip in to_scan {
        let (sem, timeout) = (sem.clone(), cfg.scan_timeout);
        set.spawn(async move { (ip, active::scan_host(ip, sem, timeout).await) });
    }
    let mut done = 0;
    while let Some(r) = set.join_next().await {
        if let Ok((ip, open)) = r {
            done += 1;
            if tx.send(Observation::Ports { ip, open }).await.is_err() {
                break;
            }
        }
    }
    tracing::info!("port scan finished ({done} hosts, {}s)", now_ts() - started);
    Ok(())
}

#[cfg(test)]
pub fn test_shared() -> Arc<Shared> {
    test_shared_at(std::path::PathBuf::new())
}

/// As `test_shared`, with a database path (its `backups` folder is where backups go).
pub fn test_shared_at(db_path: std::path::PathBuf) -> Arc<Shared> {
    Arc::new(Shared {
        info: Mutex::new(StatusInfo {
            version: "test",
            mode: "standalone",
            interface: "test0".into(),
            ip: Ipv4Addr::new(192, 168, 1, 2),
            mac: Mac([2, 0, 0, 0, 0, 1]),
            subnet: "192.168.1.0/24".into(),
            gateway: None,
            started_at: 0,
            passive_only: false,
            flows_enabled: false,
            ingest_listen: None,
            sweep_interval_secs: 300,
            sweeping: false,
            last_sweep_started: None,
            last_sweep_finished: None,
            learning_ends_at: None,
            min_score: 30,
            notes: vec![],
            frames_matched: 0,
            exports: Vec::new(),
        }),
        frames: Arc::new(AtomicU64::new(0)),
        exports: Mutex::new(Vec::new()),
        detect_base: Mutex::new(Some(DetectConfig::default())),
        channel_status: Default::default(),
        erase_tx: Mutex::new(None),
        rescan_tx: Mutex::new(None),
        updater: Mutex::new(None),
        tls: Mutex::new(None),
        scan_now: Notify::new(),
        capture_stats: Default::default(),
        db_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excluded_ranges_are_never_probed() {
        let cfg = CollectorConfig { exclude: vec!["10.0.5.0/24".parse().unwrap(), "10.0.9.7/32".parse().unwrap()], ..Default::default() };
        assert!(cfg.may_probe(Ipv4Addr::new(10, 0, 4, 9)));
        assert!(!cfg.may_probe(Ipv4Addr::new(10, 0, 5, 200)));
        assert!(!cfg.may_probe(Ipv4Addr::new(10, 0, 9, 7)));
        assert!(cfg.may_probe(Ipv4Addr::new(10, 0, 9, 8)));
        let all: Vec<Ipv4Addr> = (1..=254u8).map(|i| Ipv4Addr::new(10, 0, 5, i)).chain([Ipv4Addr::new(10, 0, 6, 1), Ipv4Addr::new(10, 0, 9, 7)]).collect();
        assert_eq!(probe_targets(all, &cfg.exclude), vec![Ipv4Addr::new(10, 0, 6, 1)]);
    }

    #[test]
    fn saved_rule_settings_reach_the_running_detector_once_and_only_when_changed() {
        let store = SqliteStore::open_in_memory().unwrap();
        let base = DetectConfig::default();
        let det = Mutex::new(Detector::new(base.clone(), vec![], 0));
        let mut applied = None;
        refresh_rules(&store, &base, &det, &mut applied);
        assert_eq!(det.lock().unwrap().config().min_score, 30, "nothing saved: unchanged");
        let mut o = crate::rules::Overrides::default();
        o.patch(&serde_json::json!({"min_score": 60, "weights": {"new_device": 0}})).unwrap();
        crate::rules::save(&store, &o, 1).unwrap();
        refresh_rules(&store, &base, &det, &mut applied);
        assert_eq!(det.lock().unwrap().config().min_score, 60);
        assert_eq!(det.lock().unwrap().config().weights["new_device"], 0.0);
        // reset: back to the base
        crate::rules::save(&store, &crate::rules::Overrides::default(), 2).unwrap();
        refresh_rules(&store, &base, &det, &mut applied);
        assert_eq!(det.lock().unwrap().config().min_score, 30);
        assert!(!det.lock().unwrap().config().weights.contains_key("new_device"));
    }

    #[test]
    fn a_changed_threat_list_is_reloaded_and_a_broken_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-ips.txt");
        let det = Mutex::new(Detector::new(DetectConfig::default(), vec![], 0));
        std::fs::write(&path, "203.0.113.9\n").unwrap();
        let mut last = None;
        refresh_threat_list(&path, &mut last, &det);
        assert_eq!(det.lock().unwrap().threat_entries(), 1);
        refresh_threat_list(&path, &mut last, &det); // unchanged: nothing to do
        // a truncated download must not wipe the protection
        std::fs::write(&path, "1.1.1.1\n2.2.2.2\n3.3.3.3\n<html>error</html>\n").unwrap();
        last = None;
        refresh_threat_list(&path, &mut last, &det);
        assert_eq!(det.lock().unwrap().threat_entries(), 1, "the old list stays");
        std::fs::write(&path, "1.1.1.1\n2.2.2.2\n").unwrap();
        last = None;
        refresh_threat_list(&path, &mut last, &det);
        assert_eq!(det.lock().unwrap().threat_entries(), 2);
    }

    #[tokio::test]
    async fn a_rescan_reports_what_answers_what_is_excluded_and_what_says_nothing() {
        let (obs_tx, mut obs_rx) = mpsc::channel(16);
        let (tx, rx) = mpsc::channel(4);
        let exclude: Vec<Ipv4Net> = vec!["10.99.0.0/16".parse().unwrap()];
        tokio::spawn(rescanner(exclude, Duration::from_millis(300), 16, rx, obs_tx));
        let (reply, answer) = tokio::sync::oneshot::channel();
        let local = Ipv4Addr::LOCALHOST;
        tx.send(RescanRequest { ips: vec![local, Ipv4Addr::new(10, 99, 1, 1), Ipv4Addr::new(240, 0, 0, 1)], reply }).await.unwrap();
        let out = answer.await.unwrap();
        // this machine answers (a refused connection is an answer), the excluded range is never touched,
        // and an address nobody answers for proves nothing
        assert!(matches!(out[0], (ip, RescanOutcome::Scanned(_)) if ip == local), "{out:?}");
        assert_eq!(out[1].1, RescanOutcome::Excluded);
        assert_eq!(out[2].1, RescanOutcome::Unreachable);
        // what was found also reaches the inventory, so the register shows the fresh port list; the silent host does not wipe it
        match obs_rx.try_recv() {
            Ok(Observation::Ports { ip, .. }) => assert_eq!(ip, local),
            other => panic!("expected the fresh ports of the answering host, got {other:?}"),
        }
        assert!(obs_rx.try_recv().is_err(), "nothing was reported for the excluded or the silent address");
    }
}
