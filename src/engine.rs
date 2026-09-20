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
use serde::Serialize;
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

use crate::agent::{self, AgentConfig};
use crate::capture::{self, CaptureThread};
use crate::detect::{DetectConfig, Detector};
use crate::ingest::{self, Ingest};
use crate::inventory::Inventory;
use crate::model::{now_ts, Asset, FlowRecord, Mac, Observation};
use crate::net::{self, Iface};
use crate::notify::{self, Alerts};
use crate::parse::Ctx;
use crate::store::sqlite::SqliteStore;
use crate::store::Store;
use crate::{active, web};

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
    /// Account traffic to/from outside the subnet (input to the anomaly rules).
    pub flows: bool,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        CollectorConfig {
            iface: None,
            db: PathBuf::from("netscope.db"),
            sweep_interval: Duration::from_secs(300),
            rescan_interval: Duration::from_secs(1800),
            passive_only: false,
            scan_timeout: Duration::from_millis(800),
            scan_concurrency: 64,
            flows: false,
        }
    }
}

pub struct Config {
    pub collector: CollectorConfig,
    pub listen: SocketAddr,
    /// Accept remote agents here (requires `agent_token`). Off by default.
    pub ingest_listen: Option<SocketAddr>,
    pub agent_token: Option<String>,
    pub detect: DetectConfig,
    pub webhook: Option<String>,
    pub webhook_min_score: i32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            collector: CollectorConfig::default(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            ingest_listen: None,
            agent_token: None,
            detect: DetectConfig::default(),
            webhook: None,
            webhook_min_score: 60,
        }
    }
}

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
}

/// State shared between the engine tasks and the web layer.
pub struct Shared {
    info: Mutex<StatusInfo>,
    frames: Arc<AtomicU64>,
    /// Wakes the scheduler for an immediate sweep + full port rescan.
    pub scan_now: Notify,
}

impl Shared {
    pub fn snapshot(&self) -> StatusInfo {
        let mut s = self.info.lock().unwrap().clone();
        s.frames_matched = self.frames.load(Ordering::Relaxed);
        s
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
    /// Closed flow windows.
    flow_rx: mpsc::Receiver<Vec<FlowRecord>>,
    /// Assets seen for the first time (already stored, with ids).
    new_rx: mpsc::UnboundedReceiver<Vec<Asset>>,
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
        let inv = Arc::new(Mutex::new(Inventory::new(store.load_assets()?, gateway, None)));
        tracing::info!("{} known assets loaded from {}", inv.lock().unwrap().len(), cfg.db.display());

        // Open capture before anything else so a privilege problem is the first,
        // clearest error rather than a half-started daemon.
        let cap = capture::open(&iface, cfg.flows)?;

        let frames = Arc::new(AtomicU64::new(0));
        let mut notes = Vec::new();
        if cfg.passive_only {
            notes.push("passive-only: no packets are transmitted".to_string());
        }
        if cfg.flows {
            notes.push("flow accounting on: anomaly rules see only traffic that crosses this interface".to_string());
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
            }),
            frames: frames.clone(),
            scan_now: Notify::new(),
        });

        let (tx, mut rx) = mpsc::channel::<Observation>(4096);
        let (flow_tx, flow_rx) = mpsc::channel::<Vec<FlowRecord>>(256);
        let (new_tx, new_rx) = mpsc::unbounded_channel::<Vec<Asset>>();
        let ctx = Ctx {
            subnet: iface.net,
            own_mac: iface.mac,
            own_ip: iface.ip,
            flows: cfg.flows,
        };
        let capture = capture::spawn(cap, ctx, tx.clone(), frames);

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

        let scheduler = tokio::spawn(schedule(
            SchedCfg {
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

/// Standalone / master mode.
pub async fn run(cfg: Config) -> Result<()> {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&cfg.collector.db)?);
    if cfg.ingest_listen.is_some() && cfg.agent_token.as_deref().is_none_or(|t| t.len() < 16) {
        anyhow::bail!("--ingest-listen needs --agent-token (or NETSCOPE_AGENT_TOKEN) of at least 16 characters");
    }

    let mode = if cfg.ingest_listen.is_some() { "master" } else { "standalone" };
    let mut coll = Collector::start(&cfg.collector, store.clone(), mode).await?;
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding web UI on {}", cfg.listen))?;

    // --- detection
    let now = now_ts();
    let mut det = Detector::new(cfg.detect.clone(), store.load_baselines()?, now);
    let local_start = store
        .load_assets()?
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
    let webhook = cfg
        .webhook
        .clone()
        .map(|url| (notify::spawn_webhook(url), cfg.webhook_min_score));
    let alerts = Arc::new(Alerts::new(store.clone(), webhook));

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    // flow windows from the embedded collector -> detector
    let mut flow_rx = std::mem::replace(&mut coll.flow_rx, mpsc::channel(1).1);
    let (d, s, al) = (detector.clone(), store.clone(), alerts.clone());
    tasks.push(tokio::spawn(async move {
        while let Some(flows) = flow_rx.recv().await {
            let ev = d.lock().unwrap().ingest_flows(None, &flows, &*s, now_ts());
            al.emit(ev);
        }
    }));

    // newly stored local assets -> detector
    let mut new_rx = std::mem::replace(&mut coll.new_rx, mpsc::unbounded_channel().1);
    let (d, al) = (detector.clone(), alerts.clone());
    tasks.push(tokio::spawn(async move {
        while let Some(assets) = new_rx.recv().await {
            let now = now_ts();
            let ev: Vec<_> = assets
                .iter()
                .flat_map(|a| d.lock().unwrap().on_new_asset(a, now))
                .collect();
            al.emit(ev);
        }
    }));

    // periodic detector work + baseline persistence
    let (d, s, al) = (detector.clone(), store.clone(), alerts.clone());
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut n = 0u64;
        loop {
            tick.tick().await;
            n += 1;
            let ev = d.lock().unwrap().tick(&*s, now_ts());
            al.emit(ev);
            if n.is_multiple_of(6) {
                if let Err(e) = d.lock().unwrap().flush(&*s) {
                    tracing::error!("saving baselines failed: {e:#}");
                }
            }
        }
    }));

    // --- web UI (loopback, no auth) and, optionally, the agent ingest listener
    let web_state = web::AppState {
        store: store.clone(),
        shared: coll.shared.clone(),
        loopback_only: cfg.listen.ip().is_loopback(),
    };
    tracing::info!("web UI on http://{}", cfg.listen);
    let server = tokio::spawn(web::serve(listener, web_state));

    if let (Some(addr), Some(token)) = (cfg.ingest_listen, cfg.agent_token.clone()) {
        let l = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding agent ingest on {addr}"))?;
        let ing = Arc::new(Ingest::new(store.clone(), detector.clone(), alerts.clone(), token));
        tracing::info!(
            "accepting agents on http://{addr} (bearer token; no TLS - use a tunnel or a TLS proxy across untrusted networks)"
        );
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(l, ingest::router(ing)).await {
                tracing::error!("ingest listener exited: {e}");
            }
        }));
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
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
    tokio::task::spawn_blocking(move || agent::check_master(&base, &token)).await??;
    tracing::info!("master reachable at {}", cfg.agent.master_url);

    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&cfg.collector.db)?);
    let mut coll = Collector::start(&cfg.collector, store, "agent").await?;
    let mut agent_cfg = cfg.agent;
    agent_cfg.meta.subnet = coll.iface.net.to_string();

    // The agent only forwards; judging happens at the master.
    let mut new_rx = std::mem::replace(&mut coll.new_rx, mpsc::unbounded_channel().1);
    let drain = tokio::spawn(async move { while new_rx.recv().await.is_some() {} });
    let flow_rx = std::mem::replace(&mut coll.flow_rx, mpsc::channel(1).1);
    let reporter = tokio::spawn(agent::run(agent_cfg, coll.inv.clone(), flow_rx));

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

async fn sweep_cycle(
    cfg: &SchedCfg,
    iface: &Iface,
    inv: &Arc<Mutex<Inventory>>,
    tx: &mpsc::Sender<Observation>,
    force_ports: bool,
) -> Result<()> {
    let started = now_ts();
    let (targets, clamped) = net::sweep_targets(iface.net, iface.ip);
    if clamped {
        tracing::warn!("{} is large; sweeping only our /24", iface.net);
    }
    tracing::info!("ARP sweep of {} addresses", targets.len());
    let (i, t) = (iface.clone(), targets);
    tokio::task::spawn_blocking(move || active::arp_sweep(&i, &t)).await??;
    // Replies flow through the capture thread; give the last ones time to land.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let live = inv.lock().unwrap().live_hosts(started);
    tracing::info!("{} hosts answered", live.len());

    let ips: Vec<Ipv4Addr> = live.iter().map(|(ip, _)| *ip).collect();
    match active::icmp_sweep(&ips, Duration::from_millis(800)).await {
        Ok(n) => tracing::info!("ICMP: {n}/{} answered", ips.len()),
        Err(e) => tracing::warn!("ICMP sweep skipped: {e:#}"),
    }

    let cutoff = started - cfg.rescan_interval.as_secs() as i64;
    let to_scan: Vec<Ipv4Addr> = live
        .iter()
        .filter(|(_, scanned)| force_ports || scanned.is_none_or(|t| t <= cutoff))
        .map(|(ip, _)| *ip)
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
        }),
        frames: Arc::new(AtomicU64::new(0)),
        scan_now: Notify::new(),
    })
}
