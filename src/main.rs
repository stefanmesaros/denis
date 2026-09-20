use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use netscope::agent::AgentConfig;
use netscope::detect::{DetectConfig, RULE_NEW_DESTINATION, RULE_NEW_DEVICE, RULE_VOLUME};
use netscope::model::{now_ts, AgentMeta};
use netscope::store::sqlite::SqliteStore;
use netscope::store::{EventQuery, Store};
use netscope::{engine, net};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Network asset discovery and fingerprinting")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// Options shared by the standalone/master and agent modes.
#[derive(clap::Args)]
struct Collect {
    /// Interface to monitor (default: the one holding the default route).
    #[arg(short, long)]
    iface: Option<String>,
    /// Seconds between ARP sweeps.
    #[arg(long, default_value_t = 300)]
    sweep_interval: u64,
    /// Minimum seconds between port scans of the same host.
    #[arg(long, default_value_t = 1800)]
    rescan_interval: u64,
    /// Capture only; never transmit ARP, ICMP or TCP probes.
    #[arg(long)]
    passive_only: bool,
    /// Account traffic to/from outside the subnet (input for the anomaly rules).
    /// Captures every IPv4 frame, so it only sees traffic that crosses this
    /// interface: run on the gateway or a mirror port for whole-network coverage.
    #[arg(long)]
    flows: bool,
}

impl Collect {
    fn into_config(self, db: PathBuf) -> engine::CollectorConfig {
        engine::CollectorConfig {
            iface: self.iface,
            db,
            sweep_interval: Duration::from_secs(self.sweep_interval.max(30)),
            rescan_interval: Duration::from_secs(self.rescan_interval),
            passive_only: self.passive_only,
            flows: self.flows,
            ..Default::default()
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Standalone or master: discover devices, detect anomalies, serve the web UI.
    /// Add --ingest-listen to also accept remote agents.
    Run {
        #[command(flatten)]
        collect: Collect,
        /// Web UI listen address. The UI has no authentication: keep it on loopback.
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// SQLite database file.
        #[arg(long, default_value = "netscope.db")]
        db: PathBuf,
        /// Accept remote agents on this address (bearer-token authenticated).
        #[arg(long)]
        ingest_listen: Option<SocketAddr>,
        /// Shared secret agents must present (>= 16 chars). Prefer the environment
        /// variable: command-line arguments are visible to other local users.
        #[arg(long, env = "NETSCOPE_AGENT_TOKEN", hide_env_values = true)]
        agent_token: Option<String>,
        /// Minutes a device/site is observed before its new destinations and
        /// devices count as anomalies (until then they are just learned).
        #[arg(long, default_value_t = 1440)]
        learning_minutes: i64,
        /// Scores below this are logged as info, not raised as alerts.
        #[arg(long, default_value_t = 30)]
        min_score: i32,
        /// Scale a rule's score: RULE=WEIGHT, e.g. new_destination=0.5 (0 disables).
        /// Rules: new_device, new_destination, volume_anomaly. Repeatable.
        #[arg(long = "rule-weight", value_parser = parse_weight)]
        rule_weights: Vec<(String, f64)>,
        /// POST alerts as JSON to this URL (Slack/Discord-compatible).
        #[arg(long, env = "NETSCOPE_WEBHOOK", hide_env_values = true)]
        webhook: Option<String>,
        /// Only alerts at or above this score go to the webhook.
        #[arg(long, default_value_t = 60)]
        webhook_min_score: i32,
        /// Volume buckets: seconds per bucket.
        #[arg(long, default_value_t = 300)]
        bucket_secs: i64,
        /// Volume rule: ignore buckets smaller than this many MB.
        #[arg(long, default_value_t = 5.0)]
        min_volume_mb: f64,
        /// Volume rule: buckets needed before a device's baseline is trusted.
        #[arg(long, default_value_t = 12)]
        min_samples: u32,
    },
    /// Remote agent: collect on this network and report to a master.
    Agent {
        #[command(flatten)]
        collect: Collect,
        /// Master ingest URL, e.g. http://192.168.1.10:8081
        #[arg(long)]
        master: String,
        #[arg(long, env = "NETSCOPE_AGENT_TOKEN", hide_env_values = true)]
        token: String,
        /// Stable identifier for this agent ([A-Za-z0-9._-], default: hostname).
        #[arg(long)]
        id: Option<String>,
        /// Display name (default: the id).
        #[arg(long)]
        name: Option<String>,
        /// Site/location label.
        #[arg(long)]
        site: Option<String>,
        /// The agent's own database (its inventory survives restarts).
        #[arg(long, default_value = "netscope-agent.db")]
        db: PathBuf,
        /// Seconds between reports.
        #[arg(long, default_value_t = 15)]
        report_interval: u64,
    },
    /// List usable network interfaces.
    Interfaces,
    /// Print the inventory from the database.
    List {
        #[arg(long, default_value = "netscope.db")]
        db: PathBuf,
    },
    /// Print alerts from the database.
    Alerts {
        #[arg(long, default_value = "netscope.db")]
        db: PathBuf,
        /// Include info-level events (e.g. devices learned during the learning period).
        #[arg(long)]
        all: bool,
    },
}

fn parse_weight(s: &str) -> Result<(String, f64), String> {
    let (rule, w) = s.split_once('=').ok_or("expected RULE=WEIGHT")?;
    if ![RULE_NEW_DEVICE, RULE_NEW_DESTINATION, RULE_VOLUME].contains(&rule) {
        return Err(format!("unknown rule {rule:?} (new_device, new_destination, volume_anomaly)"));
    }
    let w: f64 = w.parse().map_err(|_| format!("bad weight {w:?}"))?;
    if !(0.0..=5.0).contains(&w) {
        return Err("weight must be between 0 and 5".into());
    }
    Ok((rule.to_string(), w))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "netscope=info".into()))
        .with_target(false)
        .init();

    match Cli::parse().cmd {
        Cmd::Run {
            collect,
            listen,
            db,
            ingest_listen,
            agent_token,
            learning_minutes,
            min_score,
            rule_weights,
            webhook,
            webhook_min_score,
            bucket_secs,
            min_volume_mb,
            min_samples,
        } => {
            let detect = DetectConfig {
                learning_secs: learning_minutes.max(0) * 60,
                min_score,
                weights: rule_weights.into_iter().collect(),
                bucket_secs: bucket_secs.max(10),
                min_volume_bytes: (min_volume_mb.max(0.0) * 1e6) as u64,
                min_samples,
                ..Default::default()
            };
            engine::run(engine::Config {
                collector: collect.into_config(db),
                listen,
                ingest_listen,
                agent_token,
                detect,
                webhook,
                webhook_min_score,
            })
            .await
        }
        Cmd::Agent {
            collect,
            master,
            token,
            id,
            name,
            site,
            db,
            report_interval,
        } => {
            let id = id.unwrap_or_else(|| slug(&net::local_hostname().unwrap_or_else(|| "agent".into())));
            engine::run_agent(engine::AgentRunConfig {
                collector: collect.into_config(db),
                agent: AgentConfig {
                    master_url: master,
                    token,
                    meta: AgentMeta {
                        name: name.unwrap_or_else(|| id.clone()),
                        id,
                        site,
                        version: env!("CARGO_PKG_VERSION").into(),
                        subnet: String::new(), // filled in once the interface is known
                    },
                    interval: Duration::from_secs(report_interval.max(1)),
                },
            })
            .await
        }
        Cmd::Interfaces => {
            let chosen = net::select(None).ok().map(|i| i.name);
            for i in net::list_interfaces()? {
                let star = if Some(&i.name) == chosen.as_ref() { "*" } else { " " };
                println!("{star} {:<10} {:<17} {:<18} {}", i.name, i.mac, i.net, i.ip);
            }
            println!("(* = default choice)");
            Ok(())
        }
        Cmd::List { db } => list(&db),
        Cmd::Alerts { db, all } => alerts(&db, all),
    }
}

/// Hostname -> a valid agent id.
fn slug(s: &str) -> String {
    let id: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .take(64)
        .collect();
    if id.is_empty() { "agent".into() } else { id }
}

fn alerts(db: &std::path::Path, all: bool) -> Result<()> {
    let store = SqliteStore::open(db)?;
    let assets: std::collections::HashMap<i64, _> =
        store.load_assets()?.into_iter().map(|a| (a.id, a)).collect();
    let events = store.list_events(&EventQuery { limit: 200, alerts_only: !all, ..Default::default() })?;
    let now = now_ts();
    println!("{:<7} {:<6} {:<16} {:<10} {:<17} {:<8} SUMMARY", "SEV", "SCORE", "TYPE", "AGE", "DEVICE", "AGENT");
    for e in &events {
        let dev = assets.get(&e.asset_id).map_or(String::new(), |a| a.mac.to_string());
        println!(
            "{:<7} {:<6} {:<16} {:<10} {:<17} {:<8} {}{}",
            e.severity,
            e.score,
            e.kind,
            ago(now - e.timestamp),
            dev,
            e.agent_id.as_deref().unwrap_or("local"),
            e.raw_details["summary"].as_str().unwrap_or(""),
            if e.acked { "  (acked)" } else { "" }
        );
    }
    println!("{} events", events.len());
    Ok(())
}

fn list(db: &std::path::Path) -> Result<()> {
    let store = SqliteStore::open(db)?;
    let mut assets = store.load_assets()?;
    assets.sort_by_key(|a| a.current_ip().map(|ip| ip.octets()));
    let now = now_ts();
    println!(
        "{:<15} {:<17} {:<22} {:<24} {:<14} {:<18} {:<9} PORTS",
        "IP", "MAC", "VENDOR", "HOSTNAME", "TYPE", "OS", "SEEN"
    );
    for a in &assets {
        let ports = a
            .open_ports
            .iter()
            .map(|p| p.port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{:<15} {:<17} {:<22} {:<24} {:<14} {:<18} {:<9} {}",
            a.current_ip().map(|i| i.to_string()).unwrap_or_default(),
            a.mac,
            trunc(a.vendor.as_deref().unwrap_or(if a.randomized_mac { "(private MAC)" } else { "" }), 21),
            trunc(a.hostnames.iter().find(|h| !is_uuid(h)).map_or("", String::as_str), 23),
            a.device_type,
            trunc(a.os_guess.as_deref().unwrap_or(""), 17),
            ago(now - a.last_seen),
            ports
        );
    }
    println!("{} assets", assets.len());
    Ok(())
}

/// Apple devices advertise `<uuid>.local`; not a name a human would recognise.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

fn ago(secs: i64) -> String {
    match secs {
        i64::MIN..=59 => format!("{}s ago", secs.max(0)),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}
