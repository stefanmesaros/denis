use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use denis::agent::AgentConfig;
use denis::detect::{DetectConfig, RULES};
use denis::model::{now_ts, AgentMeta};
use denis::store::sqlite::SqliteStore;
use denis::store::{EventQuery, Store};
use denis::{engine, net};
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
    /// A second, capture-only interface: a switch mirror/SPAN destination
    /// port. Never probed, never used for discovery — only decoded into
    /// flows, on the same footing as --iface. Implies --flows. Typically has
    /// no IPv4 address of its own (see `denis interfaces`).
    #[arg(long)]
    mirror_iface: Option<String>,
    /// Seconds between ARP sweeps.
    #[arg(long, default_value_t = 300)]
    sweep_interval: u64,
    /// Minimum seconds between port scans of the same host.
    #[arg(long, default_value_t = 1800)]
    rescan_interval: u64,
    /// Capture only; never transmit ARP, ICMP or TCP probes.
    #[arg(long)]
    passive_only: bool,
    /// Account traffic to/from outside the subnet (input for the anomaly rules)
    /// and decode industrial protocols between local devices. Captures every
    /// IPv4 frame, so it only sees traffic that crosses this interface: run on
    /// the gateway or a mirror/SPAN port for whole-network coverage.
    #[arg(long)]
    flows: bool,
    /// `it` (default) or `ot`. The OT profile is for industrial networks: it
    /// listens only (no probes at all unless you add --active), turns on traffic
    /// analysis, and paces any active discovery gently. Industrial devices are
    /// never pinged or port-scanned in either profile.
    #[arg(long, default_value = "it", value_parser = ["it", "ot"])]
    profile: String,
    /// With `--profile ot`, allow gentle active discovery (a slow ARP sweep).
    #[arg(long)]
    active: bool,
    /// Never send probes to this range (repeatable). Still observed passively.
    #[arg(long = "exclude", value_name = "CIDR")]
    exclude: Vec<ipnet::Ipv4Net>,
}

impl Collect {
    fn into_config(self, db: PathBuf) -> engine::CollectorConfig {
        let ot = self.profile == "ot";
        engine::CollectorConfig {
            iface: self.iface,
            mirror_iface: self.mirror_iface.clone(),
            db,
            sweep_interval: Duration::from_secs(self.sweep_interval.max(30)),
            rescan_interval: Duration::from_secs(self.rescan_interval),
            // OT: listen only, unless the operator explicitly allows gentle probing.
            passive_only: self.passive_only || (ot && !self.active),
            // A mirror interface exists for no reason other than flow accounting.
            flows: self.flows || ot || self.mirror_iface.is_some(),
            exclude: self.exclude,
            arp_pace: Duration::from_millis(if ot { 50 } else { 2 }),
            ..Default::default()
        }
    }
}

#[derive(Subcommand)]
// `Run` carries every command-line option; the enum is built once at start-up
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Standalone or master: discover devices, detect anomalies, serve the web UI.
    /// Add --ingest-listen to also accept remote agents.
    Run {
        #[command(flatten)]
        collect: Collect,
        /// Web UI listen address. Sign-in is required. The console is served over
        /// HTTPS (a generated certificate, see --tls-name) unless --no-tls. On loopback
        /// it is reachable only from this machine; another address (0.0.0.0:8443, say)
        /// makes it reachable from the network. If the port is taken, DENIS exits with
        /// "Address already in use": choose another one.
        #[arg(short, long, default_value = "127.0.0.1:8080", env = "DENIS_LISTEN")]
        listen: SocketAddr,
        /// SQLite database file (default: denis.db; an existing netscope.db from
        /// before the rename is used automatically).
        #[arg(long)]
        db: Option<PathBuf>,
        /// Accept remote agents on this address. Each agent needs its own token:
        /// `denis agent-token issue --id <agent-id>`.
        #[arg(long)]
        ingest_listen: Option<SocketAddr>,
        /// Turn login off. For development only: anyone who can reach the UI gets
        /// full control. Refused unless the UI listens on a loopback address.
        #[arg(long)]
        insecure_no_auth: bool,
        /// The address people type to reach the console, e.g. https://denis.example.com.
        /// Passkeys (sign-in with fingerprint, face or a security key) are bound to it;
        /// without it they work only when you browse to http://localhost.
        #[arg(long, env = "DENIS_PUBLIC_URL")]
        public_url: Option<String>,
        /// Public host name a reverse proxy on this machine forwards to the UI
        /// (repeatable, or comma-separated in the environment). Needed when the
        /// UI listens on loopback and the proxy passes the original Host header on
        /// (Caddy does by default; nginx with `proxy_set_header Host $host`).
        #[arg(long = "allowed-host", env = "DENIS_ALLOWED_HOSTS", value_delimiter = ',')]
        allowed_hosts: Vec<String>,
        /// Serve plain HTTP instead of HTTPS. Only for a reverse proxy that terminates TLS
        /// or an SSH tunnel: by default the console and the agent port use HTTPS with a
        /// certificate DENIS creates (replaceable in the console, see `--tls-cert`).
        #[arg(long, env = "DENIS_NO_TLS")]
        no_tls: bool,
        /// Extra names or addresses to put in the generated certificate (repeatable), e.g. the
        /// name people type. Addresses of this machine are included automatically.
        #[arg(long = "tls-name", env = "DENIS_TLS_NAMES", value_delimiter = ',')]
        tls_names: Vec<String>,
        /// Folder for the generated certificate and its authority (default: `tls` beside the database).
        #[arg(long, env = "DENIS_TLS_DIR")]
        tls_dir: Option<PathBuf>,
        /// Use your own PEM certificate chain instead of the generated one (needs --tls-key).
        /// Re-read every hour, so a renewed certificate needs no restart. To swap certificates
        /// from the console instead, leave this out.
        #[arg(long, env = "DENIS_TLS_CERT", requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// PEM private key (unencrypted) for --tls-cert.
        #[arg(long, env = "DENIS_TLS_KEY", requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// Mark the session cookie `Secure`. Use when a TLS-terminating reverse
        /// proxy is in front of the UI.
        #[arg(long)]
        secure_cookies: bool,
        /// Minutes a device/site is observed before its new destinations and
        /// devices count as anomalies (until then they are just learned).
        #[arg(long, default_value_t = 1440)]
        learning_minutes: i64,
        /// Scores below this are logged as info, not raised as alerts.
        #[arg(long, default_value_t = 30)]
        min_score: i32,
        /// Scale a rule's score: RULE=WEIGHT, e.g. new_destination=0.5 (0 disables).
        /// Rules: new_device, new_destination, volume_anomaly, new_port,
        /// unusual_hours, arp_conflict, device_silent, ot_new_conversation,
        /// ot_control_command, ot_internet_exposure. Repeatable.
        #[arg(long = "rule-weight", value_parser = parse_weight)]
        rule_weights: Vec<(String, f64)>,
        /// POST alerts as JSON to this URL (Slack/Discord-compatible).
        #[arg(long, env = "DENIS_WEBHOOK", hide_env_values = true)]
        webhook: Option<String>,
        /// Export events, audit log, trend samples and the asset inventory to
        /// OpenObserve at this base URL (e.g. https://openobserve.example.com).
        /// Credentials come from DENIS_OPENOBSERVE_USER / DENIS_OPENOBSERVE_PASSWORD
        /// (environment only, so they do not show in the process list).
        #[arg(long, env = "DENIS_OPENOBSERVE_URL")]
        openobserve_url: Option<String>,
        /// OpenObserve organisation.
        #[arg(long, default_value = "default", env = "DENIS_OPENOBSERVE_ORG")]
        openobserve_org: String,
        /// Stream name prefix (streams: <prefix>_events, _audit, _metrics, _assets).
        #[arg(long, default_value = "denis")]
        openobserve_prefix: String,
        /// Seconds between export cycles.
        #[arg(long, default_value_t = 15)]
        openobserve_interval: u64,
        /// Text file of known-bad IPv4 addresses and networks, one per line (the format of
        /// abuse.ch and Spamhaus DROP lists). Devices contacting them raise an alert.
        /// Needs --flows. Re-read when the file changes.
        #[arg(long, env = "DENIS_THREAT_LIST")]
        threat_list: Option<PathBuf>,
        /// Never contact GitHub to look for a new version (air-gapped installs, or if you
        /// prefer to update by hand). Checking sends one anonymous HTTPS request every few hours.
        #[arg(long, env = "DENIS_NO_UPDATE_CHECK")]
        no_update_check: bool,
        /// `owner/repo` on GitHub whose releases DENIS updates from (default: the project's).
        #[arg(long, env = "DENIS_UPDATE_REPO")]
        update_repo: Option<String>,
        /// GitHub Enterprise: the API address (default https://api.github.com).
        #[arg(long, env = "DENIS_UPDATE_API_BASE", hide = true)]
        update_api_base: Option<String>,
        /// GitHub Enterprise: where release files are downloaded from.
        #[arg(long, env = "DENIS_UPDATE_DOWNLOAD_PREFIX", hide = true)]
        update_download_prefix: Option<String>,
        /// Send alerts to a SIEM as syslog/CEF: udp://host:514 or tcp://host:514.
        #[arg(long, env = "DENIS_SYSLOG")]
        syslog: Option<String>,
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
        /// Unusual-hours rule: days a device is observed before its daily
        /// pattern is judged.
        #[arg(long, default_value_t = 7.0)]
        hours_learning_days: f64,
        /// Silent-device rule: minutes without a sign of life before a
        /// reliably-online device is reported. Needs active sweeps (not --passive-only).
        #[arg(long, default_value_t = 120)]
        silent_minutes: i64,
        /// Delete trend samples older than this many days.
        #[arg(long, default_value_t = 90)]
        retention_days: i64,
        /// A signed commercial license file (see LICENSE-COMMERCIAL.md). Without one: the
        /// Community edition, 100 devices, personal/non-commercial use.
        #[arg(long, env = "DENIS_LICENSE_FILE")]
        license_file: Option<PathBuf>,
        /// Push this install's own scheduled backups to an MSP's master (its base URL, e.g.
        /// https://msp.example.com:9000). So the MSP still has yesterday's device list if this
        /// install is ever hit by ransomware. Needs a token issued there (`denis agent-token
        /// issue`), read from --backup-upstream-token-env; outbound only, same as an agent.
        #[arg(long, env = "DENIS_BACKUP_UPSTREAM")]
        backup_upstream: Option<String>,
        /// Environment variable holding the token for --backup-upstream (never on the command
        /// line, so it does not show in the process list).
        #[arg(long, default_value = "DENIS_BACKUP_TOKEN")]
        backup_upstream_token_env: String,
        /// Relay this install's own devices and already-scored alerts to an MSP's master (its
        /// base URL, e.g. https://msp.example.com:9000): it appears there as one more site,
        /// like an agent's. Bandwidth-conscious by design: devices are sent only when they
        /// actually change (not the whole register every cycle), alerts only past a cursor, and
        /// findings/compliance are never sent — the MSP computes those itself once the register
        /// is mirrored. Needs a token from the MSP (`denis agent-token issue`), read from
        /// --report-to-token-env; outbound only, same trust model as an agent.
        #[arg(long, env = "DENIS_REPORT_TO")]
        report_to: Option<String>,
        /// Environment variable holding the token for --report-to.
        #[arg(long, default_value = "DENIS_REPORT_TOKEN")]
        report_to_token_env: String,
        /// Seconds between relay cycles for --report-to. Deliberately not as frequent as the
        /// console's own UI refresh: alerts and device deltas do not need to be that fresh, and
        /// a longer interval means less WAN traffic to the MSP.
        #[arg(long, default_value_t = denis::msp_relay::DEFAULT_INTERVAL_SECS)]
        report_to_interval: u64,
    },
    /// Remote agent: collect on this network and report to a master.
    Agent {
        #[command(flatten)]
        collect: Collect,
        /// Master ingest URL, e.g. https://192.168.1.10:8081 (plain http:// is refused unless it is this machine
        /// or --allow-plain-http is given).
        #[arg(long)]
        master: String,
        /// Accept a plain http:// master address on a network you trust (a VPN, a tunnel). Not needed for https://.
        #[arg(long, env = "DENIS_ALLOW_PLAIN_HTTP")]
        allow_plain_http: bool,
        #[arg(long, env = "DENIS_AGENT_TOKEN", hide_env_values = true)]
        token: String,
        /// PEM file with the CA (or self-signed certificate) that signed the
        /// master's HTTPS certificate; trusted instead of the public web roots.
        #[arg(long, env = "DENIS_MASTER_CA")]
        master_ca: Option<PathBuf>,
        /// Stable identifier for this agent ([A-Za-z0-9._-], default: hostname).
        #[arg(long)]
        id: Option<String>,
        /// Display name (default: the id).
        #[arg(long)]
        name: Option<String>,
        /// Site/location label.
        #[arg(long)]
        site: Option<String>,
        /// The agent's own database (default: denis-agent.db).
        #[arg(long)]
        db: Option<PathBuf>,
        /// Seconds between reports.
        #[arg(long, default_value_t = 15)]
        report_interval: u64,
    },
    /// List usable network interfaces.
    Interfaces,
    /// Print the inventory from the database.
    List {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Write a report or export from the database (works offline).
    Report {
        #[arg(long)]
        db: Option<PathBuf>,
        /// Period to cover.
        #[arg(long, default_value_t = 7)]
        days: i64,
        /// html (printable; open it and print to PDF), assets-csv or alerts-csv.
        #[arg(long, default_value = "html")]
        format: String,
        /// Output file (default: standard output).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Manage user accounts directly in the database (also the way back in if
    /// the last administrator password is lost: whoever can read the database
    /// file is an administrator anyway).
    User {
        #[command(subcommand)]
        action: UserCmd,
        #[arg(long, global = true)]
        db: Option<PathBuf>,
    },
    /// Web console over an existing database, with no capture, probing or detection:
    /// for looking at a backup or a copy, for training and for demonstrations.
    Serve {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        #[arg(long)]
        db: Option<PathBuf>,
        /// Turn login off (loopback only). For demonstrations and documentation screenshots.
        #[arg(long)]
        insecure_no_auth: bool,
        #[arg(long, env = "DENIS_PUBLIC_URL")]
        public_url: Option<String>,
        /// A signed commercial license file (see LICENSE-COMMERCIAL.md). Without one: the
        /// Community edition, 100 devices, personal/non-commercial use.
        #[arg(long, env = "DENIS_LICENSE_FILE")]
        license_file: Option<PathBuf>,
    },
    /// Load or remove the built-in demo data (a fictional company) in a database. Works while
    /// DENIS is stopped; while it runs, use the console (Settings → Demo data and reset).
    Demo {
        #[command(subcommand)]
        action: DemoCmd,
        #[arg(long, global = true)]
        db: Option<PathBuf>,
    },
    /// Erase every device, alert and record from a database (accounts, settings and the audit
    /// log are kept). DENIS must be stopped. Cannot be undone: take a backup first.
    Erase {
        /// Required: confirms you mean it.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Print a new release-signing key pair (for whoever publishes releases). The private key
    /// must be kept secret; the public key goes into src/update_key.rs.
    ReleaseKeygen,
    /// Sign release files with the private key in the environment variable named by --key-env,
    /// writing FILE.sig next to each file (hex). Used by the release pipeline.
    ReleaseSign {
        #[arg(long, default_value = "DENIS_RELEASE_KEY")]
        key_env: String,
        files: Vec<PathBuf>,
    },
    /// Write a verified copy of the database to FILE while the program keeps running.
    /// Meant for cron or a systemd timer. The copy holds password hashes and
    /// notification secrets, so it is readable by its owner only; keep it that way.
    Backup {
        /// Where to write the copy (must not exist yet).
        out: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Run a packet capture (Ethernet pcap) through the decoders, inventory and detection and print what was found:
    /// devices, industrial conversations and alerts. Nothing is stored. For trying DENIS on a sample without a network.
    Replay {
        file: PathBuf,
        /// Only addresses inside this network count as local devices (default: every address).
        #[arg(long)]
        subnet: Option<ipnet::Ipv4Net>,
        /// Seconds of learning before new paths alert (0: alert on the first sight of every path).
        #[arg(long, default_value_t = 0)]
        learning_secs: i64,
    },
    /// Issue, list or revoke the per-agent tokens remote agents authenticate with.
    AgentToken {
        #[command(subcommand)]
        action: TokenCmd,
        #[arg(long, global = true)]
        db: Option<PathBuf>,
    },
    /// Print alerts from the database.
    Alerts {
        #[arg(long)]
        db: Option<PathBuf>,
        /// Include info-level events (e.g. devices learned during the learning period).
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum DemoCmd {
    /// Fill the database with the fictional demo company.
    Load,
    /// Remove the demo data (real data is untouched).
    Remove,
}

#[derive(Subcommand)]
enum UserCmd {
    /// List accounts.
    List,
    /// Create an account with a random one-time password.
    Add {
        username: String,
        #[arg(long, default_value = "viewer")]
        role: String,
    },
    /// Set a new random one-time password (the user must change it at next login).
    Reset { username: String },
    /// Disable an account (signs it out everywhere).
    Disable { username: String },
    /// Re-enable an account.
    Enable { username: String },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create (or rotate) the token for an agent id. Shown once.
    Issue {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "")]
        label: String,
    },
    List,
    /// Revoke an agent's token immediately.
    Revoke {
        #[arg(long)]
        id: String,
    },
}

fn parse_weight(s: &str) -> Result<(String, f64), String> {
    let (rule, w) = s.split_once('=').ok_or("expected RULE=WEIGHT")?;
    if !RULES.contains(&rule) {
        return Err(format!("unknown rule {rule:?} ({})", RULES.join(", ")));
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
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "denis=info".into()))
        .with_target(false)
        .init();

    match Cli::parse().cmd {
        Cmd::Run {
            collect,
            listen,
            db,
            ingest_listen,
            insecure_no_auth,
            secure_cookies,
            no_tls,
            tls_names,
            tls_dir,
            tls_cert,
            tls_key,
            allowed_hosts,
            public_url,
            learning_minutes,
            min_score,
            rule_weights,
            webhook,
            webhook_min_score,
            syslog,
            threat_list,
            no_update_check,
            update_repo,
            update_api_base,
            update_download_prefix,
            openobserve_url,
            openobserve_org,
            openobserve_prefix,
            openobserve_interval,
            bucket_secs,
            min_volume_mb,
            min_samples,
            hours_learning_days,
            silent_minutes,
            retention_days,
            license_file,
            backup_upstream,
            backup_upstream_token_env,
            report_to,
            report_to_token_env,
            report_to_interval,
        } => {
            let detect = DetectConfig {
                learning_secs: learning_minutes.max(0) * 60,
                min_score,
                weights: rule_weights.into_iter().collect(),
                bucket_secs: bucket_secs.max(10),
                min_volume_bytes: (min_volume_mb.max(0.0) * 1e6) as u64,
                min_samples,
                hours_learning_secs: (hours_learning_days.max(0.0) * 86_400.0) as i64,
                silent_secs: silent_minutes.max(1) * 60,
                tz_offset_secs: net::local_utc_offset_secs(),
                ..Default::default()
            };
            let openobserve = openobserve_url.map(|url| denis::sink::SinkConfig {
                url,
                org: openobserve_org,
                prefix: openobserve_prefix,
                user: std::env::var("DENIS_OPENOBSERVE_USER").unwrap_or_default(),
                password: std::env::var("DENIS_OPENOBSERVE_PASSWORD").unwrap_or_default(),
                interval: std::time::Duration::from_secs(openobserve_interval.clamp(5, 3600)),
            });
            if let Some(o) = &openobserve {
                o.validate()?;
            }
            let syslog = syslog.map(|u| denis::syslog::SyslogConfig::parse(&u, Duration::from_secs(10))).transpose()?;
            let db_path = resolve_db(db, "denis.db", "netscope.db");
            // A freshly installed version that keeps failing is replaced by the previous one (and
            // its database, if the format changed) before anything else happens.
            let exe = std::env::current_exe().ok();
            if let denis::update::Guard::RolledBack { exe: previous } = denis::update::startup_guard(&db_path) {
                eprintln!("the updated version did not start; starting the previous version (details in the console)");
                anyhow::bail!("could not start the previous version: {}", denis::update::exec(&previous));
            }
            // HTTPS by default. The certificate is generated on first start (and can be replaced in the
            // console); your own files, or explicitly no TLS, are the alternatives.
            let tls = match (tls_cert, tls_key, no_tls) {
                (Some(c), Some(k), _) => engine::TlsMode::Files(c, k),
                (_, _, true) => engine::TlsMode::Off,
                _ => {
                    let mut names = tls_names;
                    if let Some(h) = public_url.as_deref().and_then(|u| u.split_once("://")).map(|(_, r)| r.trim_end_matches('/')) {
                        names.push(h.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(h, |(h, _)| h).to_string());
                    }
                    let dir = tls_dir.unwrap_or_else(|| db_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new(".")).join("tls"));
                    engine::TlsMode::Managed { dir, names }
                }
            };
            let update = denis::update::UpdateConfig::new(update_repo, !no_update_check, db_path.clone())?.with_endpoints(update_api_base, update_download_prefix)?;
            let backup_upstream = backup_upstream
                .map(|url| {
                    let token = std::env::var(&backup_upstream_token_env)
                        .map_err(|_| anyhow::anyhow!("--backup-upstream needs a token: set the environment variable {backup_upstream_token_env}"))?;
                    Ok::<_, anyhow::Error>(denis::backups::Upstream { url, token })
                })
                .transpose()?;
            let report_to = report_to
                .map(|url| {
                    let token = std::env::var(&report_to_token_env)
                        .map_err(|_| anyhow::anyhow!("--report-to needs a token: set the environment variable {report_to_token_env}"))?;
                    Ok::<_, anyhow::Error>(denis::msp_relay::Upstream { url, token, interval: Duration::from_secs(report_to_interval.max(15)) })
                })
                .transpose()?;
            let result = engine::run(engine::Config {
                collector: collect.into_config(db_path),
                listen,
                ingest_listen,
                no_auth: insecure_no_auth,
                secure_cookie: secure_cookies,
                detect,
                webhook,
                webhook_min_score,
                openobserve,
                syslog,
                update: Some(update),
                threat_list,
                tls,
                allowed_hosts,
                public_url,
                retention_days,
                license_file,
                backup_upstream,
                report_to,
            })
            .await;
            // an update was installed: continue as the new program (same arguments, same process)
            if denis::update::restart_wanted() {
                if let Some(exe) = exe {
                    anyhow::bail!("the update was installed but restarting failed: {}", denis::update::exec(&exe));
                }
            }
            result
        }
        Cmd::Agent {
            collect,
            master,
            allow_plain_http,
            token,
            master_ca,
            id,
            name,
            site,
            db,
            report_interval,
        } => {
            denis::agent::check_master_url(&master, allow_plain_http)?;
            let id = id.unwrap_or_else(|| slug(&net::local_hostname().unwrap_or_else(|| "agent".into())));
            engine::run_agent(engine::AgentRunConfig {
                collector: collect.into_config(resolve_db(db, "denis-agent.db", "netscope-agent.db")),
                agent: AgentConfig {
                    master_url: master,
                    token,
                    ca_cert: master_ca,
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
            let with_ip: std::collections::BTreeSet<String> = net::list_interfaces()?.iter().map(|i| i.name.clone()).collect();
            for i in net::list_interfaces()? {
                let star = if Some(&i.name) == chosen.as_ref() { "*" } else { " " };
                println!("{star} {:<10} {:<17} {:<18} {}", i.name, i.mac, i.net, i.ip);
            }
            println!("(* = default choice for --iface)");
            let mirror_only: Vec<String> = net::list_all_up()?.into_iter().filter(|n| !with_ip.contains(n)).collect();
            if !mirror_only.is_empty() {
                println!("\nwithout an IPv4 address (usable only as --mirror-iface, e.g. a SPAN/mirror port):");
                for n in mirror_only {
                    println!("  {n}");
                }
            }
            Ok(())
        }
        Cmd::Serve { listen, db, insecure_no_auth, public_url, license_file } => {
            engine::serve_only(engine::ServeConfig { db: resolve_db(db, "denis.db", "netscope.db"), listen, no_auth: insecure_no_auth, public_url, license_file }).await
        }
        Cmd::Demo { action, db } => {
            let path = resolve_db(db, "denis.db", "netscope.db");
            let store = SqliteStore::open(&path)?;
            match action {
                DemoCmd::Load => {
                    let l = denis::demo::load(&store, now_ts())?;
                    println!("demo data loaded: {} devices, {} alerts", l.assets, l.events);
                }
                DemoCmd::Remove => println!("demo data removed: {} devices", denis::demo::remove(&store)?),
            }
            Ok(())
        }
        Cmd::Erase { yes, db } => {
            if !yes {
                anyhow::bail!("this deletes every device, alert and record in the database; add --yes if you mean it (and stop DENIS first; take a backup with `denis backup`)");
            }
            let path = resolve_db(db, "denis.db", "netscope.db");
            SqliteStore::open(&path)?.erase_inventory()?;
            println!("erased: {}", path.display());
            Ok(())
        }
        Cmd::ReleaseKeygen => {
            let (private, public) = denis::update::generate_keypair()?;
            println!("private key (keep SECRET, e.g. as a GitHub Actions secret named DENIS_RELEASE_KEY):\n  {private}\n");
            let bytes: Vec<String> = (0..32).map(|i| format!("0x{}", &public[i * 2..i * 2 + 2])).collect();
            println!("public key (paste into src/update_key.rs):\n  pub const RELEASE_PUBLIC_KEY: Option<[u8; 32]> = Some([{}]);", bytes.join(", "));
            Ok(())
        }
        Cmd::ReleaseSign { key_env, files } => {
            let key = std::env::var(&key_env).map_err(|_| anyhow::anyhow!("set the private key in the environment variable {key_env}"))?;
            for f in files {
                let sig = denis::update::sign(key.trim(), &std::fs::read(&f)?)?;
                let out = PathBuf::from(format!("{}.sig", f.display()));
                std::fs::write(&out, sig)?;
                println!("signed {} -> {}", f.display(), out.display());
            }
            Ok(())
        }
        Cmd::Backup { out, db } => {
            let path = resolve_db(db, "denis.db", "netscope.db");
            if !path.exists() {
                anyhow::bail!("no database at {}", path.display());
            }
            SqliteStore::open(&path)?.backup_to(&out)?;
            println!("backup written to {} (verified)", out.display());
            Ok(())
        }
        Cmd::Replay { file, subnet, learning_secs } => {
            print!("{}", denis::replay::run(&file, subnet, learning_secs)?.render());
            Ok(())
        }
        Cmd::List { db } => list(&resolve_db(db, "denis.db", "netscope.db")),
        Cmd::User { action, db } => user_cmd(&resolve_db(db, "denis.db", "netscope.db"), action),
        Cmd::AgentToken { action, db } => token_cmd(&resolve_db(db, "denis.db", "netscope.db"), action),
        Cmd::Alerts { db, all } => alerts(&resolve_db(db, "denis.db", "netscope.db"), all),
        Cmd::Report { db, days, format, out } => write_report(&resolve_db(db, "denis.db", "netscope.db"), days, &format, out.as_deref()),
    }
}

fn write_report(db: &std::path::Path, days: i64, format: &str, out: Option<&std::path::Path>) -> Result<()> {
    use denis::report;
    let store = SqliteStore::open(db)?;
    let data = report::gather(&store, days, now_ts())?;
    let body = match format {
        "html" => report::html(&data),
        "assets-csv" => report::assets_csv(&data),
        "alerts-csv" => report::alerts_csv(&data),
        other => anyhow::bail!("unknown format {other:?} (html, assets-csv, alerts-csv)"),
    };
    match out {
        Some(p) => {
            std::fs::write(p, body)?;
            eprintln!("wrote {} ({} devices, {} alerts in the last {} days)", p.display(), data.devices.len(), data.alerts.len(), data.days);
        }
        None => print!("{body}"),
    }
    Ok(())
}

fn user_cmd(db: &std::path::Path, action: UserCmd) -> Result<()> {
    use denis::auth::Auth;
    let store = std::sync::Arc::new(SqliteStore::open(db)?);
    let auth = Auth::new(store.clone());
    let find = |name: &str| -> Result<i64> {
        Ok(store.find_user(name)?.ok_or_else(|| anyhow::anyhow!("no such user: {name}"))?.user.id)
    };
    match action {
        UserCmd::List => {
            println!("{:<24} {:<8} {:<9} LAST LOGIN", "USERNAME", "ROLE", "STATE");
            for u in store.list_users()? {
                println!(
                    "{:<24} {:<8} {:<9} {}",
                    u.username,
                    u.role,
                    if u.disabled { "disabled" } else if u.must_change { "pw-reset" } else { "active" },
                    u.last_login.map_or("never".into(), denis::report::iso)
                );
            }
        }
        UserCmd::Add { username, role } => {
            let (u, pw) = auth.create_user(&username, &role, now_ts()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            println!("created {} ({}); one-time password (must be changed at first login):\n{pw}", u.username, u.role);
        }
        UserCmd::Reset { username } => {
            let pw = auth.reset_password(find(&username)?).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            println!("new one-time password for {username} (must be changed at next login):\n{pw}");
        }
        UserCmd::Disable { username } => {
            auth.update_user(find(&username)?, None, Some(true)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            println!("{username} disabled");
        }
        UserCmd::Enable { username } => {
            auth.update_user(find(&username)?, None, Some(false)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            println!("{username} enabled");
        }
    }
    Ok(())
}

fn token_cmd(db: &std::path::Path, action: TokenCmd) -> Result<()> {
    use denis::auth::Auth;
    let store = std::sync::Arc::new(SqliteStore::open(db)?);
    match action {
        TokenCmd::Issue { id, label } => {
            let t = Auth::new(store).issue_agent_token(&id, &label, now_ts()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            println!("token for agent {id} (shown once; any earlier token for it is now revoked):\n{t}\n\nOn the agent:  DENIS_AGENT_TOKEN={t} denis agent --master URL --id {id}");
        }
        TokenCmd::List => {
            println!("{:<24} {:<8} {:<24} LABEL", "AGENT", "STATE", "LAST USED");
            for t in store.list_agent_tokens()? {
                println!(
                    "{:<24} {:<8} {:<24} {}",
                    t.agent_id,
                    if t.revoked { "revoked" } else { "active" },
                    t.last_used.map_or("never".into(), denis::report::iso),
                    t.label
                );
            }
        }
        TokenCmd::Revoke { id } => {
            if store.revoke_agent_token(&id)? {
                println!("token for {id} revoked");
            } else {
                anyhow::bail!("no active token for {id}");
            }
        }
    }
    Ok(())
}

/// The database to use: the explicit path, else `name` in the current directory,
/// else a database left by the pre-rename build (`legacy`) if one exists there.
fn resolve_db(explicit: Option<PathBuf>, name: &str, legacy: &str) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    let (new, old) = (PathBuf::from(name), PathBuf::from(legacy));
    if !new.exists() && old.exists() {
        eprintln!("note: using existing {legacy} (rename it to {name} when convenient; nothing is lost either way)");
        return old;
    }
    new
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
