//! Remote-agent side: batch changed assets + flow windows and push them to the
//! master over HTTP+JSON.
//!
//! Push, not pull: the agent only needs outbound access, so it works behind NAT
//! and firewalls. Delivery is at-least-once: a batch keeps its `(run_id, seq)`
//! and is re-sent unchanged until acknowledged; the master ignores replays.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc;

use crate::inventory::Inventory;
use crate::model::{now_ts, AgentMeta, FlowRecord, Report, ReportAck};

/// Flow windows held while the master is unreachable (~ hours at typical rates).
pub const SPOOL_MAX: usize = 200_000;
/// Records per report; keeps bodies to a few MB.
pub const BATCH_FLOWS: usize = 20_000;
const HEARTBEAT: Duration = Duration::from_secs(60);
const BACKOFF_MAX: Duration = Duration::from_secs(300);

pub struct AgentConfig {
    pub master_url: String,
    pub token: String,
    pub meta: AgentMeta,
    pub interval: Duration,
}

struct Pending {
    report: Report,
    /// Inventory revision this batch covers; committed on acknowledgement.
    rev: u64,
}

/// The reporting state machine, separated from I/O so it is unit-testable.
pub struct Reporter {
    meta: AgentMeta,
    run_id: String,
    seq: u64,
    last_rev: u64,
    spool: VecDeque<FlowRecord>,
    pub dropped: u64,
    pending: Option<Pending>,
    last_sent: Option<Instant>,
}

impl Reporter {
    pub fn new(meta: AgentMeta) -> Self {
        // Distinguishes this process from earlier ones so the master doesn't
        // mistake a restarted agent's seq 1 for a replay.
        let run_id = format!("{:x}-{:x}", now_millis(), std::process::id());
        Reporter {
            meta,
            run_id,
            seq: 0,
            last_rev: 0,
            spool: VecDeque::new(),
            dropped: 0,
            pending: None,
            last_sent: None,
        }
    }

    pub fn spool(&mut self, flows: Vec<FlowRecord>) {
        for f in flows {
            if self.spool.len() >= SPOOL_MAX {
                self.spool.pop_front(); // oldest data is the least useful
                self.dropped += 1;
            }
            self.spool.push_back(f);
        }
    }

    pub fn spooled(&self) -> usize {
        self.spool.len()
    }

    /// The batch to send now: an unacknowledged one (unchanged), else a new one
    /// if there is anything to say (or a heartbeat is due).
    pub fn next_batch(&mut self, inv: &Mutex<Inventory>, now: i64) -> Option<&Report> {
        if self.pending.is_none() {
            let (assets, rev) = inv.lock().unwrap().changed_since(self.last_rev);
            let take = self.spool.len().min(BATCH_FLOWS);
            let heartbeat_due = self.last_sent.is_none_or(|t| t.elapsed() >= HEARTBEAT);
            if assets.is_empty() && take == 0 && !heartbeat_due {
                return None;
            }
            let flows: Vec<FlowRecord> = self.spool.drain(..take).collect();
            self.seq += 1;
            self.pending = Some(Pending {
                report: Report {
                    agent: self.meta.clone(),
                    run_id: self.run_id.clone(),
                    seq: self.seq,
                    sent_at: now,
                    assets,
                    flows,
                },
                rev,
            });
        }
        self.pending.as_ref().map(|p| &p.report)
    }

    pub fn on_ack(&mut self, ack: &ReportAck) {
        if let Some(p) = &self.pending {
            if p.report.seq == ack.seq {
                self.last_rev = p.rev;
                self.pending = None;
                self.last_sent = Some(Instant::now());
            }
        }
    }

    /// The master refused the batch as malformed: retrying can never succeed, so
    /// drop it rather than wedge the agent behind it.
    pub fn on_rejected(&mut self) {
        if let Some(p) = self.pending.take() {
            self.last_rev = p.rev;
        }
    }
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[derive(Debug)]
pub enum PostError {
    /// 400/413/422: the batch itself is unacceptable.
    Rejected(u16),
    Unauthorized,
    /// Network or server trouble: retry later.
    Transient(String),
}

pub fn post_report(base: &str, token: &str, report: &Report) -> std::result::Result<ReportAck, PostError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let url = format!("{}/api/v1/report", base.trim_end_matches('/'));
    match agent
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send_json(report)
    {
        Ok(mut resp) => resp
            .body_mut()
            .read_json::<ReportAck>()
            .map_err(|e| PostError::Transient(format!("bad response: {e}"))),
        Err(ureq::Error::StatusCode(401)) => Err(PostError::Unauthorized),
        Err(ureq::Error::StatusCode(c)) if matches!(c, 400 | 413 | 422) => Err(PostError::Rejected(c)),
        Err(e) => Err(PostError::Transient(e.to_string())),
    }
}

/// Check the master is reachable and the token is accepted, before starting.
pub fn check_master(base: &str, token: &str) -> Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let url = format!("{}/api/v1/ping", base.trim_end_matches('/'));
    match agent.get(&url).header("Authorization", format!("Bearer {token}")).call() {
        Ok(_) => Ok(()),
        Err(ureq::Error::StatusCode(401)) => bail!("master rejected the token (401)"),
        Err(e) => Err(anyhow::anyhow!(e)).with_context(|| format!("cannot reach master at {base}")),
    }
}

/// Driver loop. Runs until the process exits.
pub async fn run(
    cfg: AgentConfig,
    inv: Arc<Mutex<Inventory>>,
    mut flow_rx: mpsc::Receiver<Vec<FlowRecord>>,
) {
    let mut rep = Reporter::new(cfg.meta.clone());
    let mut tick = tokio::time::interval(cfg.interval);
    let mut backoff = Duration::ZERO;
    let mut retry_at = Instant::now();
    loop {
        tokio::select! {
            Some(flows) = flow_rx.recv() => rep.spool(flows),
            _ = tick.tick() => {
                if Instant::now() < retry_at {
                    continue;
                }
                let Some(report) = rep.next_batch(&inv, now_ts()).cloned() else { continue };
                let (base, token) = (cfg.master_url.clone(), cfg.token.clone());
                let res = tokio::task::spawn_blocking(move || post_report(&base, &token, &report)).await;
                match res {
                    Ok(Ok(ack)) => {
                        tracing::debug!("report {} acknowledged ({} assets, {} flows)", ack.seq, ack.assets, ack.flows);
                        rep.on_ack(&ack);
                        backoff = Duration::ZERO;
                    }
                    Ok(Err(PostError::Rejected(code))) => {
                        tracing::error!("master rejected a report with HTTP {code}; dropping it");
                        rep.on_rejected();
                    }
                    Ok(Err(e)) => {
                        backoff = (backoff * 2).clamp(Duration::from_secs(5), BACKOFF_MAX);
                        retry_at = Instant::now() + backoff;
                        tracing::warn!("report failed ({e:?}); retrying in {}s, {} flow windows spooled", backoff.as_secs(), rep.spooled());
                    }
                    Err(e) => tracing::error!("report task failed: {e}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mac, Observation};
    use std::net::Ipv4Addr;

    fn meta() -> AgentMeta {
        AgentMeta { id: "a1".into(), name: "A".into(), site: None, version: "t".into(), subnet: "10.0.0.0/24".into() }
    }

    fn flow(i: u8) -> FlowRecord {
        FlowRecord { mac: Mac([2, 0, 0, 0, 0, 1]), remote: Ipv4Addr::new(1, 1, 1, i), proto: 6, port: 443, bytes_out: 1, bytes_in: 1, packets: 1, window_start: 0, window_secs: 10 }
    }

    fn inv_with(n: u8) -> Mutex<Inventory> {
        let mut i = Inventory::new(vec![], None, None);
        for k in 0..n {
            i.apply(Observation::Arp { mac: Mac([0x3c, 0, 0, 0, 0, k + 1]), ip: Ipv4Addr::new(10, 0, 0, k + 1) }, 100);
        }
        Mutex::new(i)
    }

    #[test]
    fn first_batch_is_a_full_sync_then_only_deltas() {
        let inv = inv_with(3);
        let mut r = Reporter::new(meta());
        let b = r.next_batch(&inv, 1).unwrap().clone();
        assert_eq!((b.seq, b.assets.len(), b.run_id.is_empty()), (1, 3, false));
        r.on_ack(&ReportAck { seq: 1, assets: 3, flows: 0, duplicate: false });
        // nothing changed and the heartbeat isn't due
        assert!(r.next_batch(&inv, 2).is_none());
        inv.lock().unwrap().apply(Observation::Arp { mac: Mac([0x3c, 0, 0, 0, 0, 2]), ip: Ipv4Addr::new(10, 0, 0, 2) }, 200);
        let b = r.next_batch(&inv, 3).unwrap().clone();
        assert_eq!((b.seq, b.assets.len()), (2, 1));
    }

    #[test]
    fn an_unacknowledged_batch_is_resent_unchanged_even_as_new_data_arrives() {
        let inv = inv_with(1);
        let mut r = Reporter::new(meta());
        r.spool(vec![flow(1), flow(2)]);
        let first = r.next_batch(&inv, 1).unwrap().clone();
        assert_eq!((first.seq, first.flows.len(), r.spooled()), (1, 2, 0));
        // master down: more data accumulates, the retry is byte-identical
        r.spool(vec![flow(3)]);
        inv.lock().unwrap().apply(Observation::Arp { mac: Mac([0x3c, 0, 0, 0, 0, 1]), ip: Ipv4Addr::new(10, 0, 0, 1) }, 500);
        let retry = r.next_batch(&inv, 99).unwrap().clone();
        assert_eq!((retry.seq, retry.flows.len(), retry.assets.len(), retry.sent_at), (1, 2, 1, 1));
        r.on_ack(&ReportAck { seq: 1, assets: 1, flows: 2, duplicate: false });
        // the data that arrived meanwhile goes in the *next* batch
        let next = r.next_batch(&inv, 100).unwrap().clone();
        assert_eq!((next.seq, next.flows.len(), next.assets.len()), (2, 1, 1));
    }

    #[test]
    fn stale_or_foreign_acks_do_not_clear_the_pending_batch() {
        let inv = inv_with(1);
        let mut r = Reporter::new(meta());
        r.next_batch(&inv, 1).unwrap();
        r.on_ack(&ReportAck { seq: 99, assets: 0, flows: 0, duplicate: false });
        assert_eq!(r.next_batch(&inv, 2).unwrap().seq, 1);
    }

    #[test]
    fn a_rejected_batch_is_dropped_so_the_agent_is_not_wedged() {
        let inv = inv_with(1);
        let mut r = Reporter::new(meta());
        r.next_batch(&inv, 1).unwrap();
        r.on_rejected();
        // The next batch is a fresh one (a heartbeat: nothing was ever acked) that
        // does not re-include the rejected assets.
        let next = r.next_batch(&inv, 2).unwrap().clone();
        assert_eq!((next.seq, next.assets.len()), (2, 0), "rev advanced past the bad batch");
    }

    #[test]
    fn the_spool_is_bounded_and_drops_the_oldest() {
        let mut r = Reporter::new(meta());
        r.spool((0..SPOOL_MAX + 10).map(|i| FlowRecord { window_start: i as i64, ..flow(1) }).collect());
        assert_eq!((r.spooled(), r.dropped), (SPOOL_MAX, 10));
        assert_eq!(r.spool.front().unwrap().window_start, 10);
    }

    #[test]
    fn batches_are_capped_and_drained_in_order() {
        let inv = inv_with(0);
        let mut r = Reporter::new(meta());
        r.spool((0..BATCH_FLOWS + 5).map(|i| FlowRecord { window_start: i as i64, ..flow(1) }).collect());
        let b = r.next_batch(&inv, 1).unwrap().clone();
        assert_eq!((b.flows.len(), r.spooled()), (BATCH_FLOWS, 5));
        assert_eq!(b.flows[0].window_start, 0);
    }
}
