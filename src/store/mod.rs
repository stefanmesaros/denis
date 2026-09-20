//! Storage abstraction. SQLite serves the standalone/on-prem master and remote
//! agents; a Postgres implementation for a cloud master slots in behind this
//! same trait (not built yet).

pub mod sqlite;

use anyhow::Result;

use crate::model::{AgentInfo, Asset, Baseline, Event, Mac};

#[derive(Clone, Debug)]
pub struct EventQuery {
    pub limit: usize,
    pub asset_id: Option<i64>,
    /// Only real alerts (severity above `info`).
    pub alerts_only: bool,
    pub unacked_only: bool,
}

impl Default for EventQuery {
    fn default() -> Self {
        EventQuery {
            limit: 100,
            asset_id: None,
            alerts_only: false,
            unacked_only: false,
        }
    }
}

pub trait Store: Send + Sync {
    /// Every known asset (used to warm the in-memory inventory at startup).
    fn load_assets(&self) -> Result<Vec<Asset>>;
    /// Insert (id == 0) or update; assigns `asset.id` on insert.
    fn save_asset(&self, asset: &mut Asset) -> Result<()>;
    fn get_asset(&self, id: i64) -> Result<Option<Asset>>;
    /// Lookup by the unique key `(agent_id, mac)`; `None` = the local collector.
    fn find_asset(&self, agent_id: Option<&str>, mac: &Mac) -> Result<Option<Asset>>;

    /// Assigns `event.id`.
    fn insert_event(&self, event: &mut Event) -> Result<()>;
    /// Newest first.
    fn list_events(&self, q: &EventQuery) -> Result<Vec<Event>>;
    /// Returns false if no such event.
    fn set_event_acked(&self, id: i64, acked: bool) -> Result<bool>;

    fn load_baselines(&self) -> Result<Vec<Baseline>>;
    fn get_baseline(&self, asset_id: i64) -> Result<Option<Baseline>>;
    fn save_baseline(&self, b: &Baseline) -> Result<()>;

    fn upsert_agent(&self, a: &AgentInfo) -> Result<()>;
    fn get_agent(&self, id: &str) -> Result<Option<AgentInfo>>;
    fn list_agents(&self) -> Result<Vec<AgentInfo>>;
}
