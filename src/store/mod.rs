//! Storage abstraction. SQLite serves the standalone/on-prem master and remote
//! agents; a Postgres implementation for a cloud master slots in behind this
//! same trait (not built yet).

pub mod sqlite;

use anyhow::Result;

use std::collections::HashMap;

use crate::model::{AgentInfo, Asset, AssetMeta, AuditEntry, Baseline, Conversation, Event, Mac, Metric, Presence, RiskAcceptance, User};

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

pub struct UserRecord {
    pub user: User,
    pub password_hash: String,
}

pub struct SessionRecord {
    pub user: User,
    pub created_at: i64,
    pub last_used: i64,
    pub expires_at: i64,
}

pub struct AgentToken {
    pub agent_id: String,
    pub label: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub revoked: bool,
}

/// A long-lived credential for scripts and integrations, tied to no user.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ApiToken {
    pub id: i64,
    pub label: String,
    /// `viewer` or `editor`; never `admin`.
    pub role: String,
    pub created_by: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub revoked: bool,
}

/// A passkey (WebAuthn credential) registered by a user.
#[derive(Clone, Debug)]
pub struct Passkey {
    pub id: i64,
    pub user_id: i64,
    pub credential_id: Vec<u8>,
    /// Uncompressed P-256 point (65 bytes).
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
}

/// Prefix of the agent (site) ids that belong to the demo data.
pub const DEMO_SITE_PREFIX: &str = "demo-";

/// Every stored asset except the demo ones: what the collector and the detector must work from,
/// so fictional devices never count as real (learning start, silence checks, trends).
pub fn real_assets(store: &dyn Store) -> Result<Vec<Asset>> {
    let metas = store.load_all_meta()?;
    Ok(store.load_assets()?.into_iter().filter(|a| !metas.get(&a.id).is_some_and(|m| m.demo)).collect())
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
    /// Events with `id > after`, oldest first: the export cursor's view.
    fn events_after(&self, after: i64, limit: usize) -> Result<Vec<Event>>;
    fn set_event_acked(&self, id: i64, acked: bool) -> Result<bool>;

    fn load_baselines(&self) -> Result<Vec<Baseline>>;
    fn get_baseline(&self, asset_id: i64) -> Result<Option<Baseline>>;
    fn save_baseline(&self, b: &Baseline) -> Result<()>;

    fn load_presence(&self) -> Result<Vec<Presence>>;
    fn save_presence(&self, p: &Presence) -> Result<()>;

    fn insert_metrics(&self, m: &[Metric]) -> Result<()>;
    /// Samples with `since <= ts < until`, oldest first. `agent_id`: `None` = all
    /// collectors, `Some("")` = the local one.
    fn list_metrics(&self, since: i64, until: i64, agent_id: Option<&str>) -> Result<Vec<Metric>>;
    /// Delete samples older than `before`; returns how many.
    fn prune_metrics(&self, before: i64) -> Result<usize>;

    fn upsert_agent(&self, a: &AgentInfo) -> Result<()>;
    fn get_agent(&self, id: &str) -> Result<Option<AgentInfo>>;
    fn list_agents(&self) -> Result<Vec<AgentInfo>>;

    // ------------------------------------------------ settings (branding, integrations)
    /// Small key/value store for administrator settings and the logo image.
    fn get_setting(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set_setting(&self, key: &str, value: &[u8], ts: i64) -> Result<()>;
    fn delete_setting(&self, key: &str) -> Result<bool>;

    // ------------------------------------------------ industrial conversations
    /// Insert or replace (by client, server, protocol, port).
    fn save_conversations(&self, c: &[Conversation]) -> Result<()>;
    fn list_conversations(&self) -> Result<Vec<Conversation>>;

    // ------------------------------------------------ asset tracking
    fn load_all_meta(&self) -> Result<HashMap<i64, AssetMeta>>;
    fn get_meta(&self, asset_id: i64) -> Result<Option<AssetMeta>>;
    fn save_meta(&self, asset_id: i64, meta: &AssetMeta, by: &str, ts: i64) -> Result<()>;
    /// Remove an asset and everything hanging off it (meta, baseline, presence, events).
    fn delete_asset(&self, id: i64) -> Result<()>;
    /// A verified, owner-only copy of the whole database at `dest` (which must not exist).
    fn backup_to(&self, dest: &std::path::Path) -> Result<()>;
    /// Remove one remote site (or demo site) with all of its trend samples.
    fn delete_agent_data(&self, agent_id: &str) -> Result<()>;
    /// Empty the inventory and everything derived from it (devices, edits, alerts, baselines,
    /// communications, presence, trends, remote sites). Users, sessions, the audit log,
    /// channels, branding, rule settings and tokens are kept.
    fn erase_inventory(&self) -> Result<()>;

    // ------------------------------------------------ users and sessions
    /// Fails if the username (case-insensitive) exists.
    fn create_user(&self, username: &str, password_hash: &str, role: &str, must_change: bool, ts: i64) -> Result<User>;
    fn find_user(&self, username: &str) -> Result<Option<UserRecord>>;
    fn get_user_record(&self, id: i64) -> Result<Option<UserRecord>>;
    fn list_users(&self) -> Result<Vec<User>>;
    fn update_user(&self, id: i64, role: Option<&str>, disabled: Option<bool>, password_hash: Option<&str>, must_change: Option<bool>) -> Result<bool>;
    fn set_last_login(&self, id: i64, ts: i64) -> Result<()>;
    fn create_session(&self, token_hash: &str, user_id: i64, now: i64, expires_at: i64) -> Result<()>;
    fn get_session(&self, token_hash: &str) -> Result<Option<SessionRecord>>;
    fn touch_session(&self, token_hash: &str, now: i64) -> Result<()>;
    fn delete_session(&self, token_hash: &str) -> Result<()>;
    /// Sign a user out everywhere, optionally keeping one session.
    fn delete_user_sessions(&self, user_id: i64, except: Option<&str>) -> Result<()>;
    fn prune_sessions(&self, now: i64) -> Result<usize>;

    // ------------------------------------------------ audit trail
    fn add_audit(&self, ts: i64, user: &str, action: &str, asset_id: Option<i64>, detail: &serde_json::Value) -> Result<()>;
    /// Newest first.
    /// Audit entries with `id > after`, oldest first (export cursor).
    fn audit_after(&self, after: i64, limit: usize) -> Result<Vec<AuditEntry>>;
    fn list_audit(&self, asset_id: Option<i64>, limit: usize) -> Result<Vec<AuditEntry>>;

    // ------------------------------------------------ accepted risks
    /// Record a decision. An earlier one for the same finding and device is withdrawn (replaced by this one).
    fn add_risk_acceptance(&self, a: &RiskAcceptance) -> Result<i64>;
    /// Every decision that has not been withdrawn (expired ones included: the caller checks `is_active`), newest first.
    fn list_risk_acceptances(&self) -> Result<Vec<RiskAcceptance>>;
    /// Withdraw a decision. `false` if there was none (or it was already withdrawn).
    fn revoke_risk_acceptance(&self, id: i64, by: &str, ts: i64) -> Result<bool>;

    // ------------------------------------------------ per-agent tokens
    /// Replaces (revokes) any earlier token for the same agent.
    fn set_agent_token(&self, agent_id: &str, token_hash: &str, label: &str, ts: i64) -> Result<()>;
    fn find_agent_token(&self, token_hash: &str) -> Result<Option<AgentToken>>;
    fn list_agent_tokens(&self) -> Result<Vec<AgentToken>>;
    fn revoke_agent_token(&self, agent_id: &str) -> Result<bool>;
    fn touch_agent_token(&self, token_hash: &str, ts: i64) -> Result<()>;

    // ----- passkeys
    fn add_passkey(&self, user_id: i64, credential_id: &[u8], public_key: &[u8], sign_count: u32, name: &str, ts: i64) -> Result<i64>;
    fn find_passkey(&self, credential_id: &[u8]) -> Result<Option<Passkey>>;
    fn list_passkeys(&self, user_id: i64) -> Result<Vec<Passkey>>;
    fn update_passkey_use(&self, id: i64, sign_count: u32, ts: i64) -> Result<()>;
    /// Remove one of a user's own passkeys.
    fn delete_passkey(&self, id: i64, user_id: i64) -> Result<bool>;
    fn delete_user_passkeys(&self, user_id: i64) -> Result<usize>;

    // ----- API tokens (scripts and integrations)
    fn create_api_token(&self, token_hash: &str, label: &str, role: &str, created_by: &str, ts: i64) -> Result<i64>;
    fn find_api_token(&self, token_hash: &str) -> Result<Option<ApiToken>>;
    fn list_api_tokens(&self) -> Result<Vec<ApiToken>>;
    fn revoke_api_token(&self, id: i64) -> Result<bool>;
    fn touch_api_token(&self, token_hash: &str, ts: i64) -> Result<()>;
}
