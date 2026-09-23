use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};

use std::collections::HashMap;

use super::{
    AdminStore, AgentToken, ApiToken, AssetStore, AuthStore, EventQuery, EventStore, MetricStore, Passkey, ReportStore,
    SessionRecord, SettingsStore, Store, StoreStats, TopoRow, TotpRecord, UserRecord,
};
use crate::model::{AgentInfo, Asset, AssetMeta, AuditEntry, Baseline, Conversation, Event, Fingerprint, Mac, Metric, Presence, ReportMeta, RiskAcceptance, User};

const SCHEMA_VERSION: i64 = 13;

/// Phase 1 schema.
const V1: &str = "CREATE TABLE assets (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id         TEXT,               -- NULL = the local collector
        mac              TEXT NOT NULL,
        vendor           TEXT,
        randomized_mac   INTEGER NOT NULL,
        ip_history       TEXT NOT NULL,      -- JSON
        hostnames        TEXT NOT NULL,      -- JSON
        device_type      TEXT NOT NULL,
        os_guess         TEXT,
        guess_reasons    TEXT NOT NULL,      -- JSON
        open_ports       TEXT NOT NULL,      -- JSON
        ports_scanned_at INTEGER,
        fingerprint      TEXT NOT NULL,      -- JSON
        is_self          INTEGER NOT NULL,
        is_gateway       INTEGER NOT NULL,
        first_seen       INTEGER NOT NULL,
        last_seen        INTEGER NOT NULL
     );
     -- COALESCE: SQLite treats NULLs as distinct in UNIQUE indexes.
     CREATE UNIQUE INDEX assets_agent_mac ON assets (COALESCE(agent_id, ''), mac);
     CREATE TABLE events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id    TEXT,
        asset_id    INTEGER NOT NULL REFERENCES assets(id),
        type        TEXT NOT NULL,
        timestamp   INTEGER NOT NULL,
        severity    TEXT NOT NULL,
        raw_details TEXT NOT NULL            -- JSON
     );
     CREATE INDEX events_ts ON events (timestamp DESC);
     CREATE INDEX events_asset ON events (asset_id, timestamp DESC);";

/// Phase 2: alert scoring/ack, per-device baselines, registered agents.
const V2: &str = "ALTER TABLE events ADD COLUMN score INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE events ADD COLUMN acked INTEGER NOT NULL DEFAULT 0;
     CREATE TABLE baselines (
        asset_id   INTEGER PRIMARY KEY REFERENCES assets(id),
        data       TEXT NOT NULL,            -- JSON
        updated_at INTEGER NOT NULL
     );
     CREATE TABLE agents (
        id             TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        site           TEXT,
        version        TEXT NOT NULL,
        subnet         TEXT NOT NULL,
        first_seen     INTEGER NOT NULL,
        last_report_at INTEGER NOT NULL,
        last_run_id    TEXT NOT NULL,
        last_seq       INTEGER NOT NULL
     );";

/// Phase 3: presence history (for "went silent") and trend metrics.
const V3: &str = "CREATE TABLE presence (
        asset_id INTEGER PRIMARY KEY REFERENCES assets(id),
        data     TEXT NOT NULL               -- JSON
     );
     CREATE TABLE metrics (
        ts             INTEGER NOT NULL,
        agent_id       TEXT NOT NULL,        -- '' = local collector
        devices_total  INTEGER NOT NULL,
        devices_online INTEGER NOT NULL,
        bytes_out      INTEGER NOT NULL,
        bytes_in       INTEGER NOT NULL,
        alerts         INTEGER NOT NULL,
        PRIMARY KEY (ts, agent_id)
     );";

/// Phase 3.5: asset tracking, users/sessions, audit trail, per-agent tokens.
const V4: &str = "CREATE TABLE asset_meta (
        asset_id   INTEGER PRIMARY KEY,
        data       TEXT NOT NULL,            -- JSON
        updated_at INTEGER NOT NULL,
        updated_by TEXT NOT NULL
     );
     CREATE TABLE users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,         -- Argon2id PHC string
        role          TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        disabled      INTEGER NOT NULL DEFAULT 0,
        must_change   INTEGER NOT NULL DEFAULT 0,
        last_login    INTEGER
     );
     CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY,         -- SHA-256 of the cookie value; the token itself is never stored
        user_id    INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        last_used  INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
     );
     CREATE INDEX sessions_user ON sessions (user_id);
     CREATE TABLE audit (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        ts       INTEGER NOT NULL,
        user     TEXT NOT NULL,
        action   TEXT NOT NULL,
        asset_id INTEGER,
        detail   TEXT NOT NULL               -- JSON
     );
     CREATE INDEX audit_asset ON audit (asset_id, ts DESC);
     CREATE INDEX audit_ts ON audit (ts DESC);
     CREATE TABLE agent_tokens (
        token_hash TEXT PRIMARY KEY,         -- SHA-256; the token is shown once at creation
        agent_id   TEXT NOT NULL,
        label      TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used  INTEGER,
        revoked    INTEGER NOT NULL DEFAULT 0
     );
     CREATE INDEX agent_tokens_agent ON agent_tokens (agent_id);";

/// Phase 3.6: the OT communications matrix.
const V5: &str = "CREATE TABLE conversations (
        client_id INTEGER NOT NULL,
        server_id INTEGER NOT NULL,
        proto     TEXT NOT NULL,
        port      INTEGER NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        packets    INTEGER NOT NULL,
        bytes      INTEGER NOT NULL,
        reads      INTEGER NOT NULL,
        writes     INTEGER NOT NULL,
        controls   INTEGER NOT NULL,
        note       TEXT,
        PRIMARY KEY (client_id, server_id, proto, port)
     );
     CREATE INDEX conversations_server ON conversations (server_id);";

/// Phase 3.7: administrator settings (white-label branding, logo).
const V6: &str = "CREATE TABLE settings (
        key        TEXT PRIMARY KEY,
        value      BLOB NOT NULL,
        updated_at INTEGER NOT NULL
     );";

/// Which industrial functions each path uses (lets people watch for specific commands).
const V9: &str = "ALTER TABLE conversations ADD COLUMN commands TEXT NOT NULL DEFAULT '{}';";

/// Accepted risks: a person decided to live with a finding on a device (with the reason and an optional end date).
const V10: &str = "CREATE TABLE risk_acceptances (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id  TEXT NOT NULL,
        asset_id    INTEGER NOT NULL,
        reason      TEXT NOT NULL,
        accepted_by TEXT NOT NULL,
        accepted_at INTEGER NOT NULL,
        expires_at  INTEGER,
        revoked_at  INTEGER,
        revoked_by  TEXT
     );
     CREATE INDEX risk_acceptances_asset ON risk_acceptances (asset_id);";

/// Reports kept in the database, so they can be viewed and downloaded from the console at any time.
const V11: &str = "CREATE TABLE reports (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        kind        TEXT NOT NULL,            -- manual | scheduled
        title       TEXT NOT NULL,
        period_days INTEGER NOT NULL,
        created_at  INTEGER NOT NULL,
        created_by  TEXT NOT NULL,
        content     BLOB NOT NULL
     );
     CREATE INDEX reports_created ON reports (created_at);";

/// Authenticator-app sign-in (TOTP): one secret per person (pending until the first code is confirmed), and recovery codes.
const V12: &str = "CREATE TABLE totp (
        user_id    INTEGER PRIMARY KEY,
        secret     BLOB NOT NULL,
        enabled    INTEGER NOT NULL DEFAULT 0,
        last_step  INTEGER NOT NULL DEFAULT 0,   -- the newest 30-second step accepted: a code works once
        created_at INTEGER NOT NULL
     );
     CREATE TABLE totp_recovery (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id   INTEGER NOT NULL,
        code_hash TEXT NOT NULL,
        used_at   INTEGER
     );
     CREATE INDEX totp_recovery_user ON totp_recovery (user_id);";

/// What each polled switch last said (SNMP): the ports, its LLDP neighbours and its forwarding table, as JSON.
const V13: &str = "CREATE TABLE topo_snapshots (
        id        TEXT PRIMARY KEY,
        last_poll INTEGER NOT NULL,
        last_ok   INTEGER,
        error     TEXT,
        snapshot  TEXT
     );";

/// Phase 3.8: API tokens for scripts and integrations.
const V7: &str = "CREATE TABLE api_tokens (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT NOT NULL UNIQUE,     -- SHA-256; the token is shown once at creation
        label      TEXT NOT NULL,
        role       TEXT NOT NULL CHECK (role IN ('viewer', 'editor')),
        created_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used  INTEGER,
        revoked    INTEGER NOT NULL DEFAULT 0
     );";

/// Phase 3.9: passkeys (WebAuthn credentials).
const V8: &str = "CREATE TABLE passkeys (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        credential_id BLOB NOT NULL UNIQUE,
        public_key    BLOB NOT NULL,        -- uncompressed P-256 point
        sign_count    INTEGER NOT NULL,
        name          TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        last_used     INTEGER
     );
     CREATE INDEX passkeys_user ON passkeys (user_id);";

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// The lock on the connection. A panic in another thread while it is held "poisons" a
    /// std `Mutex`; the data behind it is still consistent either way (SQLite guards its own
    /// internal state, and every method here leaves the connection in a valid state or returns
    /// an error before committing), so every request after that one panic does not need to fail
    /// too — the alternative is every `.unwrap()` here panicking forever, taking down the whole
    /// process until it is restarted by hand.
    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        // WAL lets `denis list` read while the daemon writes.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            anyhow::bail!("database schema v{version} is newer than this build (v{SCHEMA_VERSION})");
        }
        // Each step runs in its own transaction and bumps user_version, so a
        // crash mid-migration leaves the database at a consistent older version.
        for (target, sql) in [(1, V1), (2, V2), (3, V3), (4, V4), (5, V5), (6, V6), (7, V7), (8, V8), (9, V9), (10, V10), (11, V11), (12, V12), (13, V13)] {
            if version < target {
                let tx = conn.unchecked_transaction()?;
                tx.execute_batch(sql)?;
                tx.pragma_update(None, "user_version", target)?;
                tx.commit()?;
            }
        }
        // Declared FKs (`events`/`baselines`/`presence`.asset_id, `passkeys`.user_id) were never
        // actually enforced before this: SQLite defaults foreign_keys to OFF. Turned on only
        // *after* the migrations above, in case an older schema step would behave differently
        // with it on. `delete_asset`/`erase_inventory` already delete children before the parent
        // row, so this changes no existing behaviour — it only catches a *future* bug that tries
        // to skip that ordering. A pre-existing database could in principle already have orphans
        // from before this line existed; that is not fatal (SQLite does not retroactively
        // validate existing rows when the pragma is turned on), so this only logs, never refuses
        // to start.
        conn.pragma_update(None, "foreign_keys", true)?;
        let mut violations = Vec::new();
        conn.pragma_query(None, "foreign_key_check", |r| {
            violations.push(r.get::<_, String>(0)?);
            Ok(())
        })?;
        if !violations.is_empty() {
            tracing::warn!("{} pre-existing foreign key violation(s) found (harmless, not fixed automatically): {:?}", violations.len(), violations);
        }
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }
}

const ASSET_COLS: &str = "id, agent_id, mac, vendor, randomized_mac, ip_history, hostnames, \
    device_type, os_guess, guess_reasons, open_ports, ports_scanned_at, fingerprint, \
    is_self, is_gateway, first_seen, last_seen";

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serialisable")
}

fn from_json<T: serde::de::DeserializeOwned>(r: &Row, i: usize) -> rusqlite::Result<T> {
    let s: String = r.get(i)?;
    serde_json::from_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn row_to_passkey(r: &Row) -> rusqlite::Result<Passkey> {
    Ok(Passkey { id: r.get(0)?, user_id: r.get(1)?, credential_id: r.get(2)?, public_key: r.get(3)?, sign_count: r.get(4)?, name: r.get(5)?, created_at: r.get(6)?, last_used: r.get(7)? })
}

fn row_to_api_token(r: &Row) -> rusqlite::Result<ApiToken> {
    Ok(ApiToken { id: r.get(0)?, label: r.get(1)?, role: r.get(2)?, created_by: r.get(3)?, created_at: r.get(4)?, last_used: r.get(5)?, revoked: r.get(6)? })
}

fn row_to_asset(r: &Row) -> rusqlite::Result<Asset> {
    let mac: String = r.get(2)?;
    Ok(Asset {
        id: r.get(0)?,
        agent_id: r.get(1)?,
        mac: mac.parse::<Mac>().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, e.into())
        })?,
        vendor: r.get(3)?,
        randomized_mac: r.get(4)?,
        ip_history: from_json(r, 5)?,
        hostnames: from_json(r, 6)?,
        device_type: r.get(7)?,
        os_guess: r.get(8)?,
        guess_reasons: from_json(r, 9)?,
        open_ports: from_json(r, 10)?,
        ports_scanned_at: r.get(11)?,
        fingerprint: from_json::<Fingerprint>(r, 12)?,
        is_self: r.get(13)?,
        is_gateway: r.get(14)?,
        first_seen: r.get(15)?,
        last_seen: r.get(16)?,
    })
}

impl SqliteStore {
    /// A consistent copy of the whole database at `dest`, made while the program keeps
    /// running (SQLite's `VACUUM INTO`). The destination must not exist. The copy is
    /// verified (`integrity_check`) and made readable by its owner only: it holds password
    /// hashes and notification secrets.
    pub fn backup_to(&self, dest: &Path) -> Result<()> {
        if dest.exists() {
            anyhow::bail!("{} already exists; refusing to overwrite a backup", dest.display());
        }
        let text = dest.to_str().context("the backup path must be valid text")?;
        {
            let conn = self.conn();
            conn.execute("VACUUM INTO ?1", [text])?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600))?;
        }
        let check = Connection::open_with_flags(dest, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let verdict: String = check.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if verdict != "ok" {
            let _ = std::fs::remove_file(dest);
            anyhow::bail!("the backup failed its integrity check: {verdict}");
        }
        Ok(())
    }
}

impl AssetStore for SqliteStore {
    fn load_assets(&self) -> Result<Vec<Asset>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {ASSET_COLS} FROM assets ORDER BY id"))?;
        let rows = stmt.query_map([], row_to_asset)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn save_asset(&self, a: &mut Asset) -> Result<()> {
        let conn = self.conn();
        // A manually created asset may already own this (agent, mac): adopt it, so
        // discovery and manual entry converge on one row instead of colliding.
        if a.id == 0 {
            let existing: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT id, first_seen FROM assets WHERE COALESCE(agent_id, '') = COALESCE(?1, '') AND mac = ?2",
                    params![a.agent_id, a.mac.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((id, first_seen)) = existing {
                a.id = id;
                a.first_seen = a.first_seen.min(first_seen);
            }
        }
        let mac = a.mac.to_string();
        let values = params![
            a.agent_id,
            mac,
            a.vendor,
            a.randomized_mac,
            json(&a.ip_history),
            json(&a.hostnames),
            a.device_type,
            a.os_guess,
            json(&a.guess_reasons),
            json(&a.open_ports),
            a.ports_scanned_at,
            json(&a.fingerprint),
            a.is_self,
            a.is_gateway,
            a.first_seen,
            a.last_seen,
        ];
        if a.id == 0 {
            conn.execute(
                "INSERT INTO assets (agent_id, mac, vendor, randomized_mac, ip_history, hostnames,
                    device_type, os_guess, guess_reasons, open_ports, ports_scanned_at, fingerprint,
                    is_self, is_gateway, first_seen, last_seen)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                values,
            )?;
            a.id = conn.last_insert_rowid();
        } else {
            let n = conn.execute(
                "UPDATE assets SET agent_id=?1, mac=?2, vendor=?3, randomized_mac=?4, ip_history=?5,
                    hostnames=?6, device_type=?7, os_guess=?8, guess_reasons=?9, open_ports=?10,
                    ports_scanned_at=?11, fingerprint=?12, is_self=?13, is_gateway=?14,
                    first_seen=?15, last_seen=?16
                 WHERE id=?17",
                rusqlite::params_from_iter(
                    values
                        .iter()
                        .copied()
                        .chain(std::iter::once(&a.id as &dyn rusqlite::ToSql)),
                ),
            )?;
            anyhow::ensure!(n == 1, "asset {} vanished from the database", a.id);
        }
        Ok(())
    }
    fn get_asset(&self, id: i64) -> Result<Option<Asset>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                &format!("SELECT {ASSET_COLS} FROM assets WHERE id = ?1"),
                [id],
                row_to_asset,
            )
            .optional()?)
    }
    fn find_asset(&self, agent_id: Option<&str>, mac: &Mac) -> Result<Option<Asset>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                &format!(
                    "SELECT {ASSET_COLS} FROM assets WHERE COALESCE(agent_id, '') = COALESCE(?1, '') AND mac = ?2"
                ),
                params![agent_id, mac.to_string()],
                row_to_asset,
            )
            .optional()?)
    }
    fn load_baselines(&self) -> Result<Vec<Baseline>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT data FROM baselines")?;
        let rows = stmt.query_map([], |r| from_json::<Baseline>(r, 0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn get_baseline(&self, asset_id: i64) -> Result<Option<Baseline>> {
        let conn = self.conn();
        Ok(conn
            .query_row("SELECT data FROM baselines WHERE asset_id = ?1", [asset_id], |r| from_json(r, 0))
            .optional()?)
    }
    fn save_baseline(&self, b: &Baseline) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO baselines (asset_id, data, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(asset_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
            params![b.asset_id, json(b), b.updated_at],
        )?;
        Ok(())
    }
    fn load_presence(&self) -> Result<Vec<Presence>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT data FROM presence")?;
        let rows = stmt.query_map([], |r| from_json::<Presence>(r, 0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn save_presence(&self, p: &Presence) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO presence (asset_id, data) VALUES (?1, ?2)
             ON CONFLICT(asset_id) DO UPDATE SET data = excluded.data",
            params![p.asset_id, json(p)],
        )?;
        Ok(())
    }
    // ------------------------------------------------ industrial conversations
    fn save_conversations(&self, c: &[Conversation]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for x in c {
            tx.execute(
                "INSERT OR REPLACE INTO conversations
                    (client_id, server_id, proto, port, first_seen, last_seen, packets, bytes, reads, writes, controls, note, commands)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![x.client_id, x.server_id, x.proto, x.port, x.first_seen, x.last_seen, x.packets, x.bytes, x.reads, x.writes, x.controls, x.note, serde_json::to_string(&x.commands)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT client_id, server_id, proto, port, first_seen, last_seen, packets, bytes, reads, writes, controls, note, commands
             FROM conversations ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Conversation {
                client_id: r.get(0)?, server_id: r.get(1)?, proto: r.get(2)?, port: r.get(3)?, first_seen: r.get(4)?,
                last_seen: r.get(5)?, packets: r.get(6)?, bytes: r.get(7)?, reads: r.get(8)?, writes: r.get(9)?,
                controls: r.get(10)?, note: r.get(11)?,
                commands: serde_json::from_str(&r.get::<_, String>(12)?).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    // ------------------------------------------------ asset tracking
    fn load_all_meta(&self) -> Result<HashMap<i64, AssetMeta>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT asset_id, data FROM asset_meta")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, from_json::<AssetMeta>(r, 1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn get_meta(&self, asset_id: i64) -> Result<Option<AssetMeta>> {
        let conn = self.conn();
        Ok(conn
            .query_row("SELECT data FROM asset_meta WHERE asset_id = ?1", [asset_id], |r| from_json(r, 0))
            .optional()?)
    }
    fn save_meta(&self, asset_id: i64, meta: &AssetMeta, by: &str, ts: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO asset_meta (asset_id, data, updated_at, updated_by) VALUES (?1,?2,?3,?4)
             ON CONFLICT(asset_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
            params![asset_id, json(meta), ts, by],
        )?;
        Ok(())
    }
    fn delete_asset(&self, id: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for sql in [
            "DELETE FROM asset_meta WHERE asset_id = ?1",
            "DELETE FROM risk_acceptances WHERE asset_id = ?1",
            "DELETE FROM baselines WHERE asset_id = ?1",
            "DELETE FROM presence WHERE asset_id = ?1",
            "DELETE FROM conversations WHERE client_id = ?1 OR server_id = ?1",
            "DELETE FROM events WHERE asset_id = ?1",
            "DELETE FROM assets WHERE id = ?1",
        ] {
            tx.execute(sql, [id])?;
        }
        tx.commit()?;
        Ok(())
    }

}

impl EventStore for SqliteStore {
    fn insert_event(&self, e: &mut Event) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO events (agent_id, asset_id, type, timestamp, severity, score, acked, raw_details)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![e.agent_id, e.asset_id, e.kind, e.timestamp, e.severity, e.score, e.acked, json(&e.raw_details)],
        )?;
        e.id = conn.last_insert_rowid();
        Ok(())
    }
    fn list_events(&self, q: &EventQuery) -> Result<Vec<Event>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, asset_id, type, timestamp, severity, score, acked, raw_details
             FROM events
             WHERE (?1 IS NULL OR asset_id = ?1)
               AND (?2 = 0 OR severity <> 'info')
               AND (?3 = 0 OR acked = 0)
             ORDER BY timestamp DESC, id DESC LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![q.asset_id, q.alerts_only, q.unacked_only, q.limit as i64],
            |r| {
                Ok(Event {
                    id: r.get(0)?,
                    agent_id: r.get(1)?,
                    asset_id: r.get(2)?,
                    kind: r.get(3)?,
                    timestamp: r.get(4)?,
                    severity: r.get(5)?,
                    score: r.get(6)?,
                    acked: r.get(7)?,
                    raw_details: from_json(r, 8)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn get_event(&self, id: i64) -> Result<Option<Event>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT id, agent_id, asset_id, type, timestamp, severity, score, acked, raw_details FROM events WHERE id = ?1",
                [id],
                |r| {
                    Ok(Event {
                        id: r.get(0)?,
                        agent_id: r.get(1)?,
                        asset_id: r.get(2)?,
                        kind: r.get(3)?,
                        timestamp: r.get(4)?,
                        severity: r.get(5)?,
                        score: r.get(6)?,
                        acked: r.get(7)?,
                        raw_details: from_json(r, 8)?,
                    })
                },
            )
            .optional()?)
    }
    fn events_after(&self, after: i64, limit: usize) -> Result<Vec<Event>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, asset_id, type, timestamp, severity, score, acked, raw_details
             FROM events WHERE id > ?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![after, limit as i64], |r| {
            Ok(Event {
                id: r.get(0)?, agent_id: r.get(1)?, asset_id: r.get(2)?, kind: r.get(3)?, timestamp: r.get(4)?,
                severity: r.get(5)?, score: r.get(6)?, acked: r.get(7)?, raw_details: from_json(r, 8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn set_event_acked(&self, id: i64, acked: bool) -> Result<bool> {
        let conn = self.conn();
        Ok(conn.execute("UPDATE events SET acked = ?2 WHERE id = ?1", params![id, acked])? == 1)
    }

}

impl MetricStore for SqliteStore {
    fn insert_metrics(&self, m: &[Metric]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for x in m {
            tx.execute(
                "INSERT OR REPLACE INTO metrics (ts, agent_id, devices_total, devices_online, bytes_out, bytes_in, alerts)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![x.ts, x.agent_id, x.devices_total, x.devices_online, x.bytes_out, x.bytes_in, x.alerts],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    fn list_metrics(&self, since: i64, until: i64, agent_id: Option<&str>) -> Result<Vec<Metric>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT ts, agent_id, devices_total, devices_online, bytes_out, bytes_in, alerts
             FROM metrics WHERE ts >= ?1 AND ts < ?2 AND (?3 IS NULL OR agent_id = ?3)
             ORDER BY ts, agent_id",
        )?;
        let rows = stmt.query_map(params![since, until, agent_id], |r| {
            Ok(Metric {
                ts: r.get(0)?,
                agent_id: r.get(1)?,
                devices_total: r.get(2)?,
                devices_online: r.get(3)?,
                bytes_out: r.get(4)?,
                bytes_in: r.get(5)?,
                alerts: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn prune_metrics(&self, before: i64) -> Result<usize> {
        let conn = self.conn();
        Ok(conn.execute("DELETE FROM metrics WHERE ts < ?1", [before])?)
    }

}

impl SettingsStore for SqliteStore {
    // ------------------------------------------------ settings
    fn get_setting(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn();
        Ok(conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }
    fn set_setting(&self, key: &str, value: &[u8], ts: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1,?2,?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, ts],
        )?;
        Ok(())
    }
    fn delete_setting(&self, key: &str) -> Result<bool> {
        let conn = self.conn();
        Ok(conn.execute("DELETE FROM settings WHERE key = ?1", [key])? > 0)
    }

}

impl ReportStore for SqliteStore {
    // ------------------------------------------------ reports
    fn add_report(&self, m: &ReportMeta, content: &[u8]) -> Result<i64> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO reports (kind, title, period_days, created_at, created_by, content) VALUES (?1,?2,?3,?4,?5,?6)",
            params![m.kind, m.title, m.period_days, m.created_at, m.created_by, content],
        )?;
        Ok(conn.last_insert_rowid())
    }
    fn list_reports(&self) -> Result<Vec<ReportMeta>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, kind, title, period_days, created_at, created_by, length(content) FROM reports ORDER BY created_at DESC, id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ReportMeta { id: r.get(0)?, kind: r.get(1)?, title: r.get(2)?, period_days: r.get(3)?, created_at: r.get(4)?, created_by: r.get(5)?, size: r.get(6)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn get_report(&self, id: i64) -> Result<Option<(ReportMeta, Vec<u8>)>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT id, kind, title, period_days, created_at, created_by, length(content), content FROM reports WHERE id = ?1",
                [id],
                |r| {
                    Ok((
                        ReportMeta { id: r.get(0)?, kind: r.get(1)?, title: r.get(2)?, period_days: r.get(3)?, created_at: r.get(4)?, created_by: r.get(5)?, size: r.get(6)? },
                        r.get::<_, Vec<u8>>(7)?,
                    ))
                },
            )
            .optional()?)
    }
    fn delete_report(&self, id: i64) -> Result<bool> {
        let conn = self.conn();
        Ok(conn.execute("DELETE FROM reports WHERE id = ?1", [id])? > 0)
    }
    fn prune_reports(&self, kind: &str, keep: usize) -> Result<usize> {
        let conn = self.conn();
        Ok(conn.execute(
            "DELETE FROM reports WHERE kind = ?1 AND id NOT IN (SELECT id FROM reports WHERE kind = ?1 ORDER BY created_at DESC, id DESC LIMIT ?2)",
            params![kind, keep as i64],
        )?)
    }

}

impl AuthStore for SqliteStore {
    // ------------------------------------------------ authenticator app (TOTP)
    fn get_totp(&self, user_id: i64) -> Result<Option<TotpRecord>> {
        let conn = self.conn();
        Ok(conn
            .query_row("SELECT user_id, secret, enabled, last_step, created_at FROM totp WHERE user_id = ?1", [user_id], |r| {
                Ok(TotpRecord { user_id: r.get(0)?, secret: r.get(1)?, enabled: r.get::<_, i64>(2)? != 0, last_step: r.get(3)?, created_at: r.get(4)? })
            })
            .optional()?)
    }
    fn set_totp_pending(&self, user_id: i64, secret: &[u8], now: i64) -> Result<bool> {
        let conn = self.conn();
        // a working secret is never replaced by starting again: it has to be switched off first
        if conn.query_row("SELECT enabled FROM totp WHERE user_id = ?1", [user_id], |r| r.get::<_, i64>(0)).optional()?.is_some_and(|e| e != 0) {
            return Ok(false);
        }
        conn.execute("INSERT OR REPLACE INTO totp (user_id, secret, enabled, last_step, created_at) VALUES (?1, ?2, 0, 0, ?3)", params![user_id, secret, now])?;
        Ok(true)
    }
    fn enable_totp(&self, user_id: i64, step: i64, recovery_hashes: &[String]) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute("UPDATE totp SET enabled = 1, last_step = ?2 WHERE user_id = ?1 AND enabled = 0", params![user_id, step])?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute("DELETE FROM totp_recovery WHERE user_id = ?1", [user_id])?;
        for h in recovery_hashes {
            tx.execute("INSERT INTO totp_recovery (user_id, code_hash) VALUES (?1, ?2)", params![user_id, h])?;
        }
        tx.commit()?;
        Ok(true)
    }
    fn advance_totp_step(&self, user_id: i64, step: i64) -> Result<bool> {
        let conn = self.conn();
        // one statement, so two requests with the same code cannot both win
        Ok(conn.execute("UPDATE totp SET last_step = ?2 WHERE user_id = ?1 AND enabled = 1 AND last_step < ?2", params![user_id, step])? > 0)
    }
    fn use_recovery_code(&self, user_id: i64, code_hash: &str, now: i64) -> Result<bool> {
        let conn = self.conn();
        Ok(conn.execute("UPDATE totp_recovery SET used_at = ?3 WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL", params![user_id, code_hash, now])? > 0)
    }
    fn replace_recovery_codes(&self, user_id: i64, hashes: &[String]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM totp_recovery WHERE user_id = ?1", [user_id])?;
        for h in hashes {
            tx.execute("INSERT INTO totp_recovery (user_id, code_hash) VALUES (?1, ?2)", params![user_id, h])?;
        }
        tx.commit()?;
        Ok(())
    }
    fn recovery_codes_left(&self, user_id: i64) -> Result<usize> {
        let conn = self.conn();
        Ok(conn.query_row("SELECT COUNT(*) FROM totp_recovery WHERE user_id = ?1 AND used_at IS NULL", [user_id], |r| r.get::<_, i64>(0))? as usize)
    }
    fn delete_totp(&self, user_id: i64) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM totp_recovery WHERE user_id = ?1", [user_id])?;
        let n = tx.execute("DELETE FROM totp WHERE user_id = ?1", [user_id])?;
        tx.commit()?;
        Ok(n > 0)
    }
    fn totp_enabled_users(&self) -> Result<std::collections::HashSet<i64>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT user_id FROM totp WHERE enabled = 1")?;
        let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    // ------------------------------------------------ users and sessions
    fn create_user(&self, username: &str, password_hash: &str, role: &str, must_change: bool, ts: i64) -> Result<User> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at, must_change) VALUES (?1,?2,?3,?4,?5)",
            params![username, password_hash, role, ts, must_change],
        )
        .with_context(|| format!("creating user {username:?}"))?;
        Ok(User { id: conn.last_insert_rowid(), username: username.into(), role: role.into(), created_at: ts, disabled: false, must_change, last_login: None })
    }
    fn find_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let conn = self.conn();
        Ok(conn
            .query_row(&format!("SELECT {USER_COLS} FROM users WHERE username = ?1"), [username], row_to_user_record)
            .optional()?)
    }
    fn get_user_record(&self, id: i64) -> Result<Option<UserRecord>> {
        let conn = self.conn();
        Ok(conn
            .query_row(&format!("SELECT {USER_COLS} FROM users WHERE id = ?1"), [id], row_to_user_record)
            .optional()?)
    }
    fn list_users(&self) -> Result<Vec<User>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY username"))?;
        let rows = stmt.query_map([], |r| row_to_user_record(r).map(|u| u.user))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn update_user(&self, id: i64, role: Option<&str>, disabled: Option<bool>, password_hash: Option<&str>, must_change: Option<bool>) -> Result<bool> {
        let conn = self.conn();
        let n = conn.execute(
            "UPDATE users SET role = COALESCE(?2, role), disabled = COALESCE(?3, disabled),
                password_hash = COALESCE(?4, password_hash), must_change = COALESCE(?5, must_change)
             WHERE id = ?1",
            params![id, role, disabled, password_hash, must_change],
        )?;
        Ok(n == 1)
    }
    fn delete_user(&self, id: i64) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])?;
        tx.execute("DELETE FROM passkeys WHERE user_id = ?1", params![id])?;
        tx.execute("DELETE FROM totp WHERE user_id = ?1", params![id])?;
        tx.execute("DELETE FROM totp_recovery WHERE user_id = ?1", params![id])?;
        // `site_access` (crate::access) lives as one JSON list under a `settings` key, not a
        // table `id` can reference, so no FK ever catches it. Filtering it here, inline, is the
        // only way to keep it in the same transaction as the user itself: going through
        // `access::set_for_user` would call back into this store and re-lock `self.conn`, which
        // deadlocks (the lock this method holds is not reentrant).
        let grants: Option<Vec<u8>> = tx.query_row("SELECT value FROM settings WHERE key = 'site_access'", [], |r| r.get(0)).optional()?;
        if let Some(bytes) = grants {
            if let Ok(mut list) = serde_json::from_slice::<Vec<crate::access::Grant>>(&bytes) {
                let before = list.len();
                list.retain(|g| g.user_id != id);
                if list.len() != before {
                    tx.execute("UPDATE settings SET value = ?1 WHERE key = 'site_access'", params![serde_json::to_vec(&list)?])?;
                }
            }
        }
        let n = tx.execute("DELETE FROM users WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(n == 1)
    }
    fn set_last_login(&self, id: i64, ts: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("UPDATE users SET last_login = ?2 WHERE id = ?1", params![id, ts])?;
        Ok(())
    }
    fn create_session(&self, token_hash: &str, user_id: i64, now: i64, expires_at: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, last_used, expires_at) VALUES (?1,?2,?3,?3,?4)",
            params![token_hash, user_id, now, expires_at],
        )?;
        Ok(())
    }
    fn get_session(&self, token_hash: &str) -> Result<Option<SessionRecord>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT u.id, u.username, u.role, u.created_at, u.disabled, u.must_change, u.last_login,
                        s.created_at, s.last_used, s.expires_at
                 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1",
                [token_hash],
                |r| {
                    Ok(SessionRecord {
                        user: User {
                            id: r.get(0)?, username: r.get(1)?, role: r.get(2)?, created_at: r.get(3)?,
                            disabled: r.get(4)?, must_change: r.get(5)?, last_login: r.get(6)?,
                        },
                        created_at: r.get(7)?,
                        last_used: r.get(8)?,
                        expires_at: r.get(9)?,
                    })
                },
            )
            .optional()?)
    }
    fn touch_session(&self, token_hash: &str, now: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("UPDATE sessions SET last_used = ?2 WHERE token_hash = ?1", params![token_hash, now])?;
        Ok(())
    }
    fn delete_session(&self, token_hash: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])?;
        Ok(())
    }
    fn delete_user_sessions(&self, user_id: i64, except: Option<&str>) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND (?2 IS NULL OR token_hash <> ?2)",
            params![user_id, except],
        )?;
        Ok(())
    }
    fn prune_sessions(&self, now: i64) -> Result<usize> {
        let conn = self.conn();
        Ok(conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])?)
    }
    // ------------------------------------------------ per-agent tokens
    fn set_agent_token(&self, agent_id: &str, token_hash: &str, label: &str, ts: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("UPDATE agent_tokens SET revoked = 1 WHERE agent_id = ?1", [agent_id])?;
        tx.execute(
            "INSERT INTO agent_tokens (token_hash, agent_id, label, created_at) VALUES (?1,?2,?3,?4)",
            params![token_hash, agent_id, label, ts],
        )?;
        tx.commit()?;
        Ok(())
    }
    fn find_agent_token(&self, token_hash: &str) -> Result<Option<AgentToken>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT agent_id, label, created_at, last_used, revoked FROM agent_tokens WHERE token_hash = ?1",
                [token_hash],
                row_to_agent_token,
            )
            .optional()?)
    }
    fn list_agent_tokens(&self) -> Result<Vec<AgentToken>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT agent_id, label, created_at, last_used, revoked FROM agent_tokens ORDER BY agent_id, created_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_agent_token)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn revoke_agent_token(&self, agent_id: &str) -> Result<bool> {
        let conn = self.conn();
        Ok(conn.execute("UPDATE agent_tokens SET revoked = 1 WHERE agent_id = ?1 AND revoked = 0", [agent_id])? > 0)
    }
    fn touch_agent_token(&self, token_hash: &str, ts: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("UPDATE agent_tokens SET last_used = ?2 WHERE token_hash = ?1", params![token_hash, ts])?;
        Ok(())
    }
    fn add_passkey(&self, user_id: i64, credential_id: &[u8], public_key: &[u8], sign_count: u32, name: &str, ts: i64) -> Result<i64> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, name, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![user_id, credential_id, public_key, sign_count, name, ts],
        )?;
        Ok(conn.last_insert_rowid())
    }
    fn find_passkey(&self, credential_id: &[u8]) -> Result<Option<Passkey>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT id, user_id, credential_id, public_key, sign_count, name, created_at, last_used FROM passkeys WHERE credential_id = ?1",
                [credential_id],
                row_to_passkey,
            )
            .optional()?)
    }
    fn list_passkeys(&self, user_id: i64) -> Result<Vec<Passkey>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id, user_id, credential_id, public_key, sign_count, name, created_at, last_used FROM passkeys WHERE user_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map([user_id], row_to_passkey)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn update_passkey_use(&self, id: i64, sign_count: u32, ts: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("UPDATE passkeys SET sign_count = ?2, last_used = ?3 WHERE id = ?1", params![id, sign_count, ts])?;
        Ok(())
    }
    fn delete_passkey(&self, id: i64, user_id: i64) -> Result<bool> {
        let conn = self.conn();
        Ok(conn.execute("DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2", params![id, user_id])? > 0)
    }
    fn delete_user_passkeys(&self, user_id: i64) -> Result<usize> {
        let conn = self.conn();
        Ok(conn.execute("DELETE FROM passkeys WHERE user_id = ?1", [user_id])?)
    }
    fn create_api_token(&self, token_hash: &str, label: &str, role: &str, created_by: &str, ts: i64) -> Result<i64> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO api_tokens (token_hash, label, role, created_by, created_at) VALUES (?1,?2,?3,?4,?5)",
            params![token_hash, label, role, created_by, ts],
        )?;
        Ok(conn.last_insert_rowid())
    }
    fn find_api_token(&self, token_hash: &str) -> Result<Option<ApiToken>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT id, label, role, created_by, created_at, last_used, revoked FROM api_tokens WHERE token_hash = ?1",
                [token_hash],
                row_to_api_token,
            )
            .optional()?)
    }
    fn list_api_tokens(&self) -> Result<Vec<ApiToken>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id, label, role, created_by, created_at, last_used, revoked FROM api_tokens ORDER BY id DESC")?;
        let rows = stmt.query_map([], row_to_api_token)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn revoke_api_token(&self, id: i64) -> Result<bool> {
        let conn = self.conn();
        Ok(conn.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ?1 AND revoked = 0", [id])? > 0)
    }
    fn touch_api_token(&self, token_hash: &str, ts: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("UPDATE api_tokens SET last_used = ?2 WHERE token_hash = ?1", params![token_hash, ts])?;
        Ok(())
    }

}

impl AdminStore for SqliteStore {
    fn upsert_agent(&self, a: &AgentInfo) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO agents (id, name, site, version, subnet, first_seen, last_report_at, last_run_id, last_seq)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, site=excluded.site, version=excluded.version,
                subnet=excluded.subnet, last_report_at=excluded.last_report_at,
                last_run_id=excluded.last_run_id, last_seq=excluded.last_seq",
            params![a.id, a.name, a.site, a.version, a.subnet, a.first_seen, a.last_report_at, a.last_run_id, a.last_seq as i64],
        )?;
        Ok(())
    }
    fn get_agent(&self, id: &str) -> Result<Option<AgentInfo>> {
        let conn = self.conn();
        Ok(conn
            .query_row(&format!("SELECT {AGENT_COLS} FROM agents WHERE id = ?1"), [id], row_to_agent)
            .optional()?)
    }
    fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {AGENT_COLS} FROM agents ORDER BY name"))?;
        let rows = stmt.query_map([], row_to_agent)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn backup_to(&self, dest: &Path) -> Result<()> {
        SqliteStore::backup_to(self, dest)
    }
    fn delete_agent_data(&self, agent_id: &str) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM metrics WHERE agent_id = ?1", [agent_id])?;
        tx.execute("DELETE FROM agents WHERE id = ?1", [agent_id])?;
        tx.commit()?;
        Ok(())
    }
    fn stats(&self, with_rows: bool) -> Result<StoreStats> {
        let conn = self.conn();
        let pragma = |name: &str| -> Result<i64> { Ok(conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?) };
        let (pages, size, free) = (pragma("page_count")?, pragma("page_size")?, pragma("freelist_count")?);
        let mut rows = Vec::new();
        // fixed names, never user input
        for t in ["assets", "events", "conversations", "metrics", "presence", "audit", "reports", "risk_acceptances", "sessions"].into_iter().filter(|_| with_rows) {
            rows.push((t, conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))?));
        }
        Ok(StoreStats { schema_version: pragma("user_version")?, db_bytes: pages * size, free_bytes: free * size, rows })
    }
    fn erase_inventory(&self) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        // children first
        for sql in [
            "DELETE FROM events", "DELETE FROM baselines", "DELETE FROM conversations", "DELETE FROM presence", "DELETE FROM metrics",
            "DELETE FROM asset_meta", "DELETE FROM risk_acceptances", "DELETE FROM reports", "DELETE FROM topo_snapshots", "DELETE FROM assets", "DELETE FROM agents",
            // learned state that belongs to the old network
            "DELETE FROM settings WHERE key = 'dhcp_servers'",
        ] {
            tx.execute(sql, [])?;
        }
        tx.commit()?;
        Ok(())
    }
    // ------------------------------------------------ accepted risks
    fn add_risk_acceptance(&self, a: &RiskAcceptance) -> Result<i64> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        // a new decision replaces the one still in force for the same finding and device
        tx.execute(
            "UPDATE risk_acceptances SET revoked_at = ?3, revoked_by = 'replaced' WHERE finding_id = ?1 AND asset_id = ?2 AND revoked_at IS NULL",
            params![a.finding_id, a.asset_id, a.accepted_at],
        )?;
        tx.execute(
            "INSERT INTO risk_acceptances (finding_id, asset_id, reason, accepted_by, accepted_at, expires_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![a.finding_id, a.asset_id, a.reason, a.accepted_by, a.accepted_at, a.expires_at],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }
    fn list_risk_acceptances(&self) -> Result<Vec<RiskAcceptance>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, finding_id, asset_id, reason, accepted_by, accepted_at, expires_at, revoked_at, revoked_by
             FROM risk_acceptances WHERE revoked_at IS NULL ORDER BY accepted_at DESC, id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(RiskAcceptance {
                id: r.get(0)?, finding_id: r.get(1)?, asset_id: r.get(2)?, reason: r.get(3)?, accepted_by: r.get(4)?,
                accepted_at: r.get(5)?, expires_at: r.get(6)?, revoked_at: r.get(7)?, revoked_by: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn revoke_risk_acceptance(&self, id: i64, by: &str, ts: i64) -> Result<bool> {
        let conn = self.conn();
        Ok(conn.execute("UPDATE risk_acceptances SET revoked_at = ?2, revoked_by = ?3 WHERE id = ?1 AND revoked_at IS NULL", params![id, ts, by])? > 0)
    }
    // ------------------------------------------------ switches (SNMP topology)
    fn save_topo(&self, id: &str, now: i64, snapshot: Result<&str, &str>) -> Result<()> {
        let conn = self.conn();
        match snapshot {
            Ok(json) => conn.execute(
                "INSERT INTO topo_snapshots (id, last_poll, last_ok, error, snapshot) VALUES (?1, ?2, ?2, NULL, ?3)
                 ON CONFLICT(id) DO UPDATE SET last_poll = ?2, last_ok = ?2, error = NULL, snapshot = ?3",
                params![id, now, json],
            )?,
            // a failed poll keeps what the switch said last time, and says why the newest one failed
            Err(e) => conn.execute(
                "INSERT INTO topo_snapshots (id, last_poll, last_ok, error, snapshot) VALUES (?1, ?2, NULL, ?3, NULL)
                 ON CONFLICT(id) DO UPDATE SET last_poll = ?2, error = ?3",
                params![id, now, e],
            )?,
        };
        Ok(())
    }
    fn list_topo(&self) -> Result<Vec<TopoRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id, last_poll, last_ok, error, snapshot FROM topo_snapshots ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok(TopoRow { id: r.get(0)?, last_poll: r.get(1)?, last_ok: r.get(2)?, error: r.get(3)?, snapshot: r.get(4)? }))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn delete_topo(&self, id: &str) -> Result<()> {
        self.conn().execute("DELETE FROM topo_snapshots WHERE id = ?1", [id])?;
        Ok(())
    }
    // ------------------------------------------------ audit trail
    fn add_audit(&self, ts: i64, user: &str, action: &str, asset_id: Option<i64>, detail: &serde_json::Value) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO audit (ts, user, action, asset_id, detail) VALUES (?1,?2,?3,?4,?5)",
            params![ts, user, action, asset_id, json(detail)],
        )?;
        Ok(())
    }
    fn audit_after(&self, after: i64, limit: usize) -> Result<Vec<AuditEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id, ts, user, action, asset_id, detail FROM audit WHERE id > ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![after, limit as i64], |r| {
            Ok(AuditEntry { id: r.get(0)?, ts: r.get(1)?, user: r.get(2)?, action: r.get(3)?, asset_id: r.get(4)?, detail: from_json(r, 5)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn list_audit(&self, asset_id: Option<i64>, limit: usize) -> Result<Vec<AuditEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, ts, user, action, asset_id, detail FROM audit
             WHERE (?1 IS NULL OR asset_id = ?1) ORDER BY ts DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![asset_id, limit as i64], |r| {
            Ok(AuditEntry { id: r.get(0)?, ts: r.get(1)?, user: r.get(2)?, action: r.get(3)?, asset_id: r.get(4)?, detail: from_json(r, 5)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

}

impl Store for SqliteStore {}

const USER_COLS: &str = "id, username, role, created_at, disabled, must_change, last_login, password_hash";

fn row_to_user_record(r: &Row) -> rusqlite::Result<UserRecord> {
    Ok(UserRecord {
        user: User { id: r.get(0)?, username: r.get(1)?, role: r.get(2)?, created_at: r.get(3)?, disabled: r.get(4)?, must_change: r.get(5)?, last_login: r.get(6)? },
        password_hash: r.get(7)?,
    })
}

fn row_to_agent_token(r: &Row) -> rusqlite::Result<AgentToken> {
    Ok(AgentToken { agent_id: r.get(0)?, label: r.get(1)?, created_at: r.get(2)?, last_used: r.get(3)?, revoked: r.get(4)? })
}

const AGENT_COLS: &str = "id, name, site, version, subnet, first_seen, last_report_at, last_run_id, last_seq";

fn row_to_agent(r: &Row) -> rusqlite::Result<AgentInfo> {
    Ok(AgentInfo {
        id: r.get(0)?,
        name: r.get(1)?,
        site: r.get(2)?,
        version: r.get(3)?,
        subnet: r.get(4)?,
        first_seen: r.get(5)?,
        last_report_at: r.get(6)?,
        last_run_id: r.get(7)?,
        last_seq: r.get::<_, i64>(8)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IpRecord, OpenPort};
    use std::net::Ipv4Addr;

    fn sample() -> Asset {
        let mut a = Asset::new(Mac([0x3c, 0x22, 0xfb, 1, 2, 3]), 100);
        a.vendor = Some("Apple".into());
        a.ip_history.push(IpRecord { ip: Ipv4Addr::new(192, 168, 1, 5), first_seen: 100, last_seen: 200 });
        a.hostnames.push("mac".into());
        a.open_ports.push(OpenPort { port: 22, proto: "tcp".into(), service: Some("ssh".into()) });
        a
    }

    #[test]
    fn a_panic_while_holding_the_connection_lock_does_not_wedge_every_later_request() {
        let store = std::sync::Arc::new(SqliteStore::open_in_memory().unwrap());
        let s2 = store.clone();
        // Panic inside a closure that has locked the connection (mimicking a bug elsewhere in a
        // request handler) — before the fix, this would poison the std Mutex and every following
        // `.lock().unwrap()` (i.e. every store call, from any request) would panic forever.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _conn = s2.conn();
            panic!("simulated bug while a request held the connection");
        }));
        assert!(result.is_err(), "the panic should have actually happened");
        // the store must still work for every other request after that one panic
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 9]), 5);
        store.save_asset(&mut a).unwrap();
        assert!(store.get_asset(a.id).unwrap().is_some());
    }

    #[test]
    fn a_backup_is_a_complete_verified_private_copy_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let live = SqliteStore::open(&dir.path().join("live.db")).unwrap();
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 5);
        live.save_asset(&mut a).unwrap();
        live.set_setting("channels", b"[secret]", 1).unwrap();
        let out = dir.path().join("backup.db");
        live.backup_to(&out).unwrap();
        let copy = SqliteStore::open(&out).unwrap();
        assert_eq!(copy.load_assets().unwrap().len(), 1);
        assert_eq!(copy.get_setting("channels").unwrap().as_deref(), Some(&b"[secret]"[..]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // the live database keeps working, and an existing file is never replaced
        live.set_setting("x", b"1", 2).unwrap();
        assert!(live.backup_to(&out).is_err());
        assert!(copy.get_setting("x").unwrap().is_none(), "the backup is a snapshot");
    }

    #[test]
    fn asset_roundtrip_and_update() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = sample();
        s.save_asset(&mut a).unwrap();
        assert!(a.id > 0);
        a.last_seen = 300;
        a.device_type = "computer".into();
        s.save_asset(&mut a).unwrap();
        let got = s.get_asset(a.id).unwrap().unwrap();
        assert_eq!(got.last_seen, 300);
        assert_eq!(got.mac, a.mac);
        assert_eq!(got.ip_history, a.ip_history);
        assert_eq!(got.open_ports, a.open_ports);
        assert_eq!(s.load_assets().unwrap().len(), 1);
        assert!(s.get_asset(999).unwrap().is_none());
    }

    #[test]
    fn a_second_save_of_the_same_agent_and_mac_converges_on_one_row() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = sample();
        a.first_seen = 500;
        s.save_asset(&mut a).unwrap();
        // e.g. a manually registered device that is later discovered: no error,
        // no duplicate, the earliest first_seen is kept.
        let mut dup = sample();
        dup.first_seen = 900;
        dup.hostnames = vec!["discovered".into()];
        s.save_asset(&mut dup).unwrap();
        assert_eq!(dup.id, a.id);
        assert_eq!(s.load_assets().unwrap().len(), 1);
        let got = s.get_asset(a.id).unwrap().unwrap();
        assert_eq!((got.first_seen, got.hostnames), (500, vec!["discovered".to_string()]));
        // A different agent may see the same MAC.
        let mut other = sample();
        other.agent_id = Some("site-b".into());
        s.save_asset(&mut other).unwrap();
    }

    #[test]
    fn events_newest_first_and_filtered() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = sample();
        s.save_asset(&mut a).unwrap();
        for ts in [10, 30, 20] {
            let mut e = Event {
                id: 0,
                agent_id: None,
                asset_id: a.id,
                kind: "new_device".into(),
                timestamp: ts,
                severity: if ts == 20 { "medium" } else { "info" }.into(),
                score: if ts == 20 { 55 } else { 0 },
                acked: false,
                raw_details: serde_json::json!({"ts": ts}),
            };
            s.insert_event(&mut e).unwrap();
        }
        let q = EventQuery { limit: 10, ..Default::default() };
        let all = s.list_events(&q).unwrap();
        assert_eq!(all.iter().map(|e| e.timestamp).collect::<Vec<_>>(), [30, 20, 10]);
        assert_eq!(s.list_events(&EventQuery { limit: 2, asset_id: Some(a.id), ..q.clone() }).unwrap().len(), 2);
        assert!(s.list_events(&EventQuery { asset_id: Some(a.id + 1), ..q.clone() }).unwrap().is_empty());

        // alerts_only hides info; acking removes from the unacked view
        let alerts = s.list_events(&EventQuery { alerts_only: true, ..q.clone() }).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!((alerts[0].score, alerts[0].acked), (55, false));
        assert!(s.set_event_acked(alerts[0].id, true).unwrap());
        assert!(s.list_events(&EventQuery { alerts_only: true, unacked_only: true, ..q.clone() }).unwrap().is_empty());
        assert!(s.list_events(&EventQuery { alerts_only: true, ..q }).unwrap()[0].acked);
        assert!(!s.set_event_acked(9999, true).unwrap());
    }

    #[test]
    fn find_asset_is_scoped_by_agent() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut local = sample();
        s.save_asset(&mut local).unwrap();
        let mut remote = sample();
        remote.agent_id = Some("site-b".into());
        s.save_asset(&mut remote).unwrap();
        assert_ne!(local.id, remote.id);
        assert_eq!(s.find_asset(None, &local.mac).unwrap().unwrap().id, local.id);
        assert_eq!(s.find_asset(Some("site-b"), &local.mac).unwrap().unwrap().id, remote.id);
        assert!(s.find_asset(Some("site-c"), &local.mac).unwrap().is_none());
    }

    #[test]
    fn baseline_and_agent_roundtrip() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = sample();
        s.save_asset(&mut a).unwrap();
        let mut b = Baseline::new(a.id, 1000);
        b.typical_destinations.insert("1.1.1.1".into(), crate::model::DestStat { first_seen: 1, last_seen: 2, bytes: 3 });
        b.volume = crate::model::VolumeStats { n: 4, mean: 5.5, var: 6.25 };
        b.active_hours[13] = 7;
        s.save_baseline(&b).unwrap();
        b.buckets = 9;
        s.save_baseline(&b).unwrap(); // upsert
        assert_eq!(s.get_baseline(a.id).unwrap().unwrap(), b);
        assert_eq!(s.load_baselines().unwrap().len(), 1);
        assert!(s.get_baseline(999).unwrap().is_none());

        let mut ag = AgentInfo {
            id: "site-b".into(), name: "Office".into(), site: Some("HQ".into()), version: "0.2.0".into(),
            subnet: "10.1.0.0/24".into(), first_seen: 10, last_report_at: 20, last_run_id: "r1".into(), last_seq: 3,
        };
        s.upsert_agent(&ag).unwrap();
        ag.last_seq = 4;
        ag.last_report_at = 30;
        s.upsert_agent(&ag).unwrap();
        assert_eq!(s.get_agent("site-b").unwrap().unwrap(), ag);
        assert_eq!(s.list_agents().unwrap().len(), 1);
        assert!(s.get_agent("nope").unwrap().is_none());
    }

    #[test]
    fn settings_store_bytes_and_replace() {
        let s = SqliteStore::open_in_memory().unwrap();
        assert_eq!(s.get_setting("k").unwrap(), None);
        s.set_setting("k", b"\x89PNG\x00binary", 1).unwrap();
        s.set_setting("k", b"v2", 2).unwrap();
        assert_eq!(s.get_setting("k").unwrap().as_deref(), Some(&b"v2"[..]));
        assert!(s.delete_setting("k").unwrap());
        assert!(!s.delete_setting("k").unwrap());
    }

    #[test]
    fn conversations_roundtrip_replace_and_cascade_on_delete() {
        let s = SqliteStore::open_in_memory().unwrap();
        let (mut a, mut b) = (sample(), sample());
        b.mac = Mac([0x3c, 0x22, 0xfb, 9, 9, 9]);
        s.save_asset(&mut a).unwrap();
        s.save_asset(&mut b).unwrap();
        let mut c = Conversation { client_id: a.id, server_id: b.id, proto: "modbus".into(), port: 502, first_seen: 1, last_seen: 2, packets: 3, bytes: 4, reads: 5, writes: 6, controls: 7, note: Some("PLC stop".into()), commands: [("write single register (6)".to_string(), 4)].into() };
        s.save_conversations(std::slice::from_ref(&c)).unwrap();
        c.packets = 99;
        s.save_conversations(std::slice::from_ref(&c)).unwrap(); // same key replaces
        assert_eq!(s.list_conversations().unwrap(), vec![c]);
        s.delete_asset(b.id).unwrap();
        assert!(s.list_conversations().unwrap().is_empty(), "a deleted asset takes its conversations with it");
    }

    #[test]
    fn presence_and_metrics_roundtrip_and_prune() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = sample();
        s.save_asset(&mut a).unwrap();
        let mut p = Presence { asset_id: a.id, ..Default::default() };
        p.hours.extend([10, 11, 12]);
        s.save_presence(&p).unwrap();
        p.silent_alerted = true;
        s.save_presence(&p).unwrap(); // upsert
        assert_eq!(s.load_presence().unwrap(), vec![p]);

        let m = |ts, agent: &str, total| Metric { ts, agent_id: agent.into(), devices_total: total, devices_online: total - 1, bytes_out: 5, bytes_in: 6, alerts: 1 };
        s.insert_metrics(&[m(100, "", 4), m(100, "site-b", 2), m(400, "", 5)]).unwrap();
        s.insert_metrics(&[m(400, "", 6)]).unwrap(); // same key replaces
        assert_eq!(s.list_metrics(0, 1000, None).unwrap().len(), 3);
        let local = s.list_metrics(0, 1000, Some("")).unwrap();
        assert_eq!(local.iter().map(|x| (x.ts, x.devices_total)).collect::<Vec<_>>(), [(100, 4), (400, 6)]);
        assert_eq!(s.list_metrics(101, 400, None).unwrap().len(), 0, "upper bound is exclusive");
        assert_eq!(s.prune_metrics(300).unwrap(), 2);
        assert_eq!(s.list_metrics(0, 1000, None).unwrap().len(), 1);
    }

    #[test]
    fn phase1_database_migrates_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p1.db");
        {
            // Exactly what a Phase 1 build left on disk.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(V1).unwrap();
            c.pragma_update(None, "user_version", 1).unwrap();
            c.execute(
                "INSERT INTO assets (agent_id, mac, vendor, randomized_mac, ip_history, hostnames, device_type,
                    os_guess, guess_reasons, open_ports, ports_scanned_at, fingerprint, is_self, is_gateway, first_seen, last_seen)
                 VALUES (NULL,'aa:bb:cc:00:00:01','V',0,'[]','[]','router',NULL,'[]','[]',NULL,
                    '{\"dhcp_vendor_class\":null,\"dhcp_param_list\":null,\"mdns_services\":[],\"mdns_names\":[],\"mdns_models\":[],\"ssdp_server\":null,\"ssdp_types\":[],\"tcp_sig\":null,\"ttl\":null}',0,1,5,6)",
                [],
            ).unwrap();
            c.execute(
                "INSERT INTO events (agent_id, asset_id, type, timestamp, severity, raw_details) VALUES (NULL,1,'new_device',5,'info','{}')",
                [],
            ).unwrap();
        }
        let s = SqliteStore::open(&path).unwrap();
        let assets = s.load_assets().unwrap();
        assert_eq!(assets.len(), 1);
        assert!(assets[0].is_gateway);
        let ev = s.list_events(&EventQuery::default()).unwrap();
        assert_eq!((ev.len(), ev[0].score, ev[0].acked), (1, 0, false));
        assert!(s.list_agents().unwrap().is_empty());
        // reopening at v2 is a no-op
        drop(s);
        SqliteStore::open(&path).unwrap();
    }

    #[test]
    fn accepted_risks_replace_each_other_can_be_withdrawn_and_go_with_their_device() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 1);
        let mut b = Asset::new(Mac([2, 0, 0, 0, 0, 2]), 1);
        s.save_asset(&mut a).unwrap();
        s.save_asset(&mut b).unwrap();
        let acc = |asset: i64, why: &str, expires: Option<i64>| RiskAcceptance { id: 0, finding_id: "telnet_open".into(), asset_id: asset, reason: why.into(), accepted_by: "admin".into(), accepted_at: 100, expires_at: expires, revoked_at: None, revoked_by: None };
        let first = s.add_risk_acceptance(&acc(a.id, "first", None)).unwrap();
        // deciding again for the same finding and device replaces the earlier decision (only one is in force)
        let second = s.add_risk_acceptance(&acc(a.id, "second", Some(500))).unwrap();
        s.add_risk_acceptance(&acc(b.id, "other device", None)).unwrap();
        let list = s.list_risk_acceptances().unwrap();
        assert_eq!(list.len(), 2, "the replaced one is not listed");
        let mine = list.iter().find(|r| r.asset_id == a.id).unwrap();
        assert_eq!((mine.id, mine.reason.as_str(), mine.expires_at), (second, "second", Some(500)));
        assert!(mine.is_active(499) && !mine.is_active(500), "it ends at its date");
        assert!(!s.revoke_risk_acceptance(first, "x", 200).unwrap(), "the replaced decision cannot be withdrawn again");
        assert!(s.revoke_risk_acceptance(second, "someone", 200).unwrap());
        assert!(!s.revoke_risk_acceptance(second, "someone", 201).unwrap());
        assert_eq!(s.list_risk_acceptances().unwrap().len(), 1);
        // a deleted device takes its decisions with it, and erasing everything removes them too
        s.delete_asset(b.id).unwrap();
        assert!(s.list_risk_acceptances().unwrap().is_empty());
        s.add_risk_acceptance(&acc(a.id, "again", None)).unwrap();
        s.erase_inventory().unwrap();
        assert!(s.list_risk_acceptances().unwrap().is_empty());
    }

    #[test]
    fn reports_are_stored_listed_and_pruned() {
        let s = SqliteStore::open_in_memory().unwrap();
        let meta = |kind: &str, at: i64| ReportMeta { id: 0, kind: kind.into(), title: format!("r{at}"), period_days: 7, created_at: at, created_by: "x".into(), size: 0 };
        let first = s.add_report(&meta("manual", 100), b"<html>one</html>").unwrap();
        for at in [200, 300, 400] {
            s.add_report(&meta("scheduled", at), b"<html>s</html>").unwrap();
        }
        let list = s.list_reports().unwrap();
        assert_eq!(list.len(), 4);
        assert_eq!(list[0].created_at, 400, "newest first");
        assert_eq!(list[3].size, 16);
        let (m, body) = s.get_report(first).unwrap().unwrap();
        assert_eq!((m.kind.as_str(), body.as_slice()), ("manual", &b"<html>one</html>"[..]));
        // only scheduled reports are pruned; a manual one is kept
        assert_eq!(s.prune_reports("scheduled", 1).unwrap(), 2);
        let left: Vec<i64> = s.list_reports().unwrap().iter().map(|r| r.created_at).collect();
        assert_eq!(left, vec![400, 100]);
        assert!(s.delete_report(first).unwrap());
        assert!(!s.delete_report(first).unwrap());
        s.erase_inventory().unwrap();
        assert!(s.list_reports().unwrap().is_empty());
    }

    #[test]
    fn totp_secrets_are_pending_until_confirmed_and_each_step_and_recovery_code_works_once() {
        let s = SqliteStore::open_in_memory().unwrap();
        let u = s.create_user("ana", "x", "viewer", false, 0).unwrap().id;
        assert!(s.get_totp(u).unwrap().is_none());
        assert!(s.set_totp_pending(u, b"first-secret", 10).unwrap());
        assert!(s.set_totp_pending(u, b"second-secret", 11).unwrap(), "starting again replaces a pending secret");
        let t = s.get_totp(u).unwrap().unwrap();
        assert_eq!((t.secret.as_slice(), t.enabled), (&b"second-secret"[..], false));
        assert!(!s.advance_totp_step(u, 5).unwrap(), "a pending secret cannot sign anybody in");
        assert!(s.totp_enabled_users().unwrap().is_empty());
        let codes: Vec<String> = ["a", "b", "c"].iter().map(|c| c.to_string()).collect();
        assert!(s.enable_totp(u, 100, &codes).unwrap());
        assert!(!s.enable_totp(u, 100, &codes).unwrap(), "already on");
        assert!(!s.set_totp_pending(u, b"third", 12).unwrap(), "a working secret is not replaced by starting again");
        assert_eq!(s.get_totp(u).unwrap().unwrap().secret, b"second-secret");
        assert!(s.totp_enabled_users().unwrap().contains(&u));
        // a step works once, and never an older one
        assert!(!s.advance_totp_step(u, 100).unwrap());
        assert!(s.advance_totp_step(u, 101).unwrap());
        assert!(!s.advance_totp_step(u, 101).unwrap());
        assert!(!s.advance_totp_step(u, 99).unwrap());
        // recovery codes
        assert_eq!(s.recovery_codes_left(u).unwrap(), 3);
        assert!(s.use_recovery_code(u, "b", 200).unwrap());
        assert!(!s.use_recovery_code(u, "b", 201).unwrap(), "a code works once");
        assert!(!s.use_recovery_code(u, "nope", 201).unwrap());
        assert!(!s.use_recovery_code(u + 1, "a", 201).unwrap(), "and only for its owner");
        assert_eq!(s.recovery_codes_left(u).unwrap(), 2);
        s.replace_recovery_codes(u, &["x".to_string()]).unwrap();
        assert_eq!(s.recovery_codes_left(u).unwrap(), 1);
        assert!(s.delete_totp(u).unwrap());
        assert!(!s.delete_totp(u).unwrap());
        assert_eq!((s.recovery_codes_left(u).unwrap(), s.get_totp(u).unwrap().is_none()), (0, true));
    }
}
