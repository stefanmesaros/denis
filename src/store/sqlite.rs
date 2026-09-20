use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};

use super::{EventQuery, Store};
use crate::model::{AgentInfo, Asset, Baseline, Event, Fingerprint, Mac};

const SCHEMA_VERSION: i64 = 2;

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

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        // WAL lets `netscope list` read while the daemon writes.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            anyhow::bail!("database schema v{version} is newer than this build (v{SCHEMA_VERSION})");
        }
        // Each step runs in its own transaction and bumps user_version, so a
        // crash mid-migration leaves the database at a consistent older version.
        for (target, sql) in [(1, V1), (2, V2)] {
            if version < target {
                let tx = conn.unchecked_transaction()?;
                tx.execute_batch(sql)?;
                tx.pragma_update(None, "user_version", target)?;
                tx.commit()?;
            }
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

impl Store for SqliteStore {
    fn load_assets(&self) -> Result<Vec<Asset>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&format!("SELECT {ASSET_COLS} FROM assets ORDER BY id"))?;
        let rows = stmt.query_map([], row_to_asset)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn save_asset(&self, a: &mut Asset) -> Result<()> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                &format!("SELECT {ASSET_COLS} FROM assets WHERE id = ?1"),
                [id],
                row_to_asset,
            )
            .optional()?)
    }

    fn find_asset(&self, agent_id: Option<&str>, mac: &Mac) -> Result<Option<Asset>> {
        let conn = self.conn.lock().unwrap();
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

    fn insert_event(&self, e: &mut Event) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events (agent_id, asset_id, type, timestamp, severity, score, acked, raw_details)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![e.agent_id, e.asset_id, e.kind, e.timestamp, e.severity, e.score, e.acked, json(&e.raw_details)],
        )?;
        e.id = conn.last_insert_rowid();
        Ok(())
    }

    fn list_events(&self, q: &EventQuery) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
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

    fn set_event_acked(&self, id: i64, acked: bool) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("UPDATE events SET acked = ?2 WHERE id = ?1", params![id, acked])? == 1)
    }

    fn load_baselines(&self) -> Result<Vec<Baseline>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT data FROM baselines")?;
        let rows = stmt.query_map([], |r| from_json::<Baseline>(r, 0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn get_baseline(&self, asset_id: i64) -> Result<Option<Baseline>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row("SELECT data FROM baselines WHERE asset_id = ?1", [asset_id], |r| from_json(r, 0))
            .optional()?)
    }

    fn save_baseline(&self, b: &Baseline) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO baselines (asset_id, data, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(asset_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
            params![b.asset_id, json(b), b.updated_at],
        )?;
        Ok(())
    }

    fn upsert_agent(&self, a: &AgentInfo) -> Result<()> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(&format!("SELECT {AGENT_COLS} FROM agents WHERE id = ?1"), [id], row_to_agent)
            .optional()?)
    }

    fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&format!("SELECT {AGENT_COLS} FROM agents ORDER BY name"))?;
        let rows = stmt.query_map([], row_to_agent)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
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
    fn unique_mac_per_agent_even_with_null_agent() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = sample();
        s.save_asset(&mut a).unwrap();
        let mut dup = sample();
        assert!(s.save_asset(&mut dup).is_err());
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
}
