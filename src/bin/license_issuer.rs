//! `license-issuer`: a standalone tool for issuing DENIS Community/commercial licenses.
//!
//! Deliberately a **separate program** from `denis` itself: it is vendor-only tooling (you sign
//! licenses with it; customers never run it), so it has no business shipping inside the binary
//! that every customer downloads. It keeps its own small SQLite database — a register of every
//! license ever issued (customer, tier, device cap, validity, the signed text itself) — so a lost
//! license file can always be recovered with `license-issuer show <id>`.
//!
//! The actual signing key is never stored in this database: it is read from an environment
//! variable at the moment of issuing, exactly as `denis license-issue` used to work, and is not
//! written anywhere by this program either.
//!
//! ```text
//! license-issuer keygen
//! DENIS_LICENSE_KEY=… license-issuer issue "Acme s.r.o." --tier business --device-cap 500 --days 365
//! license-issuer list
//! license-issuer show 3
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rusqlite::Connection;

#[derive(Parser)]
#[command(version, about = "Issue and keep a register of DENIS licenses (vendor-only; never distributed to customers)")]
struct Cli {
    /// The register of every license ever issued.
    #[arg(long, global = true, default_value = "license-issuer.db")]
    db: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a new signing key pair. The private key must be kept secret (never committed, never
    /// stored in the database); the public key goes into `denis`'s src/license_key.rs.
    Keygen,
    /// Issue a signed license, record it in the database, and write the license file.
    Issue {
        /// Who the license is for (shown in the console).
        customer: String,
        #[arg(long, default_value = "business")]
        tier: String,
        /// Devices allowed; omit for unlimited.
        #[arg(long)]
        device_cap: Option<u32>,
        /// Validity in days, counted from the moment it first verifies on an install (not from
        /// today) — see LICENSE-COMMERCIAL.md. Mutually exclusive with --years.
        #[arg(long)]
        days: Option<u32>,
        /// Validity in whole years (365 days each); an alternative to --days.
        #[arg(long)]
        years: Option<u32>,
        /// Environment variable holding the private signing key (never printed, never stored).
        #[arg(long, default_value = "DENIS_LICENSE_KEY")]
        key_env: String,
        /// Where to write the license file; defaults to `<customer-slug>.key`.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List every license issued so far.
    List,
    /// Print a previously issued license's file contents again (id from `list`).
    Show {
        id: i64,
    },
}

fn open_db(path: &PathBuf) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY,
            customer TEXT NOT NULL,
            tier TEXT NOT NULL,
            device_cap INTEGER,
            valid_days INTEGER NOT NULL,
            issued_date TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            license_text TEXT NOT NULL
        )",
    )?;
    Ok(conn)
}

fn slug(s: &str) -> String {
    let s: String = s.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let s = s.trim_matches('-');
    let mut out = String::new();
    for part in s.split('-').filter(|p| !p.is_empty()) {
        if !out.is_empty() {
            out.push('-');
        }
        out.push_str(part);
    }
    if out.is_empty() {
        "customer".into()
    } else {
        out
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => {
            let (private, public) = denis::update::generate_keypair()?;
            println!("private key (keep SECRET, e.g. as an env var named DENIS_LICENSE_KEY — never commit it, never store it in the database):\n  {private}\n");
            let bytes: Vec<String> = (0..32).map(|i| format!("0x{}", &public[i * 2..i * 2 + 2])).collect();
            println!("public key (paste into denis's src/license_key.rs):\n  pub const LICENSE_PUBLIC_KEY: Option<[u8; 32]> = Some([{}]);", bytes.join(", "));
            Ok(())
        }
        Cmd::Issue { customer, tier, device_cap, days, years, key_env, out } => {
            let valid_days = match (days, years) {
                (Some(_), Some(_)) => anyhow::bail!("pass --days or --years, not both"),
                (Some(d), None) => d,
                (None, Some(y)) => y.saturating_mul(365),
                (None, None) => 365,
            };
            let key = std::env::var(&key_env).map_err(|_| anyhow::anyhow!("set the private key in the environment variable {key_env}"))?;
            let today = denis::model::now_ts().div_euclid(86_400);
            let license = denis::license::License {
                customer: customer.clone(),
                tier: tier.clone(),
                device_cap,
                commercial: true,
                issued: denis::tracking::date_from_days(today),
                valid_days,
            };
            let text = denis::license::issue(key.trim(), &license)?;
            let out = out.unwrap_or_else(|| PathBuf::from(format!("{}.key", slug(&customer))));
            std::fs::write(&out, &text)?;

            let conn = open_db(&cli.db)?;
            conn.execute(
                "INSERT INTO licenses (customer, tier, device_cap, valid_days, issued_date, created_at, license_text) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![customer, tier, device_cap, valid_days, license.issued, denis::model::now_ts(), text],
            )?;
            let id = conn.last_insert_rowid();

            println!(
                "license #{id} written to {} (customer: {}, tier: {}, cap: {}, valid {} days from first use)",
                out.display(),
                license.customer,
                license.tier,
                license.device_cap.map(|c| c.to_string()).unwrap_or_else(|| "unlimited".into()),
                license.valid_days
            );
            Ok(())
        }
        Cmd::List => {
            let conn = open_db(&cli.db)?;
            let mut stmt = conn.prepare("SELECT id, customer, tier, device_cap, valid_days, issued_date FROM licenses ORDER BY id")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<u32>>(3)?, r.get::<_, u32>(4)?, r.get::<_, String>(5)?))
            })?;
            println!("{:<5} {:<28} {:<12} {:<8} {:<10} issued", "id", "customer", "tier", "cap", "days");
            for row in rows {
                let (id, customer, tier, cap, days, issued) = row?;
                println!("{:<5} {:<28} {:<12} {:<8} {:<10} {}", id, customer, tier, cap.map(|c| c.to_string()).unwrap_or_else(|| "unlimited".into()), days, issued);
            }
            Ok(())
        }
        Cmd::Show { id } => {
            let conn = open_db(&cli.db)?;
            let text: String = conn
                .query_row("SELECT license_text FROM licenses WHERE id = ?1", [id], |r| r.get(0))
                .map_err(|_| anyhow::anyhow!("no license #{id} in {}", cli.db.display()))?;
            print!("{text}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugging_a_customer_name_gives_a_safe_filename_stem() {
        assert_eq!(slug("Acme s.r.o."), "acme-s-r-o");
        assert_eq!(slug("  Ünïcode & Co.  "), "n-code-co");
        assert_eq!(slug(""), "customer");
    }

    #[test]
    fn a_fresh_database_can_record_and_recall_a_license() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("license-issuer.db");
        let conn = open_db(&path).unwrap();
        conn.execute(
            "INSERT INTO licenses (customer, tier, device_cap, valid_days, issued_date, created_at, license_text) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params!["Acme", "business", Some(250u32), 365u32, "2026-01-01", 0i64, "payload\nsig\n"],
        )
        .unwrap();
        let text: String = conn.query_row("SELECT license_text FROM licenses WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(text, "payload\nsig\n");
        // reopening (as a later `list`/`show` invocation would) sees the same row
        let conn2 = open_db(&path).unwrap();
        let customer: String = conn2.query_row("SELECT customer FROM licenses WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(customer, "Acme");
    }
}
