//! denis: passive + active network asset discovery and fingerprinting.
//!
//! One core library; the binary in `main.rs` is the Phase 1 single-process
//! deployment (agent loop + web UI). A Phase 2 remote agent reuses everything
//! except `web`.

pub mod active;
pub mod agent;
pub mod auth;
pub mod branding;
pub mod capture;
pub mod certs;
pub mod channels;
pub mod compliance;
pub mod demo;
pub mod detect;
pub mod docs;
pub mod engine;
pub mod findings;
pub mod fingerprint;
pub mod flow;
pub mod ingest;
#[cfg(test)]
mod i18n;
#[cfg(test)]
mod packaging;
pub mod inventory;
pub mod metrics;
pub mod model;
pub mod net;
pub mod notify;
pub mod ot;
pub mod parse;
pub mod passkey;
pub mod report;
pub mod reports;
pub mod risk;
pub mod rules;
pub mod sink;
pub mod store;
pub mod threat;
pub mod syslog;
pub mod tls;
pub mod update;
pub mod update_key;
pub mod tracking;
pub mod trends;
pub mod web;
pub mod web_admin;
pub mod web_passkey;
pub mod web_reports;
