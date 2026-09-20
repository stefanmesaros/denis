//! netscope: passive + active network asset discovery and fingerprinting.
//!
//! One core library; the binary in `main.rs` is the Phase 1 single-process
//! deployment (agent loop + web UI). A Phase 2 remote agent reuses everything
//! except `web`.

pub mod active;
pub mod agent;
pub mod capture;
pub mod detect;
pub mod engine;
pub mod fingerprint;
pub mod flow;
pub mod ingest;
pub mod inventory;
pub mod model;
pub mod net;
pub mod notify;
pub mod parse;
pub mod store;
pub mod web;
