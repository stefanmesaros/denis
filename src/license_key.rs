//! The public key a commercial license file's signature must verify against.
//!
//! Generated with `denis license-keygen`. The matching private key is kept secret by whoever
//! issues licenses (never in this repository — see `denis license-issue`). A build without a
//! key (`None`) can only ever run the Community edition: no license file can raise its cap.

pub const LICENSE_PUBLIC_KEY: Option<[u8; 32]> = None;
