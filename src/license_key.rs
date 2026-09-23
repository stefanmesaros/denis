//! The public key a commercial license file's signature must verify against.
//!
//! Generated with `license-issuer keygen` (a separate, vendor-only tool: see src/bin/license_issuer.rs).
//! The matching private key is kept secret by whoever issues licenses (never in this repository).
//! A build without a
//! key (`None`) can only ever run the Community edition: no license file can raise its cap.

pub const LICENSE_PUBLIC_KEY: Option<[u8; 32]> = Some([0xf1, 0x36, 0xc7, 0x02, 0xaa, 0x9c, 0xb2, 0xf9, 0x65, 0x9f, 0x29, 0x45, 0x05, 0x61, 0x79, 0x8e, 0x1a, 0xe1, 0xde, 0x3a, 0xaf, 0x99, 0xa8, 0x70, 0xce, 0x7e, 0x8b, 0x0e, 0x7a, 0x9a, 0x7a, 0xb6]);
