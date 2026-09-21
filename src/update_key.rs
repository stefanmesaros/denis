//! The public key that release files must be signed with.
//!
//! Generated with `denis release-keygen`. The matching private key is kept secret (it belongs in the
//! release pipeline's secrets, never in the repository). A build without a key (`None`) cannot install
//! updates; it can still tell you a newer version exists.

pub const RELEASE_PUBLIC_KEY: Option<[u8; 32]> = Some([0xab, 0xe7, 0x54, 0x62, 0xc8, 0xad, 0xfb, 0x1d, 0x4c, 0x5a, 0xa3, 0x9d, 0x25, 0xe4, 0x43, 0x77, 0xd0, 0x0c, 0x77, 0x44, 0x2f, 0x42, 0x3c, 0x2f, 0x01, 0xcd, 0x51, 0xfe, 0xc4, 0x0e, 0x93, 0x8e]);

/// `owner/repo` on GitHub whose releases are the update channel. Empty = updates are off.
pub const UPDATE_REPO: &str = "stefanmesaros/denis";
