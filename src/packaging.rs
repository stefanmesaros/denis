//! The installer (`packaging/install.sh`) must agree with the rest of the project: the service it writes is
//! the shipped unit, the key it verifies with is the one built into the program, and the release attaches it.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn the_service_the_installer_writes_is_the_shipped_unit() {
    let script = read("packaging/install.sh");
    let begin = script.find("<<'UNIT_EOF'\n").expect("unit start") + "<<'UNIT_EOF'\n".len();
    let end = script.find("\nUNIT_EOF\n").expect("unit end");
    let embedded = &script[begin..end];
    let unit = read("packaging/denis.service");
    let shipped = &unit[unit.find("[Unit]").expect("[Unit]")..];
    assert_eq!(embedded.trim_end(), shipped.trim_end(), "packaging/install.sh and packaging/denis.service have drifted apart");
}

#[test]
fn the_installer_verifies_with_the_key_built_into_the_program() {
    let script = read("packaging/install.sh");
    let hex: String = crate::update_key::RELEASE_PUBLIC_KEY.expect("a release key is set").iter().map(|b| format!("{b:02x}")).collect();
    assert!(script.contains(&format!("RELEASE_PUBLIC_KEY_HEX=\"{hex}\"")), "the installer's release key differs from src/update_key.rs");
}

#[test]
fn the_installer_supports_this_version_and_is_attached_to_releases() {
    let script = read("packaging/install.sh");
    let min = script.lines().find_map(|l| l.strip_prefix("MIN_VERSION=\"")).and_then(|l| l.split('"').next()).expect("MIN_VERSION");
    // "0.2.0-rc.1" counts as 0.2.0 here: only the numbers matter
    let ver = |s: &str| s.split('-').next().unwrap().split('.').map(|p| p.parse::<u32>().unwrap()).collect::<Vec<_>>();
    assert!(ver(min) <= ver(env!("CARGO_PKG_VERSION")), "MIN_VERSION {min} is newer than this version");
    assert!(read(".github/workflows/release.yml").contains("install.sh"), "the release workflow must attach the installer");
    assert!(script.starts_with("#!/usr/bin/env bash\n") && script.contains("set -euo pipefail"));
    // it never edits a running system without being asked for root, and a dry run needs none
    assert!(script.contains("--dry-run") && script.contains("run it with sudo"));
}
