//! Integration tests for `fcp manifest fix` command.

use assert_cmd::Command;
use tempfile::TempDir;

/// Get the `fcp` command for testing.
fn fcp_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fcp"));
    // Suppress tracing output during tests
    cmd.env("RUST_LOG", "error");
    cmd
}

fn placeholder_hash() -> String {
    format!("blake3-256:fcp.interface.v2:{}", "0".repeat(64))
}

fn manifest_template(interface_hash: &str) -> String {
    format!(
        r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{interface_hash}"

[connector]
id = "fcp.manifestfix"
name = "Manifest Fix Test"
version = "0.1.0"
description = "Test connector"
archetypes = ["operational"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
home = "z:project:test"
allowed_sources = ["z:project:test"]
allowed_targets = ["z:project:test"]
forbidden = []

[capabilities]
required = []
forbidden = ["system.exec"]
optional = []

[provides.operations.sample]
description = "Sample op"
capability = "fcp.manifestfix.sample"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "best_effort"
input_schema = {{ type = "object", properties = {{ }} }}
output_schema = {{ type = "object", properties = {{ }} }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 25
wall_clock_timeout_ms = 30000
fs_readonly_paths = []
fs_writable_paths = []
deny_exec = true
deny_ptrace = true
"#
    )
}

#[test]
fn manifest_fix_check_reports_changes() {
    let tmp = TempDir::new().unwrap();
    let manifest_path = tmp.path().join("manifest.toml");
    let placeholder = placeholder_hash();
    std::fs::write(&manifest_path, manifest_template(&placeholder)).unwrap();

    let output = fcp_cmd()
        .args([
            "manifest",
            "fix",
            manifest_path.to_str().unwrap(),
            "--check",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["mode"], "check");
    assert_eq!(json["changed"], true);
    assert_eq!(json["wrote"], false);
    assert_eq!(json["interface_hash_before"], placeholder);
    assert_ne!(json["interface_hash_after"], placeholder);
}

#[test]
fn manifest_fix_write_updates_hash() {
    let tmp = TempDir::new().unwrap();
    let manifest_path = tmp.path().join("manifest.toml");
    let placeholder = placeholder_hash();
    std::fs::write(&manifest_path, manifest_template(&placeholder)).unwrap();

    let output = fcp_cmd()
        .args([
            "manifest",
            "fix",
            manifest_path.to_str().unwrap(),
            "--write",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["mode"], "write");
    assert_eq!(json["changed"], true);
    assert_eq!(json["wrote"], true);

    let updated = std::fs::read_to_string(&manifest_path).unwrap();
    fcp_manifest::ConnectorManifest::parse_str(&updated)
        .expect("manifest should validate after fix");
}
