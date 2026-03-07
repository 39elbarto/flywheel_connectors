//! Integration tests for `fcp package` metadata output (bd-232x).
//!
//! Validates:
//! - Manifest round-trip
//! - Build metadata fields
//! - SBOM schema basics
//! - Structured JSONL logging

use assert_cmd::cargo::cargo_bin_cmd;
use chrono::Utc;
use fcp_testkit::LogCapture;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

#[test]
#[allow(clippy::too_many_lines)]
fn package_metadata_roundtrip_and_sbom() {
    let capture = LogCapture::new();
    let correlation_id = format!("pkg-{}", std::process::id());

    let temp = TempDir::new().expect("tempdir");
    let crate_path = temp.path();
    fs::create_dir_all(crate_path.join("src")).expect("create src");

    let cargo_toml = r#"[package]
name = "fcp_test_connector"
version = "0.1.0"
edition = "2024"
"#;
    fs::write(crate_path.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");
    fs::write(crate_path.join("src/main.rs"), "fn main() {}\n").expect("write main.rs");

    let manifest = r#"[connector]
id = "fcp.test:example:v1"
version = "0.1.0"
"#;
    fs::write(crate_path.join("manifest.toml"), manifest).expect("write manifest");

    let output_dir = crate_path.join("out");
    let mut cmd = cargo_bin_cmd!("fcp");
    let output = cmd
        .args([
            "package",
            "--path",
            crate_path.to_str().expect("path"),
            "--format",
            "json",
            "--output",
            output_dir.to_str().expect("output"),
        ])
        .output()
        .expect("run fcp package");

    assert!(output.status.success(), "fcp package should succeed");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let payload: Value = serde_json::from_str(&stdout).expect("parse package output");

    let binary_sha256 = payload
        .get("binary_sha256")
        .and_then(|v| v.as_str())
        .expect("binary_sha256");
    assert_eq!(binary_sha256.len(), 64, "sha256 hex length");

    let manifest_path = payload
        .get("manifest_path")
        .and_then(|v| v.as_str())
        .expect("manifest_path");
    let manifest_written = fs::read_to_string(manifest_path).expect("read manifest");
    assert_eq!(manifest_written, manifest, "manifest round-trip");

    let metadata_path = payload
        .get("build_metadata_path")
        .and_then(|v| v.as_str())
        .expect("build_metadata_path");
    let metadata: Value =
        serde_json::from_str(&fs::read_to_string(metadata_path).expect("read build metadata"))
            .expect("parse build metadata");
    assert!(
        metadata
            .get("cargo_version")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "cargo_version present"
    );
    assert!(
        metadata
            .get("rust_version")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "rust_version present"
    );
    assert_eq!(
        metadata.get("profile").and_then(|v| v.as_str()),
        Some("release"),
        "default profile should be release"
    );

    let sbom_path = payload
        .get("sbom_path")
        .and_then(|v| v.as_str())
        .expect("sbom_path");
    let sbom: Value = serde_json::from_str(&fs::read_to_string(sbom_path).expect("read sbom"))
        .expect("parse sbom");
    assert_eq!(
        sbom.get("format_version").and_then(|v| v.as_str()),
        Some("1.0")
    );
    assert!(sbom.get("component").is_some(), "sbom has component");

    let log = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "level": "info",
        "test_name": "package_metadata_roundtrip_and_sbom",
        "module": "fcp-cli::package",
        "phase": "verify",
        "correlation_id": correlation_id,
        "result": "pass",
        "duration_ms": 0,
        "assertions": { "passed": 5, "failed": 0 },
        "details": {
            "package_hash": binary_sha256,
            "schema_version": "1.0"
        }
    });

    capture.push_line(&log.to_string());
    capture.validate_jsonl().expect("e2e log jsonl schema");
}
