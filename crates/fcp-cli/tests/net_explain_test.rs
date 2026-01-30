//! Unit tests for `fcp net explain` command.
//!
//! Per bd-30pl: Coverage for allowlist success, deny on private CIDR,
//! deny on IP literal / missing SNI. Emits structured JSONL per
//! `docs/STANDARD_Testing_Logging.md`.

use std::io::Write;

use chrono::Utc;
use fcp_testkit::LogCapture;
use serde_json::json;
use tempfile::NamedTempFile;
use uuid::Uuid;

/// Emit a structured JSONL log entry per the E2E log standard.
fn emit_log(
    capture: &LogCapture,
    test_name: &str,
    phase: &str,
    result: &str,
    context: &serde_json::Value,
) {
    let entry = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "test_name": test_name,
        "module": "fcp-cli/net",
        "phase": phase,
        "correlation_id": format!("net-explain-{}", Uuid::new_v4()),
        "result": result,
        "duration_ms": 0,
        "assertions": {
            "passed": i32::from(result == "pass"),
            "failed": i32::from(result == "fail")
        },
        "context": context
    });
    capture.push_value(&entry).expect("log entry");
}

/// Create a strict manifest (denies private ranges, localhost, IP literals).
/// Interface hash: 8fd505a0c2d49ea76cd3d4a9cd17e5099247280f5c80505c3185c388087b8924
fn create_strict_manifest() -> NamedTempFile {
    let manifest = r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 65000
interface_hash = "blake3-256:fcp.interface.v2:8fd505a0c2d49ea76cd3d4a9cd17e5099247280f5c80505c3185c388087b8924"

[connector]
id = "fcp.test-connector"
name = "Test Connector"
version = "1.0.0"
description = "Test connector for net explain unit tests"
archetypes = ["operational"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"
migration_hint = "none"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.egress"]
optional = []
forbidden = ["system.exec", "network.listen"]

[sandbox]
profile = "strict"
memory_mb = 512
cpu_percent = 50
wall_clock_timeout_ms = 60000
fs_readonly_paths = []
fs_writable_paths = []
deny_exec = true
deny_ptrace = true

[provides.operations.test_op]
description = "Test operation"
capability = "test.invoke"
risk_level = "low"
safety_tier = "safe"
idempotency = "best_effort"
requires_approval = "none"

[provides.operations.test_op.rate_limit]
max = 100
per_ms = 60000

[provides.operations.test_op.input_schema]
required = []
type = "object"

[provides.operations.test_op.output_schema]
required = []
type = "object"

[provides.operations.test_op.network_constraints]
host_allow = ["api.example.com"]
port_allow = [443]
ip_allow = []
cidr_deny = []
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = false
require_sni = false
spki_pins = []
deny_ip_literals = true
require_host_canonicalization = false
dns_max_ips = 16
max_redirects = 5
connect_timeout_ms = 10000
total_timeout_ms = 60000
max_response_bytes = 10485760
"#;
    let mut file = NamedTempFile::new().expect("create temp file");
    file.write_all(manifest.as_bytes()).expect("write manifest");
    file.flush().expect("flush manifest");
    file
}

/// Helper to get the fcp command.
fn fcp_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_fcp"));
    cmd.env("RUST_LOG", "error");
    cmd
}

// =============================================================================
// Tests using STRICT manifest (denies private ranges, localhost, IP literals)
// =============================================================================

#[test]
fn allowlist_success_allows_permitted_host() {
    let capture = LogCapture::new();

    let manifest = create_strict_manifest();

    let output = fcp_cmd()
        .args(["net", "explain"])
        .args(["--url", "https://api.example.com/v1/test"])
        .args(["--manifest-path", manifest.path().to_str().unwrap()])
        .args(["--json"])
        .output()
        .expect("run command");

    let result = if output.status.success() {
        "pass"
    } else {
        "fail"
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    emit_log(
        &capture,
        "allowlist_success_allows_permitted_host",
        "execute",
        result,
        &json!({
            "url": "https://api.example.com/v1/test",
            "exit_code": output.status.code(),
            "stdout_len": stdout.len()
        }),
    );

    capture.assert_valid();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected success for allowed host.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse JSON output");
    assert_eq!(report["allowed"], true);
    assert_eq!(report["canonical_host"], "api.example.com");
    assert_eq!(report["port"], 443);
}

#[test]
fn allowlist_denies_unlisted_host() {
    let capture = LogCapture::new();

    let manifest = create_strict_manifest();

    let output = fcp_cmd()
        .args(["net", "explain"])
        .args(["--url", "https://malicious.example.com/hack"])
        .args(["--manifest-path", manifest.path().to_str().unwrap()])
        .args(["--json"])
        .output()
        .expect("run command");

    // Exit code 1 expected for denied requests
    let result = if output.status.success() {
        "fail"
    } else {
        "pass"
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    emit_log(
        &capture,
        "allowlist_denies_unlisted_host",
        "execute",
        result,
        &json!({
            "url": "https://malicious.example.com/hack",
            "exit_code": output.status.code()
        }),
    );

    capture.assert_valid();

    assert!(
        !output.status.success(),
        "expected failure for unlisted host"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse JSON output");
    assert_eq!(report["allowed"], false);
    assert_eq!(report["reason_code"], "host_not_allowed");
    assert!(
        report["suggestion"]["field"]
            .as_str()
            .is_some_and(|f| f.contains("host_allow"))
    );
}

#[test]
fn deny_localhost_blocks_loopback() {
    let capture = LogCapture::new();

    // Strict manifest has deny_localhost = true
    let manifest = create_strict_manifest();

    let output = fcp_cmd()
        .args(["net", "explain"])
        // Use api.example.com which is in host_allow, but localhost should still be denied
        .args(["--url", "http://localhost:443/api"])
        .args(["--manifest-path", manifest.path().to_str().unwrap()])
        .args(["--json"])
        .output()
        .expect("run command");

    let result = if output.status.success() {
        "fail"
    } else {
        "pass"
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    emit_log(
        &capture,
        "deny_localhost_blocks_loopback",
        "execute",
        result,
        &json!({
            "url": "http://localhost:443/api",
            "exit_code": output.status.code()
        }),
    );

    capture.assert_valid();

    assert!(
        !output.status.success(),
        "expected failure for localhost.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse JSON output");
    assert_eq!(report["allowed"], false);
}

#[test]
fn deny_ip_literal_blocks_direct_ip() {
    let capture = LogCapture::new();

    // Strict manifest has deny_ip_literals = true
    let manifest = create_strict_manifest();

    // Direct public IP literal should be blocked
    let output = fcp_cmd()
        .args(["net", "explain"])
        .args(["--url", "https://203.0.113.42:443/api"])
        .args(["--manifest-path", manifest.path().to_str().unwrap()])
        .args(["--json"])
        .output()
        .expect("run command");

    let result = if output.status.success() {
        "fail"
    } else {
        "pass"
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    emit_log(
        &capture,
        "deny_ip_literal_blocks_direct_ip",
        "execute",
        result,
        &json!({
            "url": "https://203.0.113.42:443/api",
            "exit_code": output.status.code()
        }),
    );

    capture.assert_valid();

    assert!(
        !output.status.success(),
        "expected failure for IP literal.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse JSON output");
    assert_eq!(report["allowed"], false);
    let reason = report["reason_code"].as_str().unwrap_or("");
    assert!(
        reason.contains("ip") || reason.contains("literal"),
        "expected IP literal denial, got: {reason}"
    );
}

#[test]
fn deny_private_cidr_blocks_rfc1918() {
    let capture = LogCapture::new();

    // Strict manifest has deny_private_ranges = true
    let manifest = create_strict_manifest();

    // RFC1918 private range: 192.168.x.x
    // Note: This also gets blocked by deny_ip_literals first
    let output = fcp_cmd()
        .args(["net", "explain"])
        .args(["--url", "http://192.168.1.1:443/api"])
        .args(["--manifest-path", manifest.path().to_str().unwrap()])
        .args(["--json"])
        .output()
        .expect("run command");

    let result = if output.status.success() {
        "fail"
    } else {
        "pass"
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    emit_log(
        &capture,
        "deny_private_cidr_blocks_rfc1918",
        "execute",
        result,
        &json!({
            "url": "http://192.168.1.1:443/api",
            "exit_code": output.status.code(),
            "private_range": "192.168.0.0/16"
        }),
    );

    capture.assert_valid();

    assert!(
        !output.status.success(),
        "expected failure for private IP range.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse JSON output");
    assert_eq!(report["allowed"], false);
    // Could be denied by ip_literal or private_range check
    let reason = report["reason_code"].as_str().unwrap_or("");
    assert!(
        reason.contains("private")
            || reason.contains("range")
            || reason.contains("ip")
            || reason.contains("literal"),
        "expected private range or IP literal denial, got: {reason}"
    );
}

#[test]
fn deny_private_cidr_blocks_10_network() {
    let capture = LogCapture::new();

    // Strict manifest has deny_private_ranges = true
    let manifest = create_strict_manifest();

    // RFC1918 private range: 10.x.x.x
    let output = fcp_cmd()
        .args(["net", "explain"])
        .args(["--url", "http://10.0.0.1:443/internal"])
        .args(["--manifest-path", manifest.path().to_str().unwrap()])
        .args(["--json"])
        .output()
        .expect("run command");

    let result = if output.status.success() {
        "fail"
    } else {
        "pass"
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    emit_log(
        &capture,
        "deny_private_cidr_blocks_10_network",
        "execute",
        result,
        &json!({
            "url": "http://10.0.0.1:443/internal",
            "exit_code": output.status.code(),
            "private_range": "10.0.0.0/8"
        }),
    );

    capture.assert_valid();

    assert!(
        !output.status.success(),
        "expected failure for 10.x.x.x private range.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse JSON output");
    assert_eq!(report["allowed"], false);
}

#[test]
fn json_output_contains_suggestion() {
    let capture = LogCapture::new();

    let manifest = create_strict_manifest();

    let output = fcp_cmd()
        .args(["net", "explain"])
        .args(["--url", "https://other.example.com/api"])
        .args(["--manifest-path", manifest.path().to_str().unwrap()])
        .args(["--json"])
        .output()
        .expect("run command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse JSON output");

    let has_suggestion = report.get("suggestion").is_some();
    let result = if has_suggestion && !output.status.success() {
        "pass"
    } else {
        "fail"
    };

    emit_log(
        &capture,
        "json_output_contains_suggestion",
        "execute",
        result,
        &json!({
            "has_suggestion": has_suggestion,
            "suggestion": report.get("suggestion")
        }),
    );

    capture.assert_valid();

    assert!(has_suggestion, "expected suggestion in denial output");
    let suggestion = &report["suggestion"];
    assert!(suggestion["field"].as_str().is_some());
    assert!(suggestion["action"].as_str().is_some());
    assert!(suggestion["value"].as_str().is_some());
}

#[test]
fn port_not_allowed_denied() {
    let capture = LogCapture::new();

    let manifest = create_strict_manifest();

    // Port 8080 not in allowlist (only 443 allowed)
    let output = fcp_cmd()
        .args(["net", "explain"])
        .args(["--url", "https://api.example.com:8080/api"])
        .args(["--manifest-path", manifest.path().to_str().unwrap()])
        .args(["--json"])
        .output()
        .expect("run command");

    let result = if output.status.success() {
        "fail"
    } else {
        "pass"
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    emit_log(
        &capture,
        "port_not_allowed_denied",
        "execute",
        result,
        &json!({
            "url": "https://api.example.com:8080/api",
            "exit_code": output.status.code()
        }),
    );

    capture.assert_valid();

    assert!(
        !output.status.success(),
        "expected failure for unlisted port"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse JSON output");
    assert_eq!(report["allowed"], false);
    let reason = report["reason_code"].as_str().unwrap_or("");
    assert!(
        reason.contains("port"),
        "expected port denial, got: {reason}"
    );
}
