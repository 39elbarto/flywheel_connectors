//! E2E scenarios for `fcp net explain` egress policy evaluation.
//!
//! Per bd-2szl: Use harness to evaluate a set of URLs and compare expected decisions.
//! Persists JSONL artifacts and validates with `fcp_conformance` schema.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use chrono::Utc;
use fcp_conformance::schemas::validate_e2e_log_jsonl;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tempfile::NamedTempFile;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const MODULE: &str = "fcp-cli/net-explain-e2e";
const LOG_VERSION: &str = "v1";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Expected decision for a URL.
#[derive(Debug, Clone)]
struct UrlScenario {
    /// The URL to test.
    url: &'static str,
    /// Expected allowed status.
    expect_allowed: bool,
    /// Expected reason code (None means no specific check).
    expect_reason: Option<&'static str>,
    /// Human-readable description.
    description: &'static str,
}

/// Result from CLI invocation.
#[derive(Debug, Serialize, Deserialize)]
struct CliResult {
    allowed: bool,
    reason_code: Option<String>,
    canonical_host: Option<String>,
    port: Option<u16>,
}

/// Assertions summary for log entries.
#[derive(Debug, Clone, Copy, Serialize)]
#[allow(dead_code)]
struct AssertionsSummary {
    passed: u32,
    failed: u32,
}

/// E2E test harness for egress explain scenarios.
struct EgressExplainHarness {
    manifest_path: PathBuf,
    log_entries: Vec<serde_json::Value>,
    test_name: String,
    correlation_id: String,
    start_time: Instant,
    passed: u32,
    failed: u32,
}

impl EgressExplainHarness {
    fn new(test_name: &str, manifest_path: PathBuf) -> Self {
        Self {
            manifest_path,
            log_entries: Vec::new(),
            test_name: test_name.to_string(),
            correlation_id: format!("egress-e2e-{}", Uuid::new_v4()),
            start_time: Instant::now(),
            passed: 0,
            failed: 0,
        }
    }

    fn emit_log(&mut self, phase: &str, result: &str, context: &serde_json::Value) {
        let duration_ms = u64::try_from(self.start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "log_version": LOG_VERSION,
            "level": if result == "fail" { "error" } else { "info" },
            "test_name": self.test_name,
            "module": MODULE,
            "phase": phase,
            "correlation_id": self.correlation_id,
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.passed,
                "failed": self.failed
            },
            "context": context
        });
        self.log_entries.push(entry);
    }

    fn run_scenario(&mut self, scenario: &UrlScenario) -> bool {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_fcp"))
            .args([
                "net",
                "explain",
                "--url",
                scenario.url,
                "--manifest-path",
                self.manifest_path.to_str().unwrap(),
                "--json",
            ])
            .env("RUST_LOG", "error")
            .output()
            .expect("run command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let cli_result: Option<CliResult> = serde_json::from_str(&stdout).ok();

        let actual_allowed = cli_result.as_ref().is_some_and(|r| r.allowed);
        let actual_reason = cli_result.as_ref().and_then(|r| r.reason_code.clone());

        let allowed_match = actual_allowed == scenario.expect_allowed;
        let reason_match = scenario
            .expect_reason
            .is_none_or(|expected| actual_reason.as_ref().is_some_and(|r| r.contains(expected)));

        let success = allowed_match && reason_match;
        if success {
            self.passed += 1;
        } else {
            self.failed += 1;
        }

        self.emit_log(
            "execute",
            if success { "pass" } else { "fail" },
            &json!({
                "url": scenario.url,
                "description": scenario.description,
                "expected": {
                    "allowed": scenario.expect_allowed,
                    "reason": scenario.expect_reason
                },
                "actual": {
                    "allowed": actual_allowed,
                    "reason": actual_reason,
                    "host": cli_result.as_ref().and_then(|r| r.canonical_host.clone()),
                    "port": cli_result.as_ref().and_then(|r| r.port)
                },
                "exit_code": output.status.code()
            }),
        );

        success
    }

    fn finalize(&mut self, output_path: &PathBuf) {
        let all_passed = self.failed == 0;
        self.emit_log(
            "verify",
            if all_passed { "pass" } else { "fail" },
            &json!({
                "total_scenarios": self.passed + self.failed,
                "passed": self.passed,
                "failed": self.failed
            }),
        );

        // Write JSONL to file
        let mut file = File::create(output_path).expect("create log file");
        for entry in &self.log_entries {
            let line = serde_json::to_string(entry).expect("serialize entry");
            writeln!(file, "{line}").expect("write line");
        }
    }

    fn to_jsonl(&self) -> String {
        self.log_entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest Helper
// ─────────────────────────────────────────────────────────────────────────────

/// Create the strict manifest used for all E2E scenarios.
/// Interface hash: 8fd505a0c2d49ea76cd3d4a9cd17e5099247280f5c80505c3185c388087b8924
fn create_strict_manifest() -> NamedTempFile {
    let manifest = r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 65000
interface_hash = "blake3-256:fcp.interface.v2:53e4687e7ba77d263570e45dd1b5801881ed2dd1aa02095a2d16bc783379c566"

[connector]
id = "fcp.test-connector"
name = "Test Connector"
version = "1.0.0"
description = "Test connector for net explain E2E scenarios"
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
host_allow = ["api.example.com", "cdn.example.com"]
port_allow = [443, 8443]
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

// ─────────────────────────────────────────────────────────────────────────────
// E2E Scenario Suite
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_egress_explain_scenarios() {
    // Define the scenario matrix
    let scenarios = vec![
        // Allowed hosts
        UrlScenario {
            url: "https://api.example.com/v1/users",
            expect_allowed: true,
            expect_reason: None,
            description: "Primary API host on HTTPS",
        },
        UrlScenario {
            url: "https://cdn.example.com/assets/logo.png",
            expect_allowed: true,
            expect_reason: None,
            description: "CDN host on HTTPS",
        },
        UrlScenario {
            url: "https://api.example.com:8443/internal",
            expect_allowed: true,
            expect_reason: None,
            description: "API host on alternate port 8443",
        },
        // Denied hosts
        UrlScenario {
            url: "https://malicious.example.com/steal",
            expect_allowed: false,
            expect_reason: Some("host"),
            description: "Unlisted host denied",
        },
        UrlScenario {
            url: "https://other-api.com/data",
            expect_allowed: false,
            expect_reason: Some("host"),
            description: "External domain denied",
        },
        // Denied ports
        UrlScenario {
            url: "https://api.example.com:80/api",
            expect_allowed: false,
            expect_reason: Some("port"),
            description: "Port 80 not in allowlist",
        },
        UrlScenario {
            url: "https://api.example.com:22/ssh",
            expect_allowed: false,
            expect_reason: Some("port"),
            description: "SSH port denied",
        },
        // Localhost denial
        UrlScenario {
            url: "http://localhost:8080/admin",
            expect_allowed: false,
            expect_reason: None,
            description: "Localhost blocked by deny_localhost",
        },
        UrlScenario {
            url: "http://127.0.0.1:443/internal",
            expect_allowed: false,
            expect_reason: None,
            description: "Loopback IP blocked",
        },
        // Private ranges (RFC1918)
        UrlScenario {
            url: "http://192.168.1.1:443/router",
            expect_allowed: false,
            expect_reason: None,
            description: "192.168.x.x private range blocked",
        },
        UrlScenario {
            url: "http://10.0.0.1:443/internal",
            expect_allowed: false,
            expect_reason: None,
            description: "10.x.x.x private range blocked",
        },
        UrlScenario {
            url: "http://172.16.0.1:443/internal",
            expect_allowed: false,
            expect_reason: None,
            description: "172.16.x.x private range blocked",
        },
        // IP literals
        UrlScenario {
            url: "https://203.0.113.42:443/api",
            expect_allowed: false,
            expect_reason: Some("ip"),
            description: "Public IP literal blocked by deny_ip_literals",
        },
        UrlScenario {
            url: "https://8.8.8.8:443/dns",
            expect_allowed: false,
            expect_reason: Some("ip"),
            description: "Well-known IP literal blocked",
        },
    ];

    // Create manifest and output path
    let manifest = create_strict_manifest();
    let output_dir = std::env::temp_dir().join("fcp-e2e-logs");
    fs::create_dir_all(&output_dir).expect("create log dir");
    let output_path = output_dir.join(format!(
        "egress-explain-{}.jsonl",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));

    // Run scenarios
    let mut harness = EgressExplainHarness::new(
        "e2e_egress_explain_scenarios",
        manifest.path().to_path_buf(),
    );

    harness.emit_log(
        "setup",
        "pass",
        &json!({
            "manifest_path": manifest.path().to_string_lossy(),
            "scenario_count": scenarios.len()
        }),
    );

    let mut all_passed = true;
    for scenario in &scenarios {
        if !harness.run_scenario(scenario) {
            all_passed = false;
        }
    }

    harness.finalize(&output_path);

    // Validate JSONL against schema
    let jsonl = harness.to_jsonl();
    let validation_result = validate_e2e_log_jsonl(&jsonl);

    assert!(
        validation_result.is_ok(),
        "JSONL should validate against E2E log schema: {:?}",
        validation_result.err()
    );

    // Assert all scenarios passed
    assert!(
        all_passed,
        "Not all E2E scenarios passed. Check log at: {}",
        output_path.display()
    );

    println!("E2E log written to: {}", output_path.display());
}
