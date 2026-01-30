//! E2E scenarios for log schema migration and validation.
//!
//! Per bd-ycmu: Generate v1 logs, migrate to v2, validate both.
//! Persists JSONL artifacts and validates with `fcp_conformance` schema.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use chrono::Utc;
use fcp_conformance::schemas::validate_e2e_log_jsonl;
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const MODULE: &str = "fcp-conformance/log-migration-e2e";
const LOG_VERSION_V1: &str = "v1";
const LOG_VERSION_V2: &str = "v2";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// E2E test harness for log migration scenarios.
struct MigrationHarness {
    log_entries: Vec<serde_json::Value>,
    test_name: String,
    correlation_id: String,
    start_time: Instant,
    passed: u32,
    failed: u32,
}

/// Log entry for the migration test itself (meta-logging).
#[derive(Debug, Serialize)]
struct MigrationLogEntry {
    timestamp: String,
    log_version: String,
    level: String,
    test_name: String,
    module: String,
    phase: String,
    correlation_id: String,
    result: String,
    duration_ms: u64,
    assertions: AssertionsSummary,
    context: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct AssertionsSummary {
    passed: u32,
    failed: u32,
}

impl MigrationHarness {
    fn new(test_name: &str) -> Self {
        Self {
            log_entries: Vec::new(),
            test_name: test_name.to_string(),
            correlation_id: format!("log-migration-{}", Uuid::new_v4()),
            start_time: Instant::now(),
            passed: 0,
            failed: 0,
        }
    }

    fn emit_log(&mut self, phase: &str, result: &str, context: &serde_json::Value) {
        let duration_ms = u64::try_from(self.start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        let entry = MigrationLogEntry {
            timestamp: Utc::now().to_rfc3339(),
            log_version: LOG_VERSION_V1.to_string(),
            level: if result == "fail" {
                "error".to_string()
            } else {
                "info".to_string()
            },
            test_name: self.test_name.clone(),
            module: MODULE.to_string(),
            phase: phase.to_string(),
            correlation_id: self.correlation_id.clone(),
            result: result.to_string(),
            duration_ms,
            assertions: AssertionsSummary {
                passed: self.passed,
                failed: self.failed,
            },
            context: context.clone(),
        };
        self.log_entries
            .push(serde_json::to_value(&entry).expect("serialize entry"));
    }

    fn finalize(&mut self, output_path: &PathBuf) {
        let all_passed = self.failed == 0;
        self.emit_log(
            "verify",
            if all_passed { "pass" } else { "fail" },
            &json!({
                "total_assertions": self.passed + self.failed,
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
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Create a v1 log entry without explicit version (implicit v1).
fn create_v1_implicit_entry(
    script: &str,
    step: &str,
    correlation_id: &str,
    result: &str,
) -> serde_json::Value {
    json!({
        "timestamp": Utc::now().to_rfc3339(),
        "script": script,
        "step": step,
        "correlation_id": correlation_id,
        "duration_ms": 10,
        "result": result
    })
}

/// Create a v1 log entry with explicit version.
fn create_v1_explicit_entry(
    script: &str,
    step: &str,
    correlation_id: &str,
    result: &str,
) -> serde_json::Value {
    json!({
        "timestamp": Utc::now().to_rfc3339(),
        "log_version": LOG_VERSION_V1,
        "script": script,
        "step": step,
        "correlation_id": correlation_id,
        "duration_ms": 10,
        "result": result
    })
}

/// Create a v2 log entry (must have explicit version).
fn create_v2_entry(
    script: &str,
    step: &str,
    correlation_id: &str,
    result: &str,
) -> serde_json::Value {
    json!({
        "timestamp": Utc::now().to_rfc3339(),
        "log_version": LOG_VERSION_V2,
        "script": script,
        "step": step,
        "correlation_id": correlation_id,
        "duration_ms": 10,
        "result": result
    })
}

/// Simulate migration by adding version field to v1 entries.
fn migrate_v1_to_v2(entry: &serde_json::Value) -> serde_json::Value {
    let mut migrated = entry.clone();
    if let serde_json::Value::Object(ref mut map) = migrated {
        // Add v2 version
        map.insert(
            "log_version".to_string(),
            serde_json::Value::String(LOG_VERSION_V2.to_string()),
        );
    }
    migrated
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Scenario
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_log_migration_scenario() {
    let correlation_base = format!("mig-{}", Uuid::new_v4());

    // Create output directory
    let output_dir = std::env::temp_dir().join("fcp-e2e-logs");
    fs::create_dir_all(&output_dir).expect("create log dir");
    let output_path = output_dir.join(format!(
        "log-migration-{}.jsonl",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));

    let mut harness = MigrationHarness::new("e2e_log_migration_scenario");

    // Phase 1: Setup - create test log entries
    harness.emit_log(
        "setup",
        "pass",
        &json!({
            "description": "Creating test log entries",
            "v1_implicit_count": 3,
            "v1_explicit_count": 3,
            "v2_count": 3
        }),
    );

    // Generate v1 implicit entries (no log_version field)
    let v1_implicit: Vec<serde_json::Value> = (0..3)
        .map(|i| {
            create_v1_implicit_entry(
                "migration-test",
                &format!("step-{i}"),
                &format!("{correlation_base}-v1i-{i}"),
                "pass",
            )
        })
        .collect();

    // Generate v1 explicit entries (log_version: "v1")
    let v1_explicit: Vec<serde_json::Value> = (0..3)
        .map(|i| {
            create_v1_explicit_entry(
                "migration-test",
                &format!("step-{i}"),
                &format!("{correlation_base}-v1e-{i}"),
                "pass",
            )
        })
        .collect();

    // Generate v2 entries (log_version: "v2")
    let v2_entries: Vec<serde_json::Value> = (0..3)
        .map(|i| {
            create_v2_entry(
                "migration-test",
                &format!("step-{i}"),
                &format!("{correlation_base}-v2-{i}"),
                "pass",
            )
        })
        .collect();

    // Phase 2: Execute migration
    harness.emit_log(
        "execute",
        "pass",
        &json!({
            "description": "Migrating v1 implicit entries to v2"
        }),
    );

    let migrated: Vec<serde_json::Value> = v1_implicit.iter().map(migrate_v1_to_v2).collect();

    // Phase 3: Validate v1 implicit entries
    let v1_implicit_jsonl: String = v1_implicit
        .iter()
        .filter_map(|e| serde_json::to_string(e).ok())
        .collect::<Vec<_>>()
        .join("\n");

    let v1_implicit_result = validate_e2e_log_jsonl(&v1_implicit_jsonl);
    match v1_implicit_result {
        Ok(()) => {
            harness.passed += 1;
            harness.emit_log(
                "assert",
                "pass",
                &json!({
                    "assertion": "v1_implicit_validation",
                    "description": "v1 entries without log_version validate as v1"
                }),
            );
        }
        Err(err) => {
            harness.failed += 1;
            harness.emit_log(
                "assert",
                "fail",
                &json!({
                    "assertion": "v1_implicit_validation",
                    "error": err.to_string()
                }),
            );
        }
    }

    // Phase 4: Validate v1 explicit entries
    let v1_explicit_jsonl: String = v1_explicit
        .iter()
        .filter_map(|e| serde_json::to_string(e).ok())
        .collect::<Vec<_>>()
        .join("\n");

    let v1_explicit_result = validate_e2e_log_jsonl(&v1_explicit_jsonl);
    match v1_explicit_result {
        Ok(()) => {
            harness.passed += 1;
            harness.emit_log(
                "assert",
                "pass",
                &json!({
                    "assertion": "v1_explicit_validation",
                    "description": "v1 entries with explicit log_version validate"
                }),
            );
        }
        Err(err) => {
            harness.failed += 1;
            harness.emit_log(
                "assert",
                "fail",
                &json!({
                    "assertion": "v1_explicit_validation",
                    "error": err.to_string()
                }),
            );
        }
    }

    // Phase 5: Validate v2 entries
    let v2_jsonl: String = v2_entries
        .iter()
        .filter_map(|e| serde_json::to_string(e).ok())
        .collect::<Vec<_>>()
        .join("\n");

    let v2_result = validate_e2e_log_jsonl(&v2_jsonl);
    match v2_result {
        Ok(()) => {
            harness.passed += 1;
            harness.emit_log(
                "assert",
                "pass",
                &json!({
                    "assertion": "v2_validation",
                    "description": "v2 entries with explicit log_version validate"
                }),
            );
        }
        Err(err) => {
            harness.failed += 1;
            harness.emit_log(
                "assert",
                "fail",
                &json!({
                    "assertion": "v2_validation",
                    "error": err.to_string()
                }),
            );
        }
    }

    // Phase 6: Validate migrated entries (should now be v2)
    let migrated_jsonl: String = migrated
        .iter()
        .filter_map(|e| serde_json::to_string(e).ok())
        .collect::<Vec<_>>()
        .join("\n");

    let migrated_result = validate_e2e_log_jsonl(&migrated_jsonl);
    match migrated_result {
        Ok(()) => {
            harness.passed += 1;
            harness.emit_log(
                "assert",
                "pass",
                &json!({
                    "assertion": "migrated_validation",
                    "description": "Migrated v1→v2 entries validate as v2"
                }),
            );
        }
        Err(err) => {
            harness.failed += 1;
            harness.emit_log(
                "assert",
                "fail",
                &json!({
                    "assertion": "migrated_validation",
                    "error": err.to_string()
                }),
            );
        }
    }

    // Phase 7: Validate mixed version JSONL
    let mixed: Vec<serde_json::Value> = v1_implicit
        .iter()
        .chain(v1_explicit.iter())
        .chain(v2_entries.iter())
        .chain(migrated.iter())
        .cloned()
        .collect();

    let mixed_jsonl: String = mixed
        .iter()
        .filter_map(|e| serde_json::to_string(e).ok())
        .collect::<Vec<_>>()
        .join("\n");

    let mixed_result = validate_e2e_log_jsonl(&mixed_jsonl);
    match mixed_result {
        Ok(()) => {
            harness.passed += 1;
            harness.emit_log(
                "assert",
                "pass",
                &json!({
                    "assertion": "mixed_version_validation",
                    "description": "Mixed v1/v2 JSONL validates correctly",
                    "entry_count": mixed.len()
                }),
            );
        }
        Err(err) => {
            harness.failed += 1;
            harness.emit_log(
                "assert",
                "fail",
                &json!({
                    "assertion": "mixed_version_validation",
                    "error": err.to_string()
                }),
            );
        }
    }

    // Finalize and write logs
    harness.finalize(&output_path);

    // Validate harness's own log output
    let harness_jsonl = harness.to_jsonl();
    let harness_validation = validate_e2e_log_jsonl(&harness_jsonl);

    assert!(
        harness_validation.is_ok(),
        "Harness log should validate: {:?}",
        harness_validation.err()
    );

    // Assert all checks passed
    assert!(
        harness.failed == 0,
        "Not all migration assertions passed. Check log at: {}",
        output_path.display()
    );

    println!("Migration E2E log written to: {}", output_path.display());
}
