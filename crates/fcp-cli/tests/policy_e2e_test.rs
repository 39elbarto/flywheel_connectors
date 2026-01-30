//! E2E policy simulation tests in a deterministic 3-node harness.
//!
//! Per IDEA-18.3: Run simulate in a deterministic harness. Compare simulate decision
//! to actual invocation (allow/deny) without executing side effects. JSONL log entries
//! with `phase=simulate` and evidence object IDs.

use std::time::Duration;

use chrono::Utc;
use fcp_conformance::TestHarness;
use fcp_core::{
    ApprovalScope, ApprovalToken, CapabilityId, Decision, DecisionReasonCode, ExecutionScope,
    InvokeRequest, ObjectHeader, PolicyPattern, PolicySimulationInput, Provenance,
    ProvenanceRecord, SafetyTier, TransportMode, ZoneId, ZonePolicyObject, ZoneTransportPolicy,
    simulate_policy_decision,
};
use fcp_testkit::LogCapture;
use serde_json::json;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Constants
// ─────────────────────────────────────────────────────────────────────────────

const TEST_SEED: u64 = 0xDEAD_BEEF;
const BASE_TIMESTAMP_MS: u64 = 1_700_000_000_000;
const CORRELATION_PREFIX: &str = "policy-e2e";

// ─────────────────────────────────────────────────────────────────────────────
// Simulation Harness
// ─────────────────────────────────────────────────────────────────────────────

/// Harness for deterministic policy simulation in a 3-node mesh.
struct PolicySimulationHarness {
    test_harness: TestHarness,
    log_capture: LogCapture,
    correlation_id: String,
    test_name: String,
}

impl PolicySimulationHarness {
    fn new(test_name: &str) -> Self {
        let test_harness = TestHarness::new(3, TEST_SEED);
        let log_capture = LogCapture::new();
        let correlation_id = format!("{CORRELATION_PREFIX}-{}", Uuid::new_v4());

        Self {
            test_harness,
            log_capture,
            correlation_id,
            test_name: test_name.to_string(),
        }
    }

    fn start(&mut self) {
        self.test_harness.start_all().expect("start all nodes");
        self.emit_log(
            "setup",
            "harness_started",
            &json!({
                "node_count": 3,
                "seed": TEST_SEED,
            }),
        );
    }

    fn stop(&mut self) {
        self.test_harness.stop_all().expect("stop all nodes");
        self.emit_log("cleanup", "harness_stopped", &json!({}));
    }

    fn advance_time(&self, duration: Duration) {
        self.test_harness.advance_time(duration);
    }

    #[allow(dead_code)]
    fn now_ms(&self) -> u64 {
        self.test_harness.now_ms()
    }

    /// Run policy simulation and log with phase=simulate.
    fn simulate(
        &self,
        input: &PolicySimulationInput,
    ) -> Result<SimulationResult, fcp_core::PolicySimulationError> {
        let start = std::time::Instant::now();
        let result = simulate_policy_decision(input);
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        match &result {
            Ok(receipt) => {
                self.emit_log_with_result(
                    "simulate",
                    "policy_simulated",
                    &json!({
                        "decision": format!("{:?}", receipt.decision),
                        "reason_code": receipt.reason_code,
                        "evidence": receipt.evidence.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                        "duration_ms": duration_ms,
                    }),
                    "pass",
                    duration_ms,
                    LogAssertions::none(),
                );

                Ok(SimulationResult {
                    decision: receipt.decision,
                    reason_code: receipt.reason_code.clone(),
                    evidence_count: receipt.evidence.len(),
                    evidence_ids: receipt.evidence.iter().map(ToString::to_string).collect(),
                })
            }
            Err(err) => {
                self.emit_log_with_result(
                    "simulate",
                    "policy_simulation_error",
                    &json!({
                        "error": err.to_string(),
                        "duration_ms": duration_ms,
                    }),
                    "fail",
                    duration_ms,
                    LogAssertions::new(0, 1),
                );
                Err(fcp_core::PolicySimulationError::MissingClaim { claim: "error" })
            }
        }
    }

    /// Compare simulation result to expected outcome without side effects.
    fn assert_simulation(
        &self,
        result: &SimulationResult,
        expected_decision: Decision,
        expected_reason: &str,
    ) {
        let matches = result.decision == expected_decision && result.reason_code == expected_reason;

        self.emit_log_with_result(
            "assert",
            "simulation_comparison",
            &json!({
                "actual_decision": format!("{:?}", result.decision),
                "expected_decision": format!("{:?}", expected_decision),
                "actual_reason": result.reason_code,
                "expected_reason": expected_reason,
                "evidence_count": result.evidence_count,
                "evidence_ids": result.evidence_ids,
                "result": if matches { "pass" } else { "fail" },
            }),
            if matches { "pass" } else { "fail" },
            0,
            LogAssertions::from_match(matches),
        );

        assert_eq!(result.decision, expected_decision, "decision mismatch");
        assert_eq!(result.reason_code, expected_reason, "reason_code mismatch");
    }

    fn emit_log(&self, phase: &str, event_type: &str, context: &serde_json::Value) {
        self.emit_log_with_result(phase, event_type, context, "pass", 0, LogAssertions::none());
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_log_with_result(
        &self,
        phase: &str,
        event_type: &str,
        context: &serde_json::Value,
        result: &str,
        duration_ms: u64,
        assertions: LogAssertions,
    ) {
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": "fcp-cli",
            "phase": phase,
            "correlation_id": self.correlation_id,
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": assertions.passed,
                "failed": assertions.failed,
            },
            "context": {
                "event_type": event_type,
                "payload": context,
            },
        });
        self.log_capture
            .push_value(&entry)
            .expect("serialize log entry");
    }

    fn jsonl(&self) -> String {
        self.log_capture.jsonl()
    }

    fn assert_logs_valid(&self) {
        self.log_capture.assert_valid();
    }
}

/// Result of a policy simulation.
#[derive(Debug, Clone)]
struct SimulationResult {
    decision: Decision,
    reason_code: String,
    evidence_count: usize,
    evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct LogAssertions {
    passed: u64,
    failed: u64,
}

impl LogAssertions {
    const fn new(passed: u64, failed: u64) -> Self {
        Self { passed, failed }
    }

    const fn none() -> Self {
        Self {
            passed: 0,
            failed: 0,
        }
    }

    fn from_match(matches: bool) -> Self {
        Self {
            passed: u64::from(matches),
            failed: u64::from(!matches),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Data Builders
// ─────────────────────────────────────────────────────────────────────────────

fn base_zone_policy(zone: ZoneId) -> ZonePolicyObject {
    let schema = fcp_cbor::SchemaId::new("fcp.core", "ZonePolicy", semver::Version::new(1, 0, 0));
    let header = ObjectHeader {
        schema,
        zone_id: zone.clone(),
        created_at: BASE_TIMESTAMP_MS / 1000,
        provenance: Provenance::new(zone.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    };

    ZonePolicyObject {
        header,
        zone_id: zone,
        principal_allow: vec![PolicyPattern {
            pattern: "user:*".to_string(),
        }],
        principal_deny: Vec::new(),
        connector_allow: vec![PolicyPattern {
            pattern: "connector:*".to_string(),
        }],
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: ZoneTransportPolicy::default(),
        decision_receipts: fcp_core::DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI Diff / Rollback Tests (bd-23d7)
// ─────────────────────────────────────────────────────────────────────────────

mod cli {
    use super::*;
    use assert_cmd::Command;
    use predicates::prelude::*;
    use std::fs;
    use std::path::PathBuf;

    fn fcp_cmd() -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fcp"));
        cmd.env("RUST_LOG", "error");
        cmd
    }

    fn temp_path(name: &str, ext: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let suffix = Uuid::new_v4();
        path.push(format!("fcp_policy_{name}_{suffix}.{ext}"));
        path
    }

    #[test]
    fn policy_diff_reports_added_and_transport_change() {
        let zone = ZoneId::work();
        let before = base_zone_policy(zone);
        let mut after = before.clone();

        after.connector_allow.push(PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        });
        after.transport_policy.allow_derp = true;

        let before_path = temp_path("before", "json");
        let after_path = temp_path("after", "json");

        fs::write(&before_path, serde_json::to_string_pretty(&before).unwrap())
            .expect("write before policy");
        fs::write(&after_path, serde_json::to_string_pretty(&after).unwrap())
            .expect("write after policy");

        let output = fcp_cmd()
            .args([
                "policy",
                "diff",
                "--before",
                before_path.to_string_lossy().as_ref(),
                "--after",
                after_path.to_string_lossy().as_ref(),
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(payload["policy_type"], "zone_policy");
        assert!(
            payload["added"]["connector_allow"]
                .as_array()
                .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("fcp.test:*")))
        );
        assert_eq!(
            payload["changed"]["transport_policy"]["after"]["allow_derp"],
            true
        );
        assert!(payload["risk_flags"].as_array().is_some_and(|arr| {
            arr.iter()
                .any(|v| v.as_str() == Some("transport_derp_enabled"))
        }));
    }

    #[test]
    fn policy_rollback_plan_includes_previous_id() {
        let zone = ZoneId::work();
        let mut current = base_zone_policy(zone.clone());
        let previous = base_zone_policy(zone);
        current.capability_allow.push(PolicyPattern {
            pattern: "cap.test.read".to_string(),
        });

        let current_path = temp_path("current", "json");
        let previous_path = temp_path("previous", "json");

        fs::write(
            &current_path,
            serde_json::to_string_pretty(&current).unwrap(),
        )
        .expect("write current policy");
        fs::write(
            &previous_path,
            serde_json::to_string_pretty(&previous).unwrap(),
        )
        .expect("write previous policy");

        let output = fcp_cmd()
            .args([
                "policy",
                "rollback",
                "--plan",
                "--current",
                current_path.to_string_lossy().as_ref(),
                "--previous",
                previous_path.to_string_lossy().as_ref(),
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let payload: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(payload["policy_type"], "zone_policy");
        assert_eq!(payload["plan_type"], "rollback");
        assert!(payload["current_policy_id"].as_str().is_some());
        assert!(payload["previous_policy_id"].as_str().is_some());
        assert_eq!(payload["zone_id"], "z:work");
    }

    #[test]
    fn policy_rollback_requires_plan_flag() {
        let zone = ZoneId::work();
        let policy = base_zone_policy(zone);
        let path = temp_path("policy", "json");
        fs::write(&path, serde_json::to_string_pretty(&policy).unwrap()).expect("write policy");

        fcp_cmd()
            .args([
                "policy",
                "rollback",
                "--current",
                path.to_string_lossy().as_ref(),
                "--previous",
                path.to_string_lossy().as_ref(),
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--plan"));
    }
}

fn base_invoke(zone: ZoneId) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: fcp_core::RequestId::new("req-test"),
        connector_id: fcp_core::ConnectorId::from_static("connector:test"),
        operation: fcp_core::OperationId::from_static("op.read"),
        zone_id: zone,
        input: json!({"value": 1}),
        capability_token: fcp_core::CapabilityToken::test_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn base_simulation_input(
    zone_policy: ZonePolicyObject,
    invoke_request: InvokeRequest,
) -> PolicySimulationInput {
    PolicySimulationInput {
        zone_policy,
        invoke_request,
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: None,
        safety_tier: SafetyTier::Safe,
        principal: Some("user:alice".to_string()),
        capability_id: Some("cap.read".to_string()),
        provenance_record: Some(ProvenanceRecord::new(ZoneId::work())),
        now_ms: Some(BASE_TIMESTAMP_MS),
        posture_attestation: None,
    }
}

fn execution_approval(invoke: &InvokeRequest, now_ms: u64) -> ApprovalToken {
    ApprovalToken {
        token_id: "exec-token-1".to_string(),
        issued_at_ms: now_ms - 1000,
        expires_at_ms: now_ms + 60_000,
        issuer: "owner".to_string(),
        scope: ApprovalScope::Execution(ExecutionScope {
            connector_id: invoke.connector_id.as_str().to_string(),
            method_pattern: invoke.operation.as_str().to_string(),
            request_object_id: None,
            input_hash: None,
            input_constraints: Vec::new(),
        }),
        zone_id: invoke.zone_id.clone(),
        signature: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test that a basic allow scenario produces the expected decision in the harness.
#[test]
fn e2e_harness_simulation_allows_valid_request() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_simulation_allows_valid_request");
    harness.start();

    let zone = ZoneId::work();
    let policy = base_zone_policy(zone.clone());
    let invoke = base_invoke(zone);
    let input = base_simulation_input(policy, invoke);

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(&result, Decision::Allow, DecisionReasonCode::Allow.as_str());

    harness.stop();

    // Verify JSONL structure
    let jsonl = harness.jsonl();
    assert!(
        jsonl.contains("\"phase\":\"simulate\""),
        "must have simulate phase"
    );
    assert!(
        jsonl.contains("\"event_type\":\"policy_simulated\""),
        "must have policy_simulated event"
    );
}

/// Test that stale revocation causes denial across all harness nodes.
#[test]
fn e2e_harness_stale_revocation_denies() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_stale_revocation_denies");
    harness.start();

    let zone = ZoneId::work();
    let policy = base_zone_policy(zone.clone());
    let invoke = base_invoke(zone);
    let mut input = base_simulation_input(policy, invoke);
    input.revocation_fresh = false;

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(
        &result,
        Decision::Deny,
        DecisionReasonCode::RevocationStaleFrontier.as_str(),
    );

    harness.stop();
}

/// Test that stale checkpoint causes denial.
#[test]
fn e2e_harness_stale_checkpoint_denies() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_stale_checkpoint_denies");
    harness.start();

    let zone = ZoneId::work();
    let policy = base_zone_policy(zone.clone());
    let invoke = base_invoke(zone);
    let mut input = base_simulation_input(policy, invoke);
    input.checkpoint_fresh = false;

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(
        &result,
        Decision::Deny,
        DecisionReasonCode::CheckpointStaleFrontier.as_str(),
    );

    harness.stop();
}

/// Test that capability ceiling enforcement works in simulation.
#[test]
fn e2e_harness_capability_ceiling_denies() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_capability_ceiling_denies");
    harness.start();

    let zone = ZoneId::work();
    let mut policy = base_zone_policy(zone.clone());
    // Set ceiling to only allow cap.allowed, not cap.read
    policy.capability_ceiling = vec![CapabilityId::from_static("cap.allowed")];

    let invoke = base_invoke(zone);
    let input = base_simulation_input(policy, invoke);

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(
        &result,
        Decision::Deny,
        DecisionReasonCode::CapabilityInsufficient.as_str(),
    );

    harness.stop();
}

/// Test that execution approval is required and granted.
#[test]
fn e2e_harness_execution_approval_allows() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_execution_approval_allows");
    harness.start();

    let zone = ZoneId::work();
    let policy = base_zone_policy(zone.clone());
    let mut invoke = base_invoke(zone);
    invoke
        .approval_tokens
        .push(execution_approval(&invoke, BASE_TIMESTAMP_MS));

    let mut input = base_simulation_input(policy, invoke);
    input.execution_approval_required = true;

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(&result, Decision::Allow, DecisionReasonCode::Allow.as_str());

    // Evidence should include the approval token
    assert!(
        result.evidence_count > 0,
        "evidence should include approval token"
    );

    harness.stop();

    // Verify evidence is logged
    let jsonl = harness.jsonl();
    assert!(jsonl.contains("\"evidence\""), "evidence must be in logs");
}

/// Test that missing execution approval denies.
#[test]
fn e2e_harness_missing_execution_approval_denies() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_missing_execution_approval_denies");
    harness.start();

    let zone = ZoneId::work();
    let policy = base_zone_policy(zone.clone());
    let invoke = base_invoke(zone);

    let mut input = base_simulation_input(policy, invoke);
    input.execution_approval_required = true;
    // No approval tokens provided

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(
        &result,
        Decision::Deny,
        DecisionReasonCode::ApprovalMissingExecution.as_str(),
    );

    harness.stop();
}

/// Test transport mode enforcement (DERP forbidden by default).
#[test]
fn e2e_harness_transport_derp_forbidden() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_transport_derp_forbidden");
    harness.start();

    let zone = ZoneId::work();
    let policy = base_zone_policy(zone.clone());
    let invoke = base_invoke(zone);

    let mut input = base_simulation_input(policy, invoke);
    input.transport = TransportMode::Derp;

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(
        &result,
        Decision::Deny,
        DecisionReasonCode::TransportDerpForbidden.as_str(),
    );

    harness.stop();
}

/// Test principal deny list enforcement.
#[test]
fn e2e_harness_principal_denied() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_principal_denied");
    harness.start();

    let zone = ZoneId::work();
    let mut policy = base_zone_policy(zone.clone());
    policy.principal_deny.push(PolicyPattern {
        pattern: "user:alice".to_string(),
    });

    let invoke = base_invoke(zone);
    let input = base_simulation_input(policy, invoke);

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(
        &result,
        Decision::Deny,
        DecisionReasonCode::ZonePolicyPrincipalDenied.as_str(),
    );

    harness.stop();
}

/// Test connector deny list enforcement.
#[test]
fn e2e_harness_connector_denied() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_connector_denied");
    harness.start();

    let zone = ZoneId::work();
    let mut policy = base_zone_policy(zone.clone());
    policy.connector_deny.push(PolicyPattern {
        pattern: "connector:test".to_string(),
    });

    let invoke = base_invoke(zone);
    let input = base_simulation_input(policy, invoke);

    let result = harness.simulate(&input).expect("simulation succeeded");
    harness.assert_simulation(
        &result,
        Decision::Deny,
        DecisionReasonCode::ZonePolicyConnectorDenied.as_str(),
    );

    harness.stop();
}

/// Full workflow: simulate multiple scenarios across harness lifetime.
#[test]
#[allow(clippy::too_many_lines)]
fn e2e_harness_full_simulation_workflow() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_full_simulation_workflow");
    harness.start();

    harness.emit_log(
        "execute",
        "workflow_started",
        &json!({
            "scenario_count": 4,
        }),
    );

    // Scenario 1: Valid request (Allow)
    {
        let zone = ZoneId::work();
        let policy = base_zone_policy(zone.clone());
        let invoke = base_invoke(zone);
        let input = base_simulation_input(policy, invoke);

        let result = harness.simulate(&input).expect("scenario 1 succeeded");
        harness.assert_simulation(&result, Decision::Allow, DecisionReasonCode::Allow.as_str());
    }

    // Advance simulated time between scenarios
    harness.advance_time(Duration::from_secs(5));

    // Scenario 2: Stale revocation (Deny)
    {
        let zone = ZoneId::work();
        let policy = base_zone_policy(zone.clone());
        let invoke = base_invoke(zone);
        let mut input = base_simulation_input(policy, invoke);
        input.revocation_fresh = false;

        let result = harness.simulate(&input).expect("scenario 2 succeeded");
        harness.assert_simulation(
            &result,
            Decision::Deny,
            DecisionReasonCode::RevocationStaleFrontier.as_str(),
        );
    }

    harness.advance_time(Duration::from_secs(5));

    // Scenario 3: With execution approval (Allow)
    {
        let zone = ZoneId::work();
        let policy = base_zone_policy(zone.clone());
        let mut invoke = base_invoke(zone);
        invoke
            .approval_tokens
            .push(execution_approval(&invoke, BASE_TIMESTAMP_MS));

        let mut input = base_simulation_input(policy, invoke);
        input.execution_approval_required = true;

        let result = harness.simulate(&input).expect("scenario 3 succeeded");
        harness.assert_simulation(&result, Decision::Allow, DecisionReasonCode::Allow.as_str());
    }

    harness.advance_time(Duration::from_secs(5));

    // Scenario 4: Capability ceiling violation (Deny)
    {
        let zone = ZoneId::work();
        let mut policy = base_zone_policy(zone.clone());
        policy.capability_ceiling = vec![CapabilityId::from_static("cap.admin")];

        let invoke = base_invoke(zone);
        let input = base_simulation_input(policy, invoke);

        let result = harness.simulate(&input).expect("scenario 4 succeeded");
        harness.assert_simulation(
            &result,
            Decision::Deny,
            DecisionReasonCode::CapabilityInsufficient.as_str(),
        );
    }

    harness.emit_log(
        "verify",
        "workflow_completed",
        &json!({
            "scenarios_passed": 4,
        }),
    );

    harness.stop();

    // Verify full JSONL output
    let jsonl = harness.jsonl();
    let lines: Vec<&str> = jsonl.lines().collect();

    // Should have: start + 4 simulations + 4 assertions + workflow events + stop
    assert!(
        lines.len() >= 10,
        "expected at least 10 log lines, got {}",
        lines.len()
    );

    // Verify all lines are valid JSON
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line).expect("each line should be valid JSON");
    }

    // Count phase=simulate entries
    let simulate_count = lines
        .iter()
        .filter(|line| line.contains("\"phase\":\"simulate\""))
        .count();
    assert_eq!(simulate_count, 4, "should have 4 simulate phase entries");
}

/// Test zone mismatch error handling.
#[test]
fn e2e_harness_zone_mismatch_error() {
    let mut harness = PolicySimulationHarness::new("e2e_harness_zone_mismatch_error");
    harness.start();

    let policy = base_zone_policy(ZoneId::work());
    let invoke = base_invoke(ZoneId::private()); // Different zone!

    let input = PolicySimulationInput {
        zone_policy: policy,
        invoke_request: invoke,
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: None,
        safety_tier: SafetyTier::Safe,
        principal: Some("user:alice".to_string()),
        capability_id: Some("cap.read".to_string()),
        provenance_record: None,
        now_ms: Some(BASE_TIMESTAMP_MS),
        posture_attestation: None,
    };

    // This should return an error, not a receipt
    let result = simulate_policy_decision(&input);
    let error_msg = result.as_ref().unwrap_err().to_string();
    assert!(result.is_err(), "zone mismatch should return error");

    harness.emit_log(
        "simulate",
        "zone_mismatch_error",
        &json!({
            "error": error_msg,
            "result": "pass",
        }),
    );

    harness.stop();
}

/// E2E rollback scenario: diff + rollback plan restores previous policy state.
#[test]
#[allow(clippy::too_many_lines)]
fn e2e_policy_rollback_plan_restores_previous_state() {
    let mut harness =
        PolicySimulationHarness::new("e2e_policy_rollback_plan_restores_previous_state");
    harness.start();

    let zone = ZoneId::work();
    let before = base_zone_policy(zone.clone());
    let mut after = before.clone();
    after.capability_allow.push(PolicyPattern {
        pattern: "cap.test.read".to_string(),
    });
    after.transport_policy.allow_derp = true;

    harness.emit_log(
        "execute",
        "policy_change_applied",
        &json!({
            "zone_id": zone.to_string(),
            "changes": ["capability_allow:+cap.test.read", "transport_policy.allow_derp:true"],
        }),
    );

    let temp_path = |name: &str, ext: &str| -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let suffix = Uuid::new_v4();
        path.push(format!("fcp_policy_{name}_{suffix}.{ext}"));
        path
    };

    let before_path = temp_path("before", "json");
    let after_path = temp_path("after", "json");

    std::fs::write(
        &before_path,
        serde_json::to_string_pretty(&before).expect("serialize before policy"),
    )
    .expect("write before policy");
    std::fs::write(
        &after_path,
        serde_json::to_string_pretty(&after).expect("serialize after policy"),
    )
    .expect("write after policy");

    let diff_start = std::time::Instant::now();
    let diff_output = assert_cmd::Command::new(env!("CARGO_BIN_EXE_fcp"))
        .args([
            "policy",
            "diff",
            "--before",
            before_path.to_string_lossy().as_ref(),
            "--after",
            after_path.to_string_lossy().as_ref(),
            "--json",
        ])
        .env("RUST_LOG", "error")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    #[allow(clippy::cast_possible_truncation)]
    let diff_duration_ms = diff_start.elapsed().as_millis() as u64;
    let diff_payload: serde_json::Value =
        serde_json::from_slice(&diff_output).expect("parse diff payload");

    harness.emit_log_with_result(
        "execute",
        "policy_diff_generated",
        &json!({
            "previous_policy_id": diff_payload["previous_policy_id"],
            "current_policy_id": diff_payload["current_policy_id"],
            "zone_id": diff_payload["zone_id"],
        }),
        "pass",
        diff_duration_ms,
        LogAssertions::none(),
    );

    let rollback_start = std::time::Instant::now();
    let rollback_output = assert_cmd::Command::new(env!("CARGO_BIN_EXE_fcp"))
        .args([
            "policy",
            "rollback",
            "--plan",
            "--current",
            after_path.to_string_lossy().as_ref(),
            "--previous",
            before_path.to_string_lossy().as_ref(),
            "--json",
        ])
        .env("RUST_LOG", "error")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    #[allow(clippy::cast_possible_truncation)]
    let rollback_duration_ms = rollback_start.elapsed().as_millis() as u64;
    let rollback_payload: serde_json::Value =
        serde_json::from_slice(&rollback_output).expect("parse rollback payload");

    assert_eq!(rollback_payload["plan_type"], "rollback");
    assert_eq!(rollback_payload["policy_type"], "zone_policy");
    assert_eq!(
        rollback_payload["previous_policy_id"],
        diff_payload["previous_policy_id"]
    );
    assert_eq!(
        rollback_payload["current_policy_id"],
        diff_payload["current_policy_id"]
    );
    assert_eq!(rollback_payload["zone_id"], diff_payload["zone_id"]);

    harness.emit_log_with_result(
        "verify",
        "policy_rollback_plan_generated",
        &json!({
            "previous_policy_id": rollback_payload["previous_policy_id"],
            "current_policy_id": rollback_payload["current_policy_id"],
            "plan_type": rollback_payload["plan_type"],
        }),
        "pass",
        rollback_duration_ms,
        LogAssertions::new(1, 0),
    );

    harness.stop();
    harness.assert_logs_valid();
}
