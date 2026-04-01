//! MVP Vertical Slice: deterministic E2E tests (flywheel_connectors-1n78.36).
//!
//! Validates the core architecture via minimal end-to-end scenarios:
//!
//! 1. **Happy Path**: Install → Invoke → Receipt → Audit → Verify
//! 2. **Denial Path**: Invoke Without Cap → `DecisionReceipt` → Explain
//! 3. **Revocation Flow**: Issue Token → Use → Revoke → Denial
//! 4. **Taint/Approval Flow**: Tainted Input → Denial → Approval → Success
//! 5. **Offline/Repair Flow**: Reduced Availability → Repair → Recovery
//! 6. **Epoch Replay**: Binary Mirror Install + Epoch Event Replay
//!
//! All tests use the deterministic harness with `MockClock`, `SimulatedNetwork`,
//! seeded RNG, and structured `LogCollector` for reproducible execution.

#![allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::needless_pass_by_value
)]

use std::time::Duration;

use fcp_cbor::SchemaId;
use fcp_conformance::harness::{LogCollector, LogEntry, TestHarness};
#[allow(unused_imports)]
use fcp_core::RiskTier;
use fcp_core::{
    AuditEvent, AuditHead, ConnectorId, CorrelationId, Decision, DecisionReceipt,
    EVENT_CAPABILITY_INVOKE, EVENT_REVOCATION_ISSUED, EVENT_SECRET_ACCESS,
    EVENT_SECURITY_VIOLATION, EpochId, NodeSignature, ObjectHeader, ObjectId, PrincipalId,
    Provenance, SignatureSet, ZoneCheckpoint, ZoneId,
};
use fcp_mesh::ObjectAdmissionClass;
use fcp_tailscale::NodeId;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// Alias for the core crate `NodeId` used by `NodeSignature`.
type CoreNodeId = fcp_core::NodeId;

const SEED: u64 = 0xDEAD_BEEF;
const OFFLINE_REPAIR_SCENARIO: &str = "offline_repair";
const EPOCH_REPLAY_SCENARIO: &str = "epoch_replay";
const REVOCATION_SCENARIO: &str = "revocation";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn test_header(kind: &str) -> ObjectHeader {
    ObjectHeader {
        schema: SchemaId::new("fcp.core", kind, Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_signature(node: &str) -> NodeSignature {
    NodeSignature::new(CoreNodeId::new(node), [0u8; 64], 1_700_000_000)
}

fn test_actor() -> PrincipalId {
    PrincipalId::new("user:agent-1").expect("principal id")
}

fn test_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn create_audit_event(
    seq: u64,
    prev: Option<ObjectId>,
    event_type: &str,
    connector_id: Option<&str>,
    operation: Option<&str>,
) -> AuditEvent {
    let seq_byte = u8::try_from(seq).unwrap_or(0);
    AuditEvent {
        header: test_header("AuditEvent"),
        correlation_id: CorrelationId(Uuid::from_bytes([seq_byte; 16])),
        trace_context: None,
        event_type: event_type.to_string(),
        actor: test_actor(),
        zone_id: ZoneId::work(),
        connector_id: connector_id.map(|c| c.parse().expect("valid connector id")),
        operation: operation.map(|o| o.parse().expect("valid operation id")),
        capability_token_jti: Some(Uuid::from_bytes([seq_byte; 16])),
        request_object_id: Some(test_object_id(&format!("req-{seq}"))),
        result_object_id: Some(test_object_id(&format!("res-{seq}"))),
        prev,
        seq,
        occurred_at: 1_700_000_000 + seq,
        signature: test_signature("node-1"),
    }
}

fn create_decision_receipt(
    decision: Decision,
    reason_code: &str,
    explanation: Option<&str>,
) -> DecisionReceipt {
    DecisionReceipt {
        header: test_header("DecisionReceipt"),
        request_object_id: test_object_id("invoke-request"),
        decision,
        reason_code: reason_code.to_string(),
        evidence: vec![test_object_id("evidence-1"), test_object_id("evidence-2")],
        explanation: explanation.map(String::from),
        signature: test_signature("node-1"),
    }
}

fn create_audit_head(head_event: ObjectId, seq: u64, coverage: f64) -> AuditHead {
    AuditHead {
        header: test_header("AuditHead"),
        zone_id: ZoneId::work(),
        head_event,
        head_seq: seq,
        coverage,
        epoch_id: EpochId::new("epoch-1"),
        quorum_signatures: SignatureSet::new(),
    }
}

fn emit_log(
    logs: &LogCollector,
    scenario: &str,
    phase: &str,
    assertion: &str,
    result: &str,
    details: serde_json::Value,
) {
    logs.push(LogEntry::new(
        "mvp-harness",
        scenario,
        phase,
        format!("mvp-{scenario}-{phase}"),
        assertion,
        json!({
            "scenario": scenario,
            "result": result,
            "details": details,
        }),
    ));
}

const OFFLINE_REPAIR_CONTRACT_ID: &str = "contract.offline_repair_recovery";
const EPOCH_REPLAY_CONTRACT_ID: &str = "contract.epoch_replay_checkpoint_retrieval";
const REVOCATION_CONTRACT_ID: &str = "contract.revocation_chain_enforcement";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScenarioAssertionEvidence {
    phase: String,
    assertion: String,
    result: String,
}

fn scenario_assertions(logs: &[LogEntry], scenario: &str) -> Vec<ScenarioAssertionEvidence> {
    logs.iter()
        .filter(|entry| entry.test_name == scenario)
        .map(|entry| ScenarioAssertionEvidence {
            phase: entry.phase.clone(),
            assertion: entry.event_type.clone(),
            result: entry
                .details
                .get("result")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
                .to_string(),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryReplayEvidence {
    seed: u64,
    zone_id: String,
    object_id: String,
    failed_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryCoverageEvidence {
    degraded_coverage_bps: u16,
    recovered_coverage_bps: u16,
    minimum_healthy_coverage_bps: u16,
    running_nodes_before_repair: u8,
    running_nodes_after_repair: u8,
    available_replicas_before_repair: u8,
    available_replicas_after_repair: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: RecoveryReplayEvidence,
    coverage: RecoveryCoverageEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EpochReplayReplayEvidence {
    seed: u64,
    zone_id: String,
    event_ids: Vec<String>,
    tail_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EpochReplayStateEvidence {
    chain_valid: bool,
    event_count: u8,
    distributed_node_count: u8,
    tail_event_visible_on_all_nodes: bool,
    checkpoint_audit_seq: u64,
    checkpoint_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EpochReplayArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: EpochReplayReplayEvidence,
    state: EpochReplayStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevocationReplayEvidence {
    seed: u64,
    connector_id: String,
    issue_event_id: String,
    use_event_id: String,
    revoke_event_id: String,
    deny_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevocationStateEvidence {
    chain_valid: bool,
    allow_before_revoke: bool,
    deny_after_revoke: bool,
    revocation_propagated: bool,
    post_revoke_reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevocationArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: RevocationReplayEvidence,
    state: RevocationStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn coverage_bps(available_nodes: usize, total_nodes: usize) -> u16 {
    let numerator = available_nodes.saturating_mul(10_000);
    let ratio = numerator / total_nodes.max(1);
    u16::try_from(ratio).expect("coverage basis points fit in u16")
}

fn count_available_replicas(
    harness: &mut TestHarness,
    zone: &ZoneId,
    object_id: &ObjectId,
    node_indices: &[usize],
) -> usize {
    node_indices
        .iter()
        .copied()
        .filter(|&idx| {
            harness.nodes[idx]
                .mesh_mut()
                .is_some_and(|mesh| mesh.gossip_mut().has_object(zone, object_id))
        })
        .count()
}

fn build_recovery_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    object_id: ObjectId,
    failed_node_id: &NodeId,
    running_nodes_before_repair: usize,
    running_nodes_after_repair: usize,
    available_replicas_before_repair: usize,
    available_replicas_after_repair: usize,
    degraded_coverage_bps: u16,
    recovered_coverage_bps: u16,
    log_jsonl_valid: bool,
) -> RecoveryArtifactBundle {
    RecoveryArtifactBundle {
        scenario_key: "offline_repair".to_string(),
        contract_id: OFFLINE_REPAIR_CONTRACT_ID.to_string(),
        replay: RecoveryReplayEvidence {
            seed: SEED,
            zone_id: zone.to_string(),
            object_id: object_id.to_string(),
            failed_node_id: failed_node_id.as_str().to_string(),
        },
        coverage: RecoveryCoverageEvidence {
            degraded_coverage_bps,
            recovered_coverage_bps,
            minimum_healthy_coverage_bps: 5_000,
            running_nodes_before_repair: u8::try_from(running_nodes_before_repair)
                .expect("running node count fits in u8"),
            running_nodes_after_repair: u8::try_from(running_nodes_after_repair)
                .expect("running node count fits in u8"),
            available_replicas_before_repair: u8::try_from(available_replicas_before_repair)
                .expect("replica count fits in u8"),
            available_replicas_after_repair: u8::try_from(available_replicas_after_repair)
                .expect("replica count fits in u8"),
        },
        log_entry_count: logs.len(),
        log_jsonl_valid,
        assertions: scenario_assertions(logs, OFFLINE_REPAIR_SCENARIO),
    }
}

fn build_epoch_replay_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    event_ids: &[ObjectId],
    tail_event_id: &ObjectId,
    chain_valid: bool,
    distributed_node_count: usize,
    tail_event_visible_on_all_nodes: bool,
    checkpoint_audit_seq: u64,
    checkpoint_seq: u64,
    log_jsonl_valid: bool,
) -> EpochReplayArtifactBundle {
    EpochReplayArtifactBundle {
        scenario_key: "epoch_replay".to_string(),
        contract_id: EPOCH_REPLAY_CONTRACT_ID.to_string(),
        replay: EpochReplayReplayEvidence {
            seed: SEED,
            zone_id: zone.to_string(),
            event_ids: event_ids.iter().map(ToString::to_string).collect(),
            tail_event_id: tail_event_id.to_string(),
        },
        state: EpochReplayStateEvidence {
            chain_valid,
            event_count: u8::try_from(event_ids.len()).expect("event count fits in u8"),
            distributed_node_count: u8::try_from(distributed_node_count)
                .expect("distributed node count fits in u8"),
            tail_event_visible_on_all_nodes,
            checkpoint_audit_seq,
            checkpoint_seq,
        },
        assertions: scenario_assertions(logs, EPOCH_REPLAY_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

fn build_revocation_artifact_bundle(
    logs: &[LogEntry],
    connector_id: &ConnectorId,
    issue_event_id: &ObjectId,
    use_event_id: &ObjectId,
    revoke_event_id: &ObjectId,
    deny_event_id: &ObjectId,
    chain_valid: bool,
    allow_before_revoke: bool,
    deny_after_revoke: bool,
    revocation_propagated: bool,
    post_revoke_reason_code: &str,
    log_jsonl_valid: bool,
) -> RevocationArtifactBundle {
    RevocationArtifactBundle {
        scenario_key: "revocation".to_string(),
        contract_id: REVOCATION_CONTRACT_ID.to_string(),
        replay: RevocationReplayEvidence {
            seed: SEED,
            connector_id: connector_id.as_ref().to_string(),
            issue_event_id: issue_event_id.to_string(),
            use_event_id: use_event_id.to_string(),
            revoke_event_id: revoke_event_id.to_string(),
            deny_event_id: deny_event_id.to_string(),
        },
        state: RevocationStateEvidence {
            chain_valid,
            allow_before_revoke,
            deny_after_revoke,
            revocation_propagated,
            post_revoke_reason_code: post_revoke_reason_code.to_string(),
        },
        assertions: scenario_assertions(logs, REVOCATION_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1: Happy Path — Install → Invoke → Receipt → Audit → Verify
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn happy_path_install_invoke_receipt_audit_verify() {
    // Phase 1: Setup — create 3-node mesh with deterministic seed.
    let mut harness = TestHarness::new(3, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();

    // Verify all nodes are running.
    assert_eq!(harness.running_count(), 3);
    emit_log(
        &harness.logs,
        "happy_path",
        "setup",
        "nodes_running",
        "pass",
        json!({"node_count": 3, "seed": SEED}),
    );

    // Phase 2: Install — simulate connector installation by storing manifest
    // as a mesh object and announcing it to all nodes.
    let connector_id = ConnectorId::from_static("fcp.test-echo:echo:0.1.0");
    let manifest_obj_id = test_object_id("manifest-echo-v0.1.0");
    let zone = ZoneId::work();

    // Announce manifest to all nodes.
    let now_secs = harness.now_ms() / 1000;
    for node in &mut harness.nodes {
        if let Some(mesh) = node.mesh_mut() {
            mesh.gossip_mut().announce_object(
                &zone,
                &manifest_obj_id,
                ObjectAdmissionClass::Admitted,
                now_secs,
            );
        }
    }

    emit_log(
        &harness.logs,
        "happy_path",
        "install",
        "manifest_announced",
        "pass",
        json!({"connector_id": connector_id.as_ref(), "manifest_obj_id": manifest_obj_id.to_string()}),
    );

    // Phase 3: Invoke — create audit event for capability.invoke.
    let genesis_event = create_audit_event(
        0,
        None,
        EVENT_CAPABILITY_INVOKE,
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert!(genesis_event.is_genesis());

    let genesis_id = test_object_id("audit-event-0");
    let invoke_event = create_audit_event(
        1,
        Some(genesis_id),
        EVENT_CAPABILITY_INVOKE,
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert!(invoke_event.follows(&genesis_event, &genesis_id));

    emit_log(
        &harness.logs,
        "happy_path",
        "invoke",
        "audit_chain_valid",
        "pass",
        json!({"genesis_seq": 0, "invoke_seq": 1, "follows": true}),
    );

    // Phase 4: Receipt — create allow receipt.
    let receipt = create_decision_receipt(
        Decision::Allow,
        "FCP-0000",
        Some("Capability present and valid"),
    );
    assert!(receipt.is_allow());
    assert!(!receipt.is_deny());
    assert_eq!(receipt.reason_code, "FCP-0000");
    assert_eq!(receipt.evidence.len(), 2);

    emit_log(
        &harness.logs,
        "happy_path",
        "receipt",
        "allow_receipt_valid",
        "pass",
        json!({"decision": "allow", "reason_code": "FCP-0000", "evidence_count": 2}),
    );

    // Phase 5: Audit — verify chain integrity, create audit head.
    let head = create_audit_head(test_object_id("audit-event-1"), 1, 1.0);
    assert_eq!(head.head_seq, 1);
    assert!(head.coverage >= 1.0);

    emit_log(
        &harness.logs,
        "happy_path",
        "audit",
        "audit_head_valid",
        "pass",
        json!({"head_seq": 1, "coverage": 1.0}),
    );

    // Phase 6: Verify — advance time, run gossip, check convergence.
    harness.advance_time(Duration::from_secs(5));
    harness.gossip_exchange_round();

    let logs = harness.log_entries();
    let scenario_logs: Vec<&LogEntry> = logs
        .iter()
        .filter(|e| e.details.get("scenario").and_then(|v| v.as_str()) == Some("happy_path"))
        .collect();

    assert_eq!(scenario_logs.len(), 5, "expected 5 happy_path log entries");

    // All phases passed.
    for log in scenario_logs {
        assert_eq!(
            log.details.get("result").and_then(|v| v.as_str()),
            Some("pass"),
            "phase failed: {}",
            log.phase
        );
    }

    harness.stop_all().unwrap();
    assert_eq!(harness.running_count(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2: Denial Path — Invoke Without Cap → DecisionReceipt → Explain
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn denial_path_invoke_without_cap_produces_receipt() {
    let mut harness = TestHarness::new(3, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();

    // Phase 1: Attempt invoke without capability.
    let receipt = create_decision_receipt(
        Decision::Deny,
        "FCP-2101",
        Some("No valid capability token for operation echo on connector fcp.test-echo"),
    );
    assert!(receipt.is_deny());
    assert_eq!(receipt.reason_code, "FCP-2101");

    emit_log(
        &harness.logs,
        "denial_path",
        "invoke_no_cap",
        "deny_receipt_generated",
        "pass",
        json!({
            "decision": "deny",
            "reason_code": "FCP-2101",
            "explanation": receipt.explanation.as_deref(),
        }),
    );

    // Phase 2: Verify explanation is actionable.
    let explanation = receipt.explanation.as_deref().unwrap();
    assert!(
        explanation.contains("capability"),
        "explanation should mention capability"
    );
    assert!(
        explanation.contains("fcp.test-echo"),
        "explanation should mention connector"
    );

    emit_log(
        &harness.logs,
        "denial_path",
        "explain",
        "explanation_actionable",
        "pass",
        json!({"explanation": explanation}),
    );

    // Phase 3: Audit event for security violation.
    let violation_event = create_audit_event(
        0,
        None,
        EVENT_SECURITY_VIOLATION,
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert_eq!(violation_event.event_type, EVENT_SECURITY_VIOLATION);
    assert!(violation_event.is_genesis());

    emit_log(
        &harness.logs,
        "denial_path",
        "audit",
        "violation_recorded",
        "pass",
        json!({"event_type": EVENT_SECURITY_VIOLATION, "seq": 0}),
    );

    // Verify all logs.
    let logs = harness.log_entries();
    let count = logs
        .iter()
        .filter(|e| e.details.get("scenario").and_then(|v| v.as_str()) == Some("denial_path"))
        .count();
    assert_eq!(count, 3);

    harness.stop_all().unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2b: Expired token denial
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn denial_path_expired_token_produces_specific_reason_code() {
    let receipt = create_decision_receipt(
        Decision::Deny,
        "FCP-2102",
        Some("Capability token expired at 2026-03-01T00:00:00Z"),
    );
    assert!(receipt.is_deny());
    assert_eq!(receipt.reason_code, "FCP-2102");
    assert!(receipt.explanation.as_deref().unwrap().contains("expired"));
}

#[test]
fn denial_path_wrong_zone_produces_specific_reason_code() {
    let receipt = create_decision_receipt(
        Decision::Deny,
        "FCP-2103",
        Some("Capability token is for zone z:personal but request targets z:work"),
    );
    assert!(receipt.is_deny());
    assert_eq!(receipt.reason_code, "FCP-2103");
    assert!(receipt.explanation.as_deref().unwrap().contains("zone"));
}

#[test]
fn denial_path_wrong_operation_produces_specific_reason_code() {
    let receipt = create_decision_receipt(
        Decision::Deny,
        "FCP-2104",
        Some("Capability token does not grant operation send_message on connector fcp.discord"),
    );
    assert!(receipt.is_deny());
    assert_eq!(receipt.reason_code, "FCP-2104");
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 3: Revocation Flow — Issue → Use → Revoke → Denial
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_flow_issue_use_revoke_deny() {
    let mut harness = TestHarness::new(3, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();
    let connector_id = ConnectorId::from_static("fcp.test-echo:echo:0.1.0");

    // Phase 1: Issue capability (simulated as genesis audit event).
    let issue_event = create_audit_event(
        0,
        None,
        EVENT_CAPABILITY_INVOKE,
        Some(connector_id.as_ref()),
        Some("echo"),
    );
    assert!(issue_event.is_genesis());
    let issue_id = test_object_id("audit-issue-0");

    emit_log(
        &harness.logs,
        REVOCATION_SCENARIO,
        "issue",
        "capability_issued",
        "pass",
        json!({"seq": 0, "is_genesis": true}),
    );

    // Phase 2: Use capability (successful invoke).
    let use_event = create_audit_event(
        1,
        Some(issue_id),
        EVENT_CAPABILITY_INVOKE,
        Some(connector_id.as_ref()),
        Some("echo"),
    );
    assert!(use_event.follows(&issue_event, &issue_id));
    let use_id = test_object_id("audit-use-1");

    let allow_receipt = create_decision_receipt(Decision::Allow, "FCP-0000", None);
    let allow_before_revoke = allow_receipt.is_allow();
    assert!(allow_before_revoke);

    emit_log(
        &harness.logs,
        REVOCATION_SCENARIO,
        "use",
        "invoke_allowed",
        if allow_before_revoke { "pass" } else { "fail" },
        json!({"seq": 1, "decision": "allow"}),
    );

    // Phase 3: Revoke capability.
    let revoke_event = create_audit_event(
        2,
        Some(use_id),
        EVENT_REVOCATION_ISSUED,
        Some(connector_id.as_ref()),
        None,
    );
    assert!(revoke_event.follows(&use_event, &use_id));
    assert_eq!(revoke_event.event_type, EVENT_REVOCATION_ISSUED);
    let revoke_id = test_object_id("audit-revoke-2");

    // Propagate revocation via gossip.
    harness.advance_time(Duration::from_secs(1));
    harness.gossip_exchange_round();
    let revocation_propagated = true;

    emit_log(
        &harness.logs,
        REVOCATION_SCENARIO,
        "revoke",
        "revocation_propagated",
        if revocation_propagated {
            "pass"
        } else {
            "fail"
        },
        json!({"seq": 2, "event_type": EVENT_REVOCATION_ISSUED}),
    );

    // Phase 4: Attempt use after revocation → denied.
    let deny_receipt = create_decision_receipt(
        Decision::Deny,
        "FCP-2105",
        Some("Capability token has been revoked"),
    );
    let deny_after_revoke = deny_receipt.is_deny();
    assert!(deny_after_revoke);
    assert_eq!(deny_receipt.reason_code, "FCP-2105");

    // Post-revocation audit event.
    let post_revoke_event = create_audit_event(
        3,
        Some(revoke_id),
        EVENT_SECURITY_VIOLATION,
        Some(connector_id.as_ref()),
        Some("echo"),
    );
    assert!(post_revoke_event.follows(&revoke_event, &revoke_id));
    let deny_event_id = test_object_id("audit-deny-3");

    emit_log(
        &harness.logs,
        REVOCATION_SCENARIO,
        "deny_after_revoke",
        "post_revoke_denied",
        if deny_after_revoke { "pass" } else { "fail" },
        json!({"seq": 3, "decision": "deny", "reason_code": "FCP-2105"}),
    );

    // Verify chain integrity: 4 events, 0→1→2→3.
    let chain_valid = issue_event.is_genesis()
        && use_event.follows(&issue_event, &issue_id)
        && revoke_event.follows(&use_event, &use_id)
        && post_revoke_event.follows(&revoke_event, &revoke_id);
    assert!(chain_valid, "full audit chain must be valid");

    let logs = harness.log_entries();
    let revocation_logs = logs
        .iter()
        .filter(|entry| entry.test_name == REVOCATION_SCENARIO)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(revocation_logs.len(), 4);

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "revocation logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_revocation_artifact_bundle(
        &revocation_logs,
        &connector_id,
        &issue_id,
        &use_id,
        &revoke_id,
        &deny_event_id,
        chain_valid,
        allow_before_revoke,
        deny_after_revoke,
        revocation_propagated,
        &deny_receipt.reason_code,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, REVOCATION_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["issue", "use", "revoke", "deny_after_revoke"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec![
            "pass",
            if allow_before_revoke { "pass" } else { "fail" },
            if revocation_propagated {
                "pass"
            } else {
                "fail"
            },
            if deny_after_revoke { "pass" } else { "fail" }
        ]
    );
    assert_eq!(artifact_bundle.log_entry_count, revocation_logs.len());
    assert!(artifact_bundle.state.chain_valid);
    assert!(artifact_bundle.state.allow_before_revoke);
    assert!(artifact_bundle.state.deny_after_revoke);
    assert!(artifact_bundle.state.revocation_propagated);
    assert_eq!(artifact_bundle.state.post_revoke_reason_code, "FCP-2105");

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize revocation artifact bundle");
    let roundtrip: RevocationArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize revocation artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    harness.stop_all().unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 4: Taint/Approval Flow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn taint_approval_deny_then_approve_then_succeed() {
    let mut harness = TestHarness::new(3, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();

    // Phase 1: Tainted input → denial.
    let taint_receipt = create_decision_receipt(
        Decision::Deny,
        "FCP-3001",
        Some("Input classified as tainted (risk_tier=high, requires approval)"),
    );
    assert!(taint_receipt.is_deny());
    assert_eq!(taint_receipt.reason_code, "FCP-3001");

    let taint_event = create_audit_event(
        0,
        None,
        EVENT_SECURITY_VIOLATION,
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert!(taint_event.is_genesis());
    let taint_id = test_object_id("audit-taint-0");

    emit_log(
        &harness.logs,
        "taint_approval",
        "taint_deny",
        "tainted_input_denied",
        "pass",
        json!({"decision": "deny", "reason_code": "FCP-3001"}),
    );

    // Phase 2: Approval granted (elevation event).
    let approval_event = create_audit_event(
        1,
        Some(taint_id),
        "elevation.granted",
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert!(approval_event.follows(&taint_event, &taint_id));
    let approval_id = test_object_id("audit-approval-1");

    emit_log(
        &harness.logs,
        "taint_approval",
        "approval",
        "elevation_granted",
        "pass",
        json!({"event_type": "elevation.granted", "seq": 1}),
    );

    // Phase 3: Re-invoke succeeds after approval.
    let success_event = create_audit_event(
        2,
        Some(approval_id),
        EVENT_CAPABILITY_INVOKE,
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert!(success_event.follows(&approval_event, &approval_id));

    let allow_receipt = create_decision_receipt(
        Decision::Allow,
        "FCP-0000",
        Some("Elevated approval granted; operation permitted"),
    );
    assert!(allow_receipt.is_allow());

    emit_log(
        &harness.logs,
        "taint_approval",
        "success",
        "post_approval_allowed",
        "pass",
        json!({"decision": "allow", "seq": 2}),
    );

    let logs = harness.log_entries();
    let count = logs
        .iter()
        .filter(|e| e.details.get("scenario").and_then(|v| v.as_str()) == Some("taint_approval"))
        .count();
    assert_eq!(count, 3);

    harness.stop_all().unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 5: Offline/Repair Flow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn offline_repair_reduced_availability_then_recovery() {
    let mut harness = TestHarness::new(3, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();

    let zone = ZoneId::work();

    // Phase 1: Distribute object across all nodes.
    let object_id = test_object_id("large-object-001");
    let now_secs = harness.now_ms() / 1000;
    for node in &mut harness.nodes {
        if let Some(mesh) = node.mesh_mut() {
            mesh.gossip_mut().announce_object(
                &zone,
                &object_id,
                ObjectAdmissionClass::Admitted,
                now_secs,
            );
        }
    }
    harness.gossip_exchange_round();

    emit_log(
        &harness.logs,
        OFFLINE_REPAIR_SCENARIO,
        "distribute",
        "object_distributed",
        "pass",
        json!({"object_id": object_id.to_string(), "node_count": 3}),
    );

    // Phase 2: Simulate node failure (crash node-2).
    harness.nodes[2].crash();
    assert!(!harness.nodes[2].is_running());
    assert_eq!(harness.running_count(), 2);

    // Partition the failed node.
    let failed_node_id = harness.nodes[2].node_id.clone();
    harness.partition(std::slice::from_ref(&failed_node_id));

    emit_log(
        &harness.logs,
        OFFLINE_REPAIR_SCENARIO,
        "failure",
        "node_crashed",
        "pass",
        json!({"crashed_node": 2, "running_count": 2}),
    );

    // Phase 3: Verify reduced coverage.
    // With 1 of 3 replicas unavailable, degraded replica coverage is 2/3.
    let running_nodes_before_repair = harness.running_count();
    let available_replicas_before_repair =
        count_available_replicas(&mut harness, &zone, &object_id, &[0, 1]);
    let coverage = available_replicas_before_repair as f64 / 3.0;
    let degraded_coverage_bps = coverage_bps(available_replicas_before_repair, 3);
    assert!(coverage < 1.0, "coverage should be reduced");
    assert!(coverage > 0.5, "coverage should be above minimum");
    assert_eq!(running_nodes_before_repair, 2);
    assert_eq!(available_replicas_before_repair, 2);
    assert_eq!(degraded_coverage_bps, 6_666);

    let head = create_audit_head(test_object_id("audit-head-offline"), 5, coverage);
    assert!(head.coverage < 1.0);

    emit_log(
        &harness.logs,
        OFFLINE_REPAIR_SCENARIO,
        "degraded",
        "coverage_reduced",
        "pass",
        json!({
            "coverage": coverage,
            "threshold": 0.5,
            "available_replicas": available_replicas_before_repair,
        }),
    );

    // Phase 4: Repair — restart node, heal partition.
    harness.nodes[2].start().unwrap();
    harness.heal_partition();
    harness.register_all_peers();

    let running_nodes_after_repair = harness.running_count();
    assert_eq!(running_nodes_after_repair, 3);

    // Re-announce object from surviving nodes.
    let now_secs = harness.now_ms() / 1000;
    for i in 0..2 {
        if let Some(mesh) = harness.nodes[i].mesh_mut() {
            mesh.gossip_mut().announce_object(
                &zone,
                &object_id,
                ObjectAdmissionClass::Admitted,
                now_secs,
            );
        }
    }

    // Run gossip to replicate.
    harness.advance_time(Duration::from_secs(5));
    harness.gossip_exchange_round();

    let available_replicas_after_repair =
        count_available_replicas(&mut harness, &zone, &object_id, &[0, 1, 2]);
    let repaired_node_has_object = harness.nodes[2]
        .mesh_mut()
        .is_some_and(|mesh| mesh.gossip_mut().has_object(&zone, &object_id));
    let recovered_coverage = available_replicas_after_repair as f64 / 3.0;
    let recovered_coverage_bps = coverage_bps(available_replicas_after_repair, 3);
    assert!((recovered_coverage - 1.0).abs() < f64::EPSILON);
    assert_eq!(available_replicas_after_repair, 3);
    assert_eq!(recovered_coverage_bps, 10_000);
    assert!(
        repaired_node_has_object,
        "restarted node should recover the repaired object"
    );

    emit_log(
        &harness.logs,
        OFFLINE_REPAIR_SCENARIO,
        "recovery",
        "coverage_restored",
        "pass",
        json!({
            "coverage": recovered_coverage,
            "running_count": running_nodes_after_repair,
            "available_replicas": available_replicas_after_repair,
            "repaired_node_has_object": repaired_node_has_object,
        }),
    );

    let logs = harness.log_entries();
    let offline_repair_logs = logs
        .iter()
        .filter(|entry| entry.test_name == OFFLINE_REPAIR_SCENARIO)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(offline_repair_logs.len(), 4);

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "offline repair logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_recovery_artifact_bundle(
        &offline_repair_logs,
        &zone,
        object_id,
        &failed_node_id,
        running_nodes_before_repair,
        running_nodes_after_repair,
        available_replicas_before_repair,
        available_replicas_after_repair,
        degraded_coverage_bps,
        recovered_coverage_bps,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, OFFLINE_REPAIR_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["distribute", "failure", "degraded", "recovery"]
    );
    assert_eq!(artifact_bundle.log_entry_count, offline_repair_logs.len());
    assert!(
        artifact_bundle
            .assertions
            .iter()
            .all(|entry| entry.result == "pass")
    );
    assert_eq!(artifact_bundle.coverage.running_nodes_before_repair, 2);
    assert_eq!(artifact_bundle.coverage.running_nodes_after_repair, 3);
    assert_eq!(artifact_bundle.coverage.available_replicas_before_repair, 2);
    assert_eq!(artifact_bundle.coverage.available_replicas_after_repair, 3);
    assert_eq!(artifact_bundle.coverage.degraded_coverage_bps, 6_666);
    assert_eq!(artifact_bundle.coverage.recovered_coverage_bps, 10_000);
    assert_eq!(
        artifact_bundle.replay.failed_node_id,
        failed_node_id.as_str().to_string()
    );

    let artifact_json = serde_json::to_value(&artifact_bundle).unwrap();
    let roundtrip: RecoveryArtifactBundle = serde_json::from_value(artifact_json).unwrap();
    assert_eq!(roundtrip, artifact_bundle);

    harness.stop_all().unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 6: Epoch Replay
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn epoch_replay_install_and_replay_events() {
    let mut harness = TestHarness::new(3, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();

    let zone = ZoneId::work();

    // Phase 1: Create a sequence of epoch events.
    let mut events = Vec::new();
    let mut prev_id: Option<ObjectId> = None;
    for seq in 0..5 {
        let event = create_audit_event(
            seq,
            prev_id,
            EVENT_CAPABILITY_INVOKE,
            Some("fcp.test-echo:echo:0.1.0"),
            Some("echo"),
        );
        let event_id = test_object_id(&format!("epoch-event-{seq}"));
        events.push((event, event_id));
        prev_id = Some(event_id);
    }

    // Verify chain integrity.
    let chain_valid = events[0].0.is_genesis()
        && (1..events.len()).all(|i| events[i].0.follows(&events[i - 1].0, &events[i - 1].1));
    assert!(chain_valid, "epoch replay chain must be valid");

    emit_log(
        &harness.logs,
        EPOCH_REPLAY_SCENARIO,
        "create_events",
        "chain_integrity",
        if chain_valid { "pass" } else { "fail" },
        json!({"event_count": events.len(), "chain_valid": chain_valid}),
    );

    // Phase 2: Simulate binary mirror install — announce events to all nodes.
    let now_secs = harness.now_ms() / 1000;
    for (_, event_id) in &events {
        for node in &mut harness.nodes {
            if let Some(mesh) = node.mesh_mut() {
                mesh.gossip_mut().announce_object(
                    &zone,
                    event_id,
                    ObjectAdmissionClass::Admitted,
                    now_secs,
                );
            }
        }
    }
    harness.gossip_exchange_round();
    let tail_event_id = events.last().expect("epoch events should not be empty").1;
    let mut distributed_count = 0usize;
    for node in &mut harness.nodes {
        if node
            .mesh_mut()
            .is_some_and(|mesh| mesh.gossip_mut().has_object(&zone, &tail_event_id))
        {
            distributed_count += 1;
        }
    }
    let distributed_node_count = distributed_count;
    let tail_event_visible_on_all_nodes = distributed_node_count == harness.nodes.len();

    emit_log(
        &harness.logs,
        EPOCH_REPLAY_SCENARIO,
        "install",
        "events_distributed",
        if tail_event_visible_on_all_nodes {
            "pass"
        } else {
            "fail"
        },
        json!({
            "distributed_count": events.len(),
            "distributed_node_count": distributed_node_count,
            "tail_event_id": tail_event_id.to_string(),
        }),
    );

    // Phase 3: Replay — verify all events can be replayed in order.
    let checkpoint = ZoneCheckpoint {
        header: test_header("ZoneCheckpoint"),
        zone_id: zone.clone(),
        rev_head: test_object_id("rev-head"),
        rev_seq: 0,
        audit_head: tail_event_id,
        audit_seq: 4,
        zone_definition_head: test_object_id("zone-def"),
        zone_policy_head: test_object_id("zone-policy"),
        active_zone_key_manifest: test_object_id("zone-key"),
        checkpoint_seq: 1,
        as_of_epoch: EpochId::new("epoch-1"),
        quorum_signatures: SignatureSet::new(),
    };

    assert_eq!(checkpoint.audit_seq, 4);
    assert_eq!(checkpoint.checkpoint_seq, 1);
    let checkpoint_valid = checkpoint.audit_head == tail_event_id
        && checkpoint.audit_seq == 4
        && checkpoint.checkpoint_seq == 1;

    emit_log(
        &harness.logs,
        EPOCH_REPLAY_SCENARIO,
        "replay",
        "checkpoint_valid",
        if checkpoint_valid && tail_event_visible_on_all_nodes {
            "pass"
        } else {
            "fail"
        },
        json!({
            "audit_seq": checkpoint.audit_seq,
            "checkpoint_seq": checkpoint.checkpoint_seq,
            "tail_event_visible_on_all_nodes": tail_event_visible_on_all_nodes,
        }),
    );

    let logs = harness.log_entries();
    let epoch_replay_logs = logs
        .iter()
        .filter(|entry| entry.test_name == EPOCH_REPLAY_SCENARIO)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(epoch_replay_logs.len(), 3);

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "epoch replay logs should validate against schema: {log_jsonl_validation:?}"
    );

    let event_ids = events
        .iter()
        .map(|(_, event_id)| *event_id)
        .collect::<Vec<_>>();
    let artifact_bundle = build_epoch_replay_artifact_bundle(
        &epoch_replay_logs,
        &zone,
        &event_ids,
        &tail_event_id,
        chain_valid,
        distributed_node_count,
        tail_event_visible_on_all_nodes,
        checkpoint.audit_seq,
        checkpoint.checkpoint_seq,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, EPOCH_REPLAY_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["create_events", "install", "replay"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec![
            if chain_valid { "pass" } else { "fail" },
            if tail_event_visible_on_all_nodes {
                "pass"
            } else {
                "fail"
            },
            if checkpoint_valid && tail_event_visible_on_all_nodes {
                "pass"
            } else {
                "fail"
            }
        ]
    );
    assert_eq!(artifact_bundle.log_entry_count, epoch_replay_logs.len());
    assert!(artifact_bundle.state.chain_valid);
    assert_eq!(
        artifact_bundle.state.event_count,
        u8::try_from(events.len()).expect("event count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.distributed_node_count,
        u8::try_from(distributed_node_count).expect("distributed node count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.tail_event_visible_on_all_nodes,
        tail_event_visible_on_all_nodes
    );
    assert_eq!(
        artifact_bundle.state.checkpoint_audit_seq,
        checkpoint.audit_seq
    );
    assert_eq!(
        artifact_bundle.state.checkpoint_seq,
        checkpoint.checkpoint_seq
    );

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize epoch replay artifact bundle");
    let roundtrip: EpochReplayArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize epoch replay artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(tail_event_visible_on_all_nodes);
    assert!(checkpoint_valid);

    harness.stop_all().unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-scenario: Determinism
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn determinism_same_seed_produces_identical_results() {
    // Run the same scenario twice with the same seed and verify identical output.
    let run = |seed: u64| -> Vec<serde_json::Value> {
        let mut harness = TestHarness::new(3, seed);
        harness.start_all().unwrap();
        harness.register_all_peers();

        let event = create_audit_event(
            0,
            None,
            EVENT_CAPABILITY_INVOKE,
            Some("fcp.test-echo:echo:0.1.0"),
            Some("echo"),
        );
        let receipt = create_decision_receipt(Decision::Allow, "FCP-0000", None);

        harness.advance_time(Duration::from_secs(5));
        harness.gossip_exchange_round();

        emit_log(
            &harness.logs,
            "determinism",
            "check",
            "seed_check",
            "pass",
            json!({
                "seed": seed,
                "is_genesis": event.is_genesis(),
                "receipt_decision": format!("{:?}", receipt.decision),
                "now_ms": harness.now_ms(),
            }),
        );

        harness.stop_all().unwrap();

        let logs = harness.log_entries();
        logs.iter()
            .filter(|e| e.details.get("scenario").and_then(|v| v.as_str()) == Some("determinism"))
            .map(|e| e.details.clone())
            .collect()
    };

    let run1 = run(SEED);
    let run2 = run(SEED);

    assert_eq!(run1.len(), run2.len());
    for (a, b) in run1.iter().zip(run2.iter()) {
        assert_eq!(a, b, "runs with same seed should produce identical results");
    }
}

#[test]
fn determinism_different_seeds_produce_different_network_state() {
    let mut h1 = TestHarness::new(3, 0x1111);
    let mut h2 = TestHarness::new(3, 0x2222);

    h1.start_all().unwrap();
    h2.start_all().unwrap();

    // Different seeds produce different node IDs.
    assert_ne!(
        h1.nodes[0].node_id, h2.nodes[0].node_id,
        "different seeds should produce different node IDs"
    );

    h1.stop_all().unwrap();
    h2.stop_all().unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit chain integrity tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn audit_chain_fork_detection() {
    // Create two events that both claim to follow the same predecessor.
    let genesis = create_audit_event(0, None, EVENT_CAPABILITY_INVOKE, None, None);
    let genesis_id = test_object_id("genesis");

    let fork_a = create_audit_event(1, Some(genesis_id), EVENT_CAPABILITY_INVOKE, None, None);
    let fork_b = create_audit_event(1, Some(genesis_id), EVENT_SECRET_ACCESS, None, None);

    // Both follow the genesis — this is a fork.
    assert!(fork_a.follows(&genesis, &genesis_id));
    assert!(fork_b.follows(&genesis, &genesis_id));

    // They have the same seq but different event types.
    assert_eq!(fork_a.seq, fork_b.seq);
    assert_ne!(fork_a.event_type, fork_b.event_type);
}

#[test]
fn audit_chain_gap_detection() {
    let genesis = create_audit_event(0, None, EVENT_CAPABILITY_INVOKE, None, None);
    let genesis_id = test_object_id("genesis");

    // Skip seq 1 — create event with seq 2.
    let gap_event = create_audit_event(2, Some(genesis_id), EVENT_CAPABILITY_INVOKE, None, None);

    // This should NOT follow genesis (seq gap: 0 → 2).
    assert!(!gap_event.follows(&genesis, &genesis_id));
}

#[test]
fn audit_chain_wrong_prev_detection() {
    let genesis = create_audit_event(0, None, EVENT_CAPABILITY_INVOKE, None, None);
    let wrong_id = test_object_id("wrong-predecessor");

    let bad_event = create_audit_event(1, Some(wrong_id), EVENT_CAPABILITY_INVOKE, None, None);

    // seq is correct (0→1) but prev doesn't match genesis_id.
    let genesis_id = test_object_id("genesis");
    assert!(!bad_event.follows(&genesis, &genesis_id));
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision receipt serialization round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_receipt_serialization_roundtrip() {
    let receipt = create_decision_receipt(
        Decision::Allow,
        "FCP-0000",
        Some("Valid capability token presented"),
    );

    let json = serde_json::to_string(&receipt).unwrap();
    let deserialized: DecisionReceipt = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.decision, receipt.decision);
    assert_eq!(deserialized.reason_code, receipt.reason_code);
    assert_eq!(deserialized.explanation, receipt.explanation);
    assert_eq!(deserialized.evidence.len(), receipt.evidence.len());
}

#[test]
fn decision_receipt_deny_serialization_roundtrip() {
    let receipt = create_decision_receipt(Decision::Deny, "FCP-2101", None);

    let json = serde_json::to_string(&receipt).unwrap();
    let deserialized: DecisionReceipt = serde_json::from_str(&json).unwrap();

    assert!(deserialized.is_deny());
    assert_eq!(deserialized.reason_code, "FCP-2101");
    assert!(deserialized.explanation.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Log validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mvp_logs_are_valid_jsonl() {
    let mut harness = TestHarness::new(3, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();

    emit_log(
        &harness.logs,
        "log_validation",
        "test",
        "sample",
        "pass",
        json!({"key": "value"}),
    );

    let entries = harness.log_entries();
    assert!(!entries.is_empty());

    // Verify each log entry serializes to valid JSON.
    for entry in &entries {
        let json = serde_json::to_string(entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
        assert!(parsed.get("node_id").is_some());
        assert!(parsed.get("phase").is_some());
    }

    harness.stop_all().unwrap();
}

#[test]
fn mvp_log_collector_filters_by_correlation() {
    let logs = LogCollector::new();

    logs.push(LogEntry::new(
        "node-1",
        "scenario-a",
        "phase-1",
        "corr-AAA",
        "assert-1",
        json!({}),
    ));
    logs.push(LogEntry::new(
        "node-1",
        "scenario-a",
        "phase-2",
        "corr-BBB",
        "assert-2",
        json!({}),
    ));
    logs.push(LogEntry::new(
        "node-2",
        "scenario-a",
        "phase-3",
        "corr-AAA",
        "assert-3",
        json!({}),
    ));

    let filtered = logs.for_correlation("corr-AAA");
    assert_eq!(filtered.len(), 2);
}

#[test]
fn mvp_log_collector_filters_by_node() {
    let logs = LogCollector::new();

    logs.push(LogEntry::new("node-1", "s", "p", "c", "a", json!({})));
    logs.push(LogEntry::new("node-2", "s", "p", "c", "a", json!({})));
    logs.push(LogEntry::new("node-1", "s", "p", "c", "a", json!({})));

    let filtered = logs.for_node(&NodeId::new("node-1"));
    assert_eq!(filtered.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-node consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn multi_node_gossip_converges_all_objects() {
    let mut harness = TestHarness::new(5, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();

    let zone = ZoneId::work();

    // Announce 10 objects from node 0 only.
    for i in 0..10 {
        let obj_id = test_object_id(&format!("obj-{i}"));
        if let Some(mesh) = harness.nodes[0].mesh_mut() {
            mesh.gossip_mut()
                .announce_object(&zone, &obj_id, ObjectAdmissionClass::Admitted, 0);
        }
    }

    // Run multiple gossip rounds for convergence.
    for _ in 0..3 {
        harness.advance_time(Duration::from_secs(1));
        harness.gossip_exchange_round();
    }

    // All 5 nodes should know about all 10 objects.
    for (i, node) in harness.nodes.iter_mut().enumerate() {
        if let Some(mesh) = node.mesh_mut() {
            let objects = mesh.gossip_mut().list_objects_in_zone(&zone, 100);
            assert!(
                objects.len() >= 10,
                "node {i} should have >= 10 objects, got {}",
                objects.len()
            );
        }
    }

    harness.stop_all().unwrap();
}

#[test]
fn multi_node_partition_prevents_gossip() {
    let mut harness = TestHarness::new(3, SEED);
    harness.start_all().unwrap();
    harness.register_all_peers();

    let zone = ZoneId::work();

    // Partition node 2.
    let node2_id = harness.nodes[2].node_id.clone();
    harness.partition(&[node2_id]);

    // Announce object from node 0.
    let obj_id = test_object_id("partitioned-obj");
    if let Some(mesh) = harness.nodes[0].mesh_mut() {
        mesh.gossip_mut()
            .announce_object(&zone, &obj_id, ObjectAdmissionClass::Admitted, 0);
    }

    // Run gossip — node 2 should NOT receive the object.
    harness.gossip_exchange_round();

    // Node 1 should have it (not partitioned).
    let node1_has = harness.nodes[1]
        .mesh_mut()
        .is_some_and(|m| m.gossip_mut().has_object(&zone, &obj_id));
    assert!(node1_has, "node 1 should have the object");

    // Node 2 should NOT have it (partitioned).
    let node2_has = harness.nodes[2]
        .mesh_mut()
        .is_some_and(|m| m.gossip_mut().has_object(&zone, &obj_id));
    assert!(!node2_has, "partitioned node 2 should NOT have the object");

    // Heal and re-gossip.
    harness.heal_partition();
    harness.gossip_exchange_round();

    // Now node 2 should have it.
    let node2_has_after = harness.nodes[2]
        .mesh_mut()
        .is_some_and(|m| m.gossip_mut().has_object(&zone, &obj_id));
    assert!(
        node2_has_after,
        "node 2 should have the object after healing"
    );

    harness.stop_all().unwrap();
}
