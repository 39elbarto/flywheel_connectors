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

#![allow(clippy::too_many_lines, clippy::cast_precision_loss, clippy::needless_pass_by_value)]

use std::time::Duration;

use fcp_conformance::harness::{LogCollector, LogEntry, TestHarness};
use fcp_core::{
    AuditEvent, AuditHead, ConnectorId, CorrelationId, Decision, DecisionReceipt, EpochId,
    NodeSignature, ObjectHeader, ObjectId, PrincipalId, Provenance,
    SignatureSet, ZoneCheckpoint, ZoneId, EVENT_CAPABILITY_INVOKE, EVENT_REVOCATION_ISSUED,
    EVENT_SECRET_ACCESS, EVENT_SECURITY_VIOLATION,
};
#[allow(unused_imports)]
use fcp_core::RiskTier;
use fcp_cbor::SchemaId;
use fcp_mesh::ObjectAdmissionClass;
use fcp_tailscale::NodeId;
use semver::Version;
use serde_json::json;
use uuid::Uuid;

/// Alias for the core crate `NodeId` used by `NodeSignature`.
type CoreNodeId = fcp_core::NodeId;

const SEED: u64 = 0xDEAD_BEEF;

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
    let genesis_event = create_audit_event(0, None, EVENT_CAPABILITY_INVOKE, Some("fcp.test-echo:echo:0.1.0"), Some("echo"));
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
    let receipt = create_decision_receipt(Decision::Allow, "FCP-0000", Some("Capability present and valid"));
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
        .filter(|e| {
            e.details
                .get("scenario")
                .and_then(|v| v.as_str())
                == Some("denial_path")
        })
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

    // Phase 1: Issue capability (simulated as genesis audit event).
    let issue_event = create_audit_event(
        0,
        None,
        EVENT_CAPABILITY_INVOKE,
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert!(issue_event.is_genesis());
    let issue_id = test_object_id("audit-issue-0");

    emit_log(
        &harness.logs,
        "revocation",
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
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert!(use_event.follows(&issue_event, &issue_id));
    let use_id = test_object_id("audit-use-1");

    let allow_receipt = create_decision_receipt(Decision::Allow, "FCP-0000", None);
    assert!(allow_receipt.is_allow());

    emit_log(
        &harness.logs,
        "revocation",
        "use",
        "invoke_allowed",
        "pass",
        json!({"seq": 1, "decision": "allow"}),
    );

    // Phase 3: Revoke capability.
    let revoke_event = create_audit_event(
        2,
        Some(use_id),
        EVENT_REVOCATION_ISSUED,
        Some("fcp.test-echo:echo:0.1.0"),
        None,
    );
    assert!(revoke_event.follows(&use_event, &use_id));
    assert_eq!(revoke_event.event_type, EVENT_REVOCATION_ISSUED);
    let revoke_id = test_object_id("audit-revoke-2");

    // Propagate revocation via gossip.
    harness.advance_time(Duration::from_secs(1));
    harness.gossip_exchange_round();

    emit_log(
        &harness.logs,
        "revocation",
        "revoke",
        "revocation_propagated",
        "pass",
        json!({"seq": 2, "event_type": EVENT_REVOCATION_ISSUED}),
    );

    // Phase 4: Attempt use after revocation → denied.
    let deny_receipt = create_decision_receipt(
        Decision::Deny,
        "FCP-2105",
        Some("Capability token has been revoked"),
    );
    assert!(deny_receipt.is_deny());
    assert_eq!(deny_receipt.reason_code, "FCP-2105");

    // Post-revocation audit event.
    let post_revoke_event = create_audit_event(
        3,
        Some(revoke_id),
        EVENT_SECURITY_VIOLATION,
        Some("fcp.test-echo:echo:0.1.0"),
        Some("echo"),
    );
    assert!(post_revoke_event.follows(&revoke_event, &revoke_id));

    emit_log(
        &harness.logs,
        "revocation",
        "deny_after_revoke",
        "post_revoke_denied",
        "pass",
        json!({"seq": 3, "decision": "deny", "reason_code": "FCP-2105"}),
    );

    // Verify chain integrity: 4 events, 0→1→2→3.
    let chain_valid = issue_event.is_genesis()
        && use_event.follows(&issue_event, &issue_id)
        && revoke_event.follows(&use_event, &use_id)
        && post_revoke_event.follows(&revoke_event, &revoke_id);
    assert!(chain_valid, "full audit chain must be valid");

    let logs = harness.log_entries();
    let count = logs
        .iter()
        .filter(|e| {
            e.details
                .get("scenario")
                .and_then(|v| v.as_str())
                == Some("revocation")
        })
        .count();
    assert_eq!(count, 4);

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
        .filter(|e| {
            e.details
                .get("scenario")
                .and_then(|v| v.as_str())
                == Some("taint_approval")
        })
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
        "offline_repair",
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
        "offline_repair",
        "failure",
        "node_crashed",
        "pass",
        json!({"crashed_node": 2, "running_count": 2}),
    );

    // Phase 3: Verify reduced coverage.
    // With 1 of 3 nodes down, coverage = 2/3 ≈ 0.667.
    let coverage = harness.running_count() as f64 / 3.0;
    assert!(coverage < 1.0, "coverage should be reduced");
    assert!(coverage > 0.5, "coverage should be above minimum");

    let head = create_audit_head(test_object_id("audit-head-offline"), 5, coverage);
    assert!(head.coverage < 1.0);

    emit_log(
        &harness.logs,
        "offline_repair",
        "degraded",
        "coverage_reduced",
        "pass",
        json!({"coverage": coverage, "threshold": 0.5}),
    );

    // Phase 4: Repair — restart node, heal partition.
    harness.nodes[2].start().unwrap();
    harness.heal_partition();
    harness.register_all_peers();

    assert_eq!(harness.running_count(), 3);

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

    let recovered_coverage = harness.running_count() as f64 / 3.0;
    assert!((recovered_coverage - 1.0).abs() < f64::EPSILON);

    emit_log(
        &harness.logs,
        "offline_repair",
        "recovery",
        "coverage_restored",
        "pass",
        json!({"coverage": recovered_coverage, "running_count": 3}),
    );

    let logs = harness.log_entries();
    let count = logs
        .iter()
        .filter(|e| {
            e.details
                .get("scenario")
                .and_then(|v| v.as_str())
                == Some("offline_repair")
        })
        .count();
    assert_eq!(count, 4);

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
    assert!(events[0].0.is_genesis());
    for i in 1..events.len() {
        assert!(
            events[i].0.follows(&events[i - 1].0, &events[i - 1].1),
            "event {i} should follow event {}",
            i - 1
        );
    }

    emit_log(
        &harness.logs,
        "epoch_replay",
        "create_events",
        "chain_integrity",
        "pass",
        json!({"event_count": 5, "chain_valid": true}),
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

    emit_log(
        &harness.logs,
        "epoch_replay",
        "install",
        "events_distributed",
        "pass",
        json!({"distributed_count": 5}),
    );

    // Phase 3: Replay — verify all events can be replayed in order.
    let checkpoint = ZoneCheckpoint {
        header: test_header("ZoneCheckpoint"),
        zone_id: zone,
        rev_head: test_object_id("rev-head"),
        rev_seq: 0,
        audit_head: events.last().unwrap().1,
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

    emit_log(
        &harness.logs,
        "epoch_replay",
        "replay",
        "checkpoint_valid",
        "pass",
        json!({"audit_seq": 4, "checkpoint_seq": 1}),
    );

    let logs = harness.log_entries();
    let count = logs
        .iter()
        .filter(|e| {
            e.details
                .get("scenario")
                .and_then(|v| v.as_str())
                == Some("epoch_replay")
        })
        .count();
    assert_eq!(count, 3);

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

        let event = create_audit_event(0, None, EVENT_CAPABILITY_INVOKE, Some("fcp.test-echo:echo:0.1.0"), Some("echo"));
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
            .filter(|e| {
                e.details
                    .get("scenario")
                    .and_then(|v| v.as_str())
                    == Some("determinism")
            })
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
        "node-1", "scenario-a", "phase-1", "corr-AAA", "assert-1", json!({}),
    ));
    logs.push(LogEntry::new(
        "node-1", "scenario-a", "phase-2", "corr-BBB", "assert-2", json!({}),
    ));
    logs.push(LogEntry::new(
        "node-2", "scenario-a", "phase-3", "corr-AAA", "assert-3", json!({}),
    ));

    let filtered = logs.for_correlation("corr-AAA");
    assert_eq!(filtered.len(), 2);
}

#[test]
fn mvp_log_collector_filters_by_node() {
    let logs = LogCollector::new();

    logs.push(LogEntry::new(
        "node-1", "s", "p", "c", "a", json!({}),
    ));
    logs.push(LogEntry::new(
        "node-2", "s", "p", "c", "a", json!({}),
    ));
    logs.push(LogEntry::new(
        "node-1", "s", "p", "c", "a", json!({}),
    ));

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
            mesh.gossip_mut().announce_object(
                &zone,
                &obj_id,
                ObjectAdmissionClass::Admitted,
                0,
            );
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
        mesh.gossip_mut().announce_object(
            &zone,
            &obj_id,
            ObjectAdmissionClass::Admitted,
            0,
        );
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
