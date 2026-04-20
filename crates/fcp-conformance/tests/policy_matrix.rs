//! Differential policy matrix: 3 zones × 3 capabilities.
//!
//! Exercises the `PolicyEngine` across a 3×3 grid of {zone, capability}
//! pairs and asserts the matrix of expected outcomes. Each zone has a
//! distinct `ZonePolicyObject` shape (ceiling vs blocklist vs
//! wide-open), and each capability represents a different safety class.
//! The test proves:
//!
//!   1. `capability_ceiling` gates capabilities not in the ceiling set.
//!   2. `capability_deny` blocklists a capability regardless of ceiling.
//!   3. The same capability can pass in one zone and fail in another.
//!   4. The same zone produces consistent verdicts for the same
//!      capability across repeated evaluations.
//!
//! Spec source: FCP V3 §5 (Zone Policies) — MUST clause that policy
//! evaluation is a function of (zone, principal, capability, provenance).
//! This matrix locks down the zone × capability axes.
//!
//! Pattern: spec-derived test matrix with metamorphic relation
//! (zone-and-capability orthogonality).

use fcp_cbor::SchemaId;
use fcp_core::{
    CapabilityId, ConnectorId, Decision, DecisionReasonCode, NodeId, NodeSignature, ObjectHeader,
    ObjectId, OperationId, PolicyDecisionInput, PolicyEngine, PolicyPattern, PrincipalId,
    Provenance, ProvenanceRecord, SafetyTier, TransportMode, ZoneId, ZonePolicyObject,
    ZoneTransportPolicy,
};
use semver::Version;

/// Three capability families exercised by the matrix. `send_message` and
/// `read_file` are "ordinary" surface area; `spawn_process` stands in
/// for a dangerous capability that many zones want to blocklist.
const CAP_SEND_MESSAGE: &str = "msg.send";
const CAP_READ_FILE: &str = "file.read";
const CAP_SPAWN_PROCESS: &str = "proc.spawn";

fn test_header(zone: &ZoneId) -> ObjectHeader {
    ObjectHeader {
        schema: SchemaId::new("fcp.core", "ZonePolicyObject", Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone.clone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn _test_signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("node-matrix"), [0u8; 64], 1_700_000_000)
}

/// Build a zone policy with the given allow/deny/ceiling configuration.
fn make_policy(
    zone: ZoneId,
    capability_ceiling: Vec<&'static str>,
    capability_deny: Vec<&'static str>,
) -> ZonePolicyObject {
    ZonePolicyObject {
        header: test_header(&zone),
        zone_id: zone,
        principal_allow: vec![PolicyPattern {
            pattern: "user:*".into(),
        }],
        principal_deny: vec![],
        connector_allow: vec![PolicyPattern {
            pattern: "connector:*".into(),
        }],
        connector_deny: vec![],
        capability_allow: vec![],
        capability_deny: capability_deny
            .into_iter()
            .map(|p| PolicyPattern { pattern: p.into() })
            .collect(),
        capability_ceiling: capability_ceiling
            .into_iter()
            .map(CapabilityId::from_static)
            .collect(),
        transport_policy: ZoneTransportPolicy::default(),
        decision_receipts: fcp_core::DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

/// Build a minimal input that varies only on (zone, capability).
fn make_input(zone: ZoneId, capability: &str) -> PolicyDecisionInput<'static> {
    PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"matrix-req"),
        zone_id: zone.clone(),
        principal: PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:matrix"),
        operation_id: OperationId::from_static("op.matrix"),
        capability_id: match capability {
            CAP_SEND_MESSAGE => CapabilityId::from_static(CAP_SEND_MESSAGE),
            CAP_READ_FILE => CapabilityId::from_static(CAP_READ_FILE),
            CAP_SPAWN_PROCESS => CapabilityId::from_static(CAP_SPAWN_PROCESS),
            _ => panic!("unknown capability: {capability}"),
        },
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(zone),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    }
}

/// Three-policy corpus for the matrix.
fn zone_policies() -> [(ZoneId, PolicyEngine); 3] {
    // private: strict ceiling — only read_file + send_message allowed;
    //          spawn_process is outside the ceiling → CapabilityInsufficient
    let private_policy = make_policy(
        ZoneId::private(),
        vec![CAP_READ_FILE, CAP_SEND_MESSAGE],
        vec![],
    );

    // work: open ceiling — all three capabilities allowed.
    let work_policy = make_policy(
        ZoneId::work(),
        vec![CAP_READ_FILE, CAP_SEND_MESSAGE, CAP_SPAWN_PROCESS],
        vec![],
    );

    // community: explicit blocklist on spawn_process — no ceiling.
    let community_policy = make_policy(ZoneId::community(), vec![], vec![CAP_SPAWN_PROCESS]);

    [
        (
            ZoneId::private(),
            PolicyEngine {
                zone_policy: private_policy,
            },
        ),
        (
            ZoneId::work(),
            PolicyEngine {
                zone_policy: work_policy,
            },
        ),
        (
            ZoneId::community(),
            PolicyEngine {
                zone_policy: community_policy,
            },
        ),
    ]
}

/// Lookup expected decision for a (zone, capability) pair.
fn expected(zone: &ZoneId, capability: &str) -> (Decision, Option<DecisionReasonCode>) {
    match (zone.as_str(), capability) {
        // private: only read_file + send_message are in the ceiling
        ("z:private", CAP_READ_FILE | CAP_SEND_MESSAGE) => (Decision::Allow, None),
        ("z:private", CAP_SPAWN_PROCESS) => (
            Decision::Deny,
            Some(DecisionReasonCode::CapabilityInsufficient),
        ),
        // work: wide-open ceiling
        ("z:work", _) => (Decision::Allow, None),
        // community: spawn_process is blocklisted
        ("z:community", CAP_SPAWN_PROCESS) => (
            Decision::Deny,
            Some(DecisionReasonCode::ZonePolicyCapabilityDenied),
        ),
        ("z:community", _) => (Decision::Allow, None),
        _ => panic!("unknown (zone, capability): ({zone:?}, {capability})"),
    }
}

// ── Matrix tests ────────────────────────────────────────────

/// Full 9-cell grid — the canonical conformance matrix.
#[test]
fn policy_matrix_zones_times_capabilities() {
    let capabilities = [CAP_READ_FILE, CAP_SEND_MESSAGE, CAP_SPAWN_PROCESS];
    let mut report: Vec<(String, String, String, String)> = Vec::new();

    for (zone, engine) in zone_policies() {
        for cap in capabilities {
            let input = make_input(zone.clone(), cap);
            let decision = engine.evaluate_invoke(&input);
            let (exp_decision, exp_reason) = expected(&zone, cap);
            assert_eq!(
                decision.decision, exp_decision,
                "matrix[{zone:?}, {cap}] decision mismatch: got {decision:?}, expected {exp_decision:?}",
            );
            if let Some(reason) = exp_reason {
                assert_eq!(
                    decision.reason_code, reason,
                    "matrix[{zone:?}, {cap}] reason mismatch",
                );
            }
            report.push((
                zone.as_str().to_owned(),
                cap.to_owned(),
                format!("{:?}", decision.decision),
                decision.reason_code.as_str().to_owned(),
            ));
        }
    }

    // Emit the matrix as structured output for CI consumption.
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "module": "policy_matrix",
            "event": "matrix_evaluated",
            "cells": report.iter().map(|(z, c, d, r)| serde_json::json!({
                "zone": z, "capability": c, "decision": d, "reason": r,
            })).collect::<Vec<_>>(),
        }))
        .unwrap_or_default()
    );
}

/// Metamorphic: the matrix is stable — re-evaluating every cell yields
/// the same (decision, reason) pair. Catches hidden mutation/ordering
/// bugs in policy evaluation.
#[test]
fn policy_matrix_is_deterministic_across_invocations() {
    let capabilities = [CAP_READ_FILE, CAP_SEND_MESSAGE, CAP_SPAWN_PROCESS];
    for (zone, engine) in zone_policies() {
        for cap in capabilities {
            let input_1 = make_input(zone.clone(), cap);
            let input_2 = make_input(zone.clone(), cap);
            let d1 = engine.evaluate_invoke(&input_1);
            let d2 = engine.evaluate_invoke(&input_2);
            assert_eq!(d1.decision, d2.decision);
            assert_eq!(d1.reason_code, d2.reason_code);
        }
    }
}

/// Orthogonality check: changing zone (capability fixed) or changing
/// capability (zone fixed) changes the decision for at least one pair.
/// This guards against a silent regression where policy evaluation
/// becomes independent of one of its inputs.
#[test]
fn policy_matrix_depends_on_both_axes() {
    // Same capability, different zone must disagree for at least one cap.
    let mut zone_axis_varies = false;
    let capabilities = [CAP_READ_FILE, CAP_SEND_MESSAGE, CAP_SPAWN_PROCESS];
    let policies = zone_policies();
    for cap in capabilities {
        let decisions: Vec<_> = policies
            .iter()
            .map(|(zone, engine)| engine.evaluate_invoke(&make_input(zone.clone(), cap)).decision)
            .collect();
        if decisions.windows(2).any(|w| w[0] != w[1]) {
            zone_axis_varies = true;
            break;
        }
    }
    assert!(
        zone_axis_varies,
        "zone axis does not influence decisions — policy is zone-blind"
    );

    // Same zone, different capability must disagree for at least one zone.
    let mut cap_axis_varies = false;
    for (zone, engine) in &policies {
        let decisions: Vec<_> = capabilities
            .iter()
            .map(|cap| engine.evaluate_invoke(&make_input(zone.clone(), cap)).decision)
            .collect();
        if decisions.windows(2).any(|w| w[0] != w[1]) {
            cap_axis_varies = true;
            break;
        }
    }
    assert!(
        cap_axis_varies,
        "capability axis does not influence decisions — policy is capability-blind"
    );
}

/// Soundness: when the matrix denies, it ALWAYS produces a stable,
/// non-empty reason code. A deny with empty reason would be an
/// explainability regression (FCP V3 §5.5 decision receipts MUST carry
/// a reason code).
#[test]
fn policy_matrix_deny_decisions_have_stable_reason_codes() {
    let capabilities = [CAP_READ_FILE, CAP_SEND_MESSAGE, CAP_SPAWN_PROCESS];
    for (zone, engine) in zone_policies() {
        for cap in capabilities {
            let decision = engine.evaluate_invoke(&make_input(zone.clone(), cap));
            if matches!(decision.decision, Decision::Deny) {
                let reason = decision.reason_code.as_str();
                assert!(
                    !reason.is_empty(),
                    "deny decision at ({zone:?}, {cap}) MUST carry a non-empty reason code"
                );
                assert!(
                    reason.contains('.'),
                    "reason code {reason:?} should be a dotted identifier"
                );
            }
        }
    }
}
