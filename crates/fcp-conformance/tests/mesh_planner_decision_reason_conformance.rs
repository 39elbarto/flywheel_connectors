//! `fcp_mesh::planner` AdjustmentFactor + DecisionReason variant
//! matrix + ScoreAdjustment + CandidateNode struct conformance.
//!
//! `planner_lease_causality_conformance.rs` already exercises
//! ExecutionPlanner end-to-end with these types, but the FULL
//! variant matrix (especially DecisionReason's 9 variants and
//! their payloads) is not pinned. These types appear directly in
//! the audit/triage output every operator inspects when a planner
//! decision needs explaining.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`AdjustmentFactor` 5 variants** — `Connector`,
//!    `DataLocality`, `LeaseConstraint`, `ZoneRestriction`,
//!    `Custom(String)`. Hash + PartialEq for HashMap keying in
//!    score-aggregation paths.
//! 2. **`DecisionReason` 9 variants** with their documented
//!    payloads (the audit-trail explanations).
//! 3. **`ScoreAdjustment`** 3-field construction (factor, delta,
//!    explanation).
//! 4. **`CandidateNode`** 7-field construction (node_id, score,
//!    base_fitness, adjustments, eligible, decision_reasons, zones).
//! 5. PartialEq + Hash semantics for AdjustmentFactor variants
//!    (including Custom payload disambiguation).

use fcp_mesh::{AdjustmentFactor, CandidateNode, DecisionReason, ScoreAdjustment};
use fcp_tailscale::NodeId;

// ─── AdjustmentFactor ──────────────────────────────────────────────

#[test]
fn adjustment_factor_five_variants_are_distinct() {
    let v = [
        AdjustmentFactor::Connector,
        AdjustmentFactor::DataLocality,
        AdjustmentFactor::LeaseConstraint,
        AdjustmentFactor::ZoneRestriction,
        AdjustmentFactor::Custom("x".into()),
    ];
    for (i, a) in v.iter().enumerate() {
        for (j, b) in v.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "AdjustmentFactor variants MUST be distinct");
            }
        }
    }
}

#[test]
fn adjustment_factor_custom_payload_distinguishes_two_customs() {
    let a = AdjustmentFactor::Custom("alpha".into());
    let b = AdjustmentFactor::Custom("alpha".into());
    let c = AdjustmentFactor::Custom("beta".into());
    assert_eq!(a, b);
    assert_ne!(
        a, c,
        "Custom payload difference MUST register on PartialEq"
    );
}

#[test]
fn adjustment_factor_implements_hash_for_hashmap_use() {
    use std::collections::HashMap;
    let mut counts: HashMap<AdjustmentFactor, i64> = HashMap::new();
    *counts.entry(AdjustmentFactor::Connector).or_default() += 1;
    *counts.entry(AdjustmentFactor::Connector).or_default() += 1;
    *counts.entry(AdjustmentFactor::DataLocality).or_default() += 1;
    *counts
        .entry(AdjustmentFactor::Custom("x".into()))
        .or_default() += 1;
    *counts
        .entry(AdjustmentFactor::Custom("x".into()))
        .or_default() += 1;
    assert_eq!(counts.get(&AdjustmentFactor::Connector), Some(&2));
    assert_eq!(counts.get(&AdjustmentFactor::DataLocality), Some(&1));
    assert_eq!(
        counts.get(&AdjustmentFactor::Custom("x".into())),
        Some(&2),
        "Custom payload MUST hash equally for the same inner string"
    );
}

#[test]
fn adjustment_factor_clone_preserves_variant_and_payload() {
    let original = AdjustmentFactor::Custom("alpha".into());
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ─── DecisionReason variant payloads ──────────────────────────────

#[test]
fn decision_reason_selected_as_best_carries_rank() {
    let r = DecisionReason::SelectedAsBest { rank: 1 };
    match r {
        DecisionReason::SelectedAsBest { rank } => assert_eq!(rank, 1),
        other => panic!("expected SelectedAsBest, got {other:?}"),
    }
}

#[test]
fn decision_reason_eligible_not_selected_carries_rank_and_better_count() {
    let r = DecisionReason::EligibleNotSelected {
        rank: 3,
        better_count: 2,
    };
    match r {
        DecisionReason::EligibleNotSelected { rank, better_count } => {
            assert_eq!(rank, 3);
            assert_eq!(better_count, 2);
        }
        other => panic!("expected EligibleNotSelected, got {other:?}"),
    }
}

#[test]
fn decision_reason_missing_connector_carries_connector_id() {
    let r = DecisionReason::MissingConnector {
        connector_id: "github:saas:v1".into(),
    };
    match r {
        DecisionReason::MissingConnector { connector_id } => {
            assert_eq!(connector_id, "github:saas:v1");
        }
        other => panic!("expected MissingConnector, got {other:?}"),
    }
}

#[test]
fn decision_reason_incompatible_version_carries_required_and_installed() {
    let r = DecisionReason::IncompatibleVersion {
        connector_id: "github:saas:v1".into(),
        required: ">=2.0".into(),
        installed: "1.5".into(),
    };
    match r {
        DecisionReason::IncompatibleVersion {
            connector_id,
            required,
            installed,
        } => {
            assert_eq!(connector_id, "github:saas:v1");
            assert_eq!(required, ">=2.0");
            assert_eq!(installed, "1.5");
        }
        other => panic!("expected IncompatibleVersion, got {other:?}"),
    }
}

#[test]
fn decision_reason_lease_conflict_carries_holder_and_purpose() {
    let r = DecisionReason::LeaseConflict {
        holder: NodeId::new("holder-node"),
        lease_purpose: "operation_execution".into(),
    };
    match r {
        DecisionReason::LeaseConflict {
            holder,
            lease_purpose,
        } => {
            assert_eq!(holder.as_str(), "holder-node");
            assert_eq!(lease_purpose, "operation_execution");
        }
        other => panic!("expected LeaseConflict, got {other:?}"),
    }
}

#[test]
fn decision_reason_zone_restriction_carries_zone_and_reason() {
    let r = DecisionReason::ZoneRestriction {
        zone: "z:work".into(),
        reason: "tagged-not-allowed".into(),
    };
    match r {
        DecisionReason::ZoneRestriction { zone, reason } => {
            assert_eq!(zone, "z:work");
            assert_eq!(reason, "tagged-not-allowed");
        }
        other => panic!("expected ZoneRestriction, got {other:?}"),
    }
}

#[test]
fn decision_reason_has_local_data_carries_symbol_count() {
    let r = DecisionReason::HasLocalData { symbol_count: 42 };
    match r {
        DecisionReason::HasLocalData { symbol_count } => {
            assert_eq!(symbol_count, 42);
        }
        other => panic!("expected HasLocalData, got {other:?}"),
    }
}

#[test]
fn decision_reason_missing_required_symbol_carries_symbol_prefix() {
    let r = DecisionReason::MissingRequiredSymbol {
        symbol_prefix: "obj_abc".into(),
    };
    match r {
        DecisionReason::MissingRequiredSymbol { symbol_prefix } => {
            assert_eq!(symbol_prefix, "obj_abc");
        }
        other => panic!("expected MissingRequiredSymbol, got {other:?}"),
    }
}

#[test]
fn decision_reason_custom_carries_string_payload() {
    let r = DecisionReason::Custom("operator-override".into());
    match r {
        DecisionReason::Custom(payload) => assert_eq!(payload, "operator-override"),
        other => panic!("expected Custom, got {other:?}"),
    }
}

#[test]
fn decision_reason_clone_preserves_payloads() {
    // A representative selection — Clone semantics matter for audit
    // log preservation.
    let cases = vec![
        DecisionReason::SelectedAsBest { rank: 0 },
        DecisionReason::EligibleNotSelected {
            rank: 1,
            better_count: 1,
        },
        DecisionReason::Custom("x".into()),
    ];
    for r in cases {
        let cloned = r.clone();
        // PartialEq is NOT derived on DecisionReason — verify via Debug.
        let original_debug = format!("{r:?}");
        let cloned_debug = format!("{cloned:?}");
        assert_eq!(original_debug, cloned_debug);
    }
}

// ─── ScoreAdjustment ──────────────────────────────────────────────

#[test]
fn score_adjustment_construction_preserves_three_fields() {
    let a = ScoreAdjustment {
        factor: AdjustmentFactor::DataLocality,
        delta: 5.0,
        explanation: "has all required symbols".into(),
    };
    assert_eq!(a.factor, AdjustmentFactor::DataLocality);
    assert!((a.delta - 5.0).abs() < f64::EPSILON);
    assert_eq!(a.explanation, "has all required symbols");
}

#[test]
fn score_adjustment_negative_delta_is_a_penalty() {
    // Delta is f64; negative values are penalties (per docstring).
    let a = ScoreAdjustment {
        factor: AdjustmentFactor::ZoneRestriction,
        delta: -10.0,
        explanation: "zone forbidden".into(),
    };
    assert!(a.delta < 0.0, "negative delta MUST mean penalty");
}

// ─── CandidateNode ────────────────────────────────────────────────

#[test]
fn candidate_node_construction_preserves_seven_fields() {
    let node = CandidateNode {
        node_id: NodeId::new("node-x"),
        score: 75.0,
        base_fitness: 100.0,
        adjustments: vec![ScoreAdjustment {
            factor: AdjustmentFactor::Connector,
            delta: -25.0,
            explanation: "connector not installed".into(),
        }],
        eligible: false,
        decision_reasons: vec![DecisionReason::MissingConnector {
            connector_id: "discord:saas:v1".into(),
        }],
        zones: vec![],
    };
    assert_eq!(node.node_id.as_str(), "node-x");
    assert!((node.score - 75.0).abs() < f64::EPSILON);
    assert!((node.base_fitness - 100.0).abs() < f64::EPSILON);
    assert_eq!(node.adjustments.len(), 1);
    assert!(!node.eligible);
    assert_eq!(node.decision_reasons.len(), 1);
    assert!(node.zones.is_empty());
}

#[test]
fn candidate_node_eligible_with_high_score_is_documented_state() {
    // The "good candidate" shape: eligible=true + base score
    // unaltered + SelectedAsBest reason.
    let node = CandidateNode {
        node_id: NodeId::new("good-node"),
        score: 100.0,
        base_fitness: 100.0,
        adjustments: vec![],
        eligible: true,
        decision_reasons: vec![DecisionReason::SelectedAsBest { rank: 1 }],
        zones: vec![],
    };
    assert!(node.eligible);
    assert_eq!(node.adjustments.len(), 0);
    assert_eq!(node.decision_reasons.len(), 1);
}

#[test]
fn candidate_node_clone_preserves_all_fields() {
    let node = CandidateNode {
        node_id: NodeId::new("n"),
        score: 50.0,
        base_fitness: 100.0,
        adjustments: vec![ScoreAdjustment {
            factor: AdjustmentFactor::LeaseConstraint,
            delta: -50.0,
            explanation: "lease held".into(),
        }],
        eligible: false,
        decision_reasons: vec![],
        zones: vec![],
    };
    let cloned = node.clone();
    assert_eq!(cloned.node_id.as_str(), "n");
    assert_eq!(cloned.adjustments.len(), 1);
    assert!(!cloned.eligible);
}
