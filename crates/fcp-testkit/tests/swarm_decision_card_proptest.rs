//! Property tests for the swarm decision-card evidence gate
//! (br-evxvv.6).
//!
//! `SwarmDecisionCard` is the operator-facing replay artifact that
//! every adaptive subsystem (scheduler, placement, backpressure)
//! emits per decision. Operators rely on three load-bearing
//! predicates:
//!
//! - `is_replayable_offline()` — can this card be replayed from a
//!   bundle without hitting a live service?
//! - `safe_to_disable()` — can the adaptive feature be turned off
//!   without losing the audit trail?
//! - `dominant_loss_term()` — which term drove the decision?
//!
//! These predicates are computed from cards built through a
//! type-safe builder that mixes optional pieces (loss terms,
//! evidence pointers, calibration, fallback). The unit tests in
//! `evidence_helpers.rs` cover named scenarios; this proptest file
//! sweeps the input space and pins the predicate contracts so a
//! future builder refactor cannot silently change the predicate
//! semantics that operator dashboards key off.

use std::collections::BTreeMap;

use chrono::Utc;
use fcp_testkit::evidence_helpers::{
    SwarmCalibrationStatus, SwarmDecisionAction, SwarmDecisionCard, SwarmDecisionCounterfactual,
    SwarmDecisionDomain, SwarmDecisionEvidenceKind, SwarmDecisionEvidencePointer,
    SwarmDecisionFallback, SwarmDecisionLossTerm,
};
use proptest::prelude::*;
use serde_json::{Value, json};

fn arb_action() -> impl Strategy<Value = SwarmDecisionAction> {
    prop_oneof![
        Just(SwarmDecisionAction::Admit),
        Just(SwarmDecisionAction::Dispatch),
        Just(SwarmDecisionAction::Delay),
        Just(SwarmDecisionAction::Place),
        Just(SwarmDecisionAction::Throttle),
        Just(SwarmDecisionAction::Shed),
        Just(SwarmDecisionAction::Reject),
        Just(SwarmDecisionAction::Fallback),
    ]
}

fn arb_domain() -> impl Strategy<Value = SwarmDecisionDomain> {
    prop_oneof![
        Just(SwarmDecisionDomain::Scheduler),
        Just(SwarmDecisionDomain::Placement),
        Just(SwarmDecisionDomain::Backpressure),
    ]
}

fn arb_calibration() -> impl Strategy<Value = SwarmCalibrationStatus> {
    prop_oneof![
        Just(SwarmCalibrationStatus::NotRequired),
        Just(SwarmCalibrationStatus::Valid),
        Just(SwarmCalibrationStatus::DriftDetected),
        Just(SwarmCalibrationStatus::MissingTelemetry),
        Just(SwarmCalibrationStatus::ReplayMismatch),
    ]
}

fn arb_loss_term() -> impl Strategy<Value = SwarmDecisionLossTerm> {
    (
        "[a-z_]{1,16}",
        any::<i32>(),
        any::<i32>(),
        prop_oneof![
            Just("ns".to_string()),
            Just("count".to_string()),
            Just("bytes".to_string()),
            Just("violations".to_string()),
        ],
    )
        .prop_map(|(name, value, weight, unit)| {
            SwarmDecisionLossTerm::new(name, i64::from(value), i64::from(weight), unit)
        })
}

fn arb_evidence_pointer() -> impl Strategy<Value = SwarmDecisionEvidencePointer> {
    prop_oneof![
        ("[a-z0-9_./#-]{1,32}").prop_map(SwarmDecisionEvidencePointer::inline_summary),
        ("[a-z0-9_./#-]{1,32}", "[a-f0-9]{8,16}", any::<bool>()).prop_map(
            |(handle, digest, redacted)| SwarmDecisionEvidencePointer::bundle_artifact(
                handle, digest, redacted,
            )
        ),
        ("[a-z0-9_./:-]{1,32}").prop_map(SwarmDecisionEvidencePointer::live_service),
    ]
}

fn arb_fallback() -> impl Strategy<Value = SwarmDecisionFallback> {
    prop_oneof![
        arb_action().prop_map(SwarmDecisionFallback::available),
        (arb_action(), "[a-z _]{1,32}")
            .prop_map(|(action, reason)| SwarmDecisionFallback::active(action, reason)),
    ]
}

fn arb_counterfactual() -> impl Strategy<Value = SwarmDecisionCounterfactual> {
    (arb_action(), any::<i32>(), "[a-z _]{1,32}").prop_map(|(action, score, reason)| {
        SwarmDecisionCounterfactual::new(action, i64::from(score), reason)
    })
}

fn arb_replay_inputs() -> impl Strategy<Value = BTreeMap<String, Value>> {
    proptest::collection::btree_map("[a-z_]{1,12}", any::<i32>(), 0..6)
        .prop_map(|m| m.into_iter().map(|(k, v)| (k, json!(v))).collect())
}

fn arb_card() -> impl Strategy<Value = SwarmDecisionCard> {
    (
        "[a-z0-9-]{4,16}",
        arb_domain(),
        "[a-z:0-9_.-]{1,32}",
        "[a-z_]{1,32}",
        arb_action(),
        any::<i32>(),
        arb_fallback(),
        arb_calibration(),
        proptest::collection::vec(arb_loss_term(), 0..6),
        proptest::collection::vec(arb_evidence_pointer(), 0..6),
        arb_replay_inputs(),
        proptest::option::of(arb_counterfactual()),
    )
        .prop_map(
            |(
                card_id,
                domain,
                subject,
                state,
                action,
                score,
                fallback,
                calibration,
                loss_terms,
                evidence_pointers,
                replay_inputs,
                counterfactual,
            )| {
                let mut card = SwarmDecisionCard::new(
                    card_id,
                    domain,
                    subject,
                    state,
                    action,
                    i64::from(score),
                    fallback,
                )
                .with_loss_terms(loss_terms)
                .with_calibration(calibration)
                .with_evidence_pointers(evidence_pointers)
                .with_replay_inputs(replay_inputs);
                if let Some(cf) = counterfactual {
                    card = card.with_counterfactual(cf);
                }
                card
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// is_replayable_offline ↔ (replay_inputs non-empty AND no
    /// live-service evidence pointer). Pin the contract so a future
    /// refactor cannot silently change which cards count as
    /// replayable. Operators key alerting off this predicate; a
    /// silent semantics change would either spam or silence them.
    #[test]
    fn prop_is_replayable_offline_matches_documented_contract(card in arb_card()) {
        let has_replay_inputs = !card.replay_inputs.is_empty();
        let has_live_pointer = card
            .evidence_pointers
            .iter()
            .any(|p| p.kind == SwarmDecisionEvidenceKind::LiveService);
        let expected = has_replay_inputs && !has_live_pointer;
        prop_assert_eq!(
            card.is_replayable_offline(),
            expected,
            "is_replayable_offline contract drift: replay_inputs_empty={} \
             has_live_pointer={} predicate={}",
            !has_replay_inputs,
            has_live_pointer,
            card.is_replayable_offline(),
        );
    }

    /// safe_to_disable IMPLIES is_replayable_offline. A card you
    /// can safely disable adaptive behaviour for must always carry
    /// enough evidence to replay the decision offline — otherwise
    /// disabling the feature loses the audit trail.
    #[test]
    fn prop_safe_to_disable_implies_replayable_offline(card in arb_card()) {
        if card.safe_to_disable() {
            prop_assert!(
                card.is_replayable_offline(),
                "safe_to_disable=true must imply is_replayable_offline=true \
                 (card_id={}); otherwise disabling the adaptive feature \
                 loses the operator audit trail",
                card.card_id,
            );
        }
    }

    /// safe_to_disable contract: replayable AND (fallback action is
    /// `Fallback`, OR fallback is active, OR calibration requires
    /// fallback). Exercise every clause.
    #[test]
    fn prop_safe_to_disable_matches_documented_contract(card in arb_card()) {
        let has_fallback_signal = card.fallback.action == SwarmDecisionAction::Fallback
            || card.fallback.active
            || card.calibration.requires_fallback();
        let expected = card.is_replayable_offline() && has_fallback_signal;
        prop_assert_eq!(
            card.safe_to_disable(),
            expected,
            "safe_to_disable contract drift: replayable={} has_fallback_signal={} \
             calibration={:?} fallback_active={} fallback_action={:?}",
            card.is_replayable_offline(),
            has_fallback_signal,
            card.calibration,
            card.fallback.active,
            card.fallback.action,
        );
    }

    /// dominant_loss_term selects the term with the largest
    /// weighted_score across the entire term vector. Empty vector
    /// returns None. Multi-tied maxima are tolerated (the API does
    /// not promise a tiebreak), but the returned term MUST achieve
    /// the maximum.
    #[test]
    fn prop_dominant_loss_term_selects_max_weighted_score(card in arb_card()) {
        match card.dominant_loss_term() {
            None => {
                prop_assert!(
                    card.loss_terms.is_empty(),
                    "dominant_loss_term=None requires empty loss_terms",
                );
            }
            Some(dominant) => {
                let max_score = card
                    .loss_terms
                    .iter()
                    .map(|t| t.weighted_score())
                    .max()
                    .expect("non-empty loss_terms must have a max");
                prop_assert_eq!(
                    dominant.weighted_score(),
                    max_score,
                    "dominant_loss_term must achieve max weighted_score",
                );
            }
        }
    }

    /// Every card serde-roundtrips through JSON. Bundle records are
    /// `card.to_jsonl_value()` payloads — operator tooling reads
    /// them back; PartialEq drift would silently break dashboards.
    #[test]
    fn prop_card_serde_roundtrips(card in arb_card()) {
        let json_value = serde_json::to_value(&card)
            .expect("card must serialise");
        let recovered: SwarmDecisionCard = serde_json::from_value(json_value)
            .expect("card must deserialise");
        prop_assert_eq!(card, recovered);
    }

    /// to_jsonl_value record_type/schema_version pinning. The
    /// downstream JSONL ingest pipeline filters records by
    /// `record_type == "swarm_decision_card"`. A typo introduced in
    /// a refactor would silently drop every card from the operator
    /// view.
    #[test]
    fn prop_jsonl_record_envelope_is_stable(card in arb_card()) {
        let record = card.to_jsonl_value().expect("to_jsonl_value must succeed");
        prop_assert_eq!(record["record_type"].as_str(), Some("swarm_decision_card"));
        prop_assert_eq!(
            record["schema_version"].as_str(),
            Some(card.schema_version.as_str()),
        );
        prop_assert!(record["card"].is_object());
    }

    /// requires_fallback maps to exactly the documented variants.
    /// A future refactor that drops one of these from the
    /// `requires_fallback` predicate would silently let drift /
    /// missing telemetry / replay mismatch land as adaptive
    /// decisions instead of conservative fallbacks.
    #[test]
    fn prop_calibration_requires_fallback_matches_documented_set(
        status in arb_calibration(),
    ) {
        let expected = matches!(
            status,
            SwarmCalibrationStatus::DriftDetected
                | SwarmCalibrationStatus::MissingTelemetry
                | SwarmCalibrationStatus::ReplayMismatch,
        );
        prop_assert_eq!(status.requires_fallback(), expected);
    }
}

// ── Targeted regression: builder default state ──────────────────

/// Newly-constructed card has documented defaults: empty loss terms,
/// empty evidence pointers, empty replay inputs, no counterfactual,
/// `NotRequired` calibration. Pin so the builder's initial state
/// cannot silently drift (operator tooling assumes these defaults).
#[test]
fn new_card_defaults_match_documentation() {
    let card = SwarmDecisionCard::new(
        "card-default",
        SwarmDecisionDomain::Scheduler,
        "subject",
        "normal",
        SwarmDecisionAction::Admit,
        0,
        SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
    );

    assert!(card.loss_terms.is_empty());
    assert!(card.evidence_pointers.is_empty());
    assert!(card.replay_inputs.is_empty());
    assert!(card.counterfactual.is_none());
    assert_eq!(card.calibration, SwarmCalibrationStatus::NotRequired);
    assert!(card.scenario_id.is_none());

    // No replay inputs ⇒ not replayable offline.
    assert!(!card.is_replayable_offline());
    assert!(!card.safe_to_disable());

    // created_at populated (non-default).
    assert!(card.created_at <= Utc::now());
}

/// br-evxvv.6: even with replay inputs set, a single `LiveService`
/// pointer flips the card to non-replayable. Operator dashboards
/// rely on this — a card containing a live URL must not be marked
/// "safe to disable" because the live source could disappear.
#[test]
fn single_live_service_pointer_kills_replayability() {
    let mut replay_inputs = BTreeMap::new();
    replay_inputs.insert("retry_after_ms".to_string(), json!(250));

    let card = SwarmDecisionCard::new(
        "card-mixed",
        SwarmDecisionDomain::Backpressure,
        "connector:stripe",
        "downstream_throttled",
        SwarmDecisionAction::Throttle,
        25,
        SwarmDecisionFallback::active(SwarmDecisionAction::Fallback, "downstream throttled"),
    )
    .with_calibration(SwarmCalibrationStatus::DriftDetected)
    .with_replay_inputs(replay_inputs)
    .with_evidence_pointers(vec![
        SwarmDecisionEvidencePointer::bundle_artifact("samples.jsonl", "blake3:abc", true),
        SwarmDecisionEvidencePointer::live_service("https://live-host.example/status"),
    ]);

    assert!(
        !card.is_replayable_offline(),
        "a single live-service pointer must disqualify the card from offline replay \
         (otherwise a card with a dead live URL could falsely report safe_to_disable=true)"
    );
    assert!(!card.safe_to_disable());
}
