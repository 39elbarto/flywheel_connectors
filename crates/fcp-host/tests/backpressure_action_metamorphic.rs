//! Metamorphic tests for the AdmitWithWarning + Delay backpressure
//! conformance contract (br-817cba87c, fix landed in 966e4f264).
//!
//! The existing conformance harness in `backpressure_action_conformance.rs`
//! pins four named-scenario contracts (action exhaustiveness, decision-card
//! invariants, delay-vs-admit timing, label stability). This file adds
//! three METAMORPHIC RELATIONS that pin properties the named-scenario
//! tests cannot easily cover — properties that hold across the full input
//! space and that catch refactor classes the conformance tests miss.
//!
//! - **MR.subject-string-irrelevance** (Equivalence): the controller's
//!   decision MUST NOT depend on the `subject` string. The subject is
//!   operator-readable metadata, not a routing key. Two decisions with
//!   identical telemetry/priority/calibration but different subjects
//!   MUST be byte-identical except for the subject field itself.
//!   Pre-fix concern: a refactor that hashed the subject into the loss
//!   matrix or used it to pick a config branch would break replayability
//!   (audit bundles serialise subjects verbatim).
//!
//! - **MR.priority-shed-monotonicity** (Inclusive): for the SAME
//!   telemetry, `Critical` is never SHED at a workload where `Low` is
//!   admitted. The loss matrix's `dropped_useful_work` term scales by
//!   `priority_factor` (Critical=4, Low=1), so Shed costs more for
//!   higher-priority requests; the propensity to shed must be
//!   monotonically non-increasing in priority. Pre-fix concern: a
//!   refactor that flipped the priority_factor mapping (or zeroed it
//!   for Critical) would let the controller silently shed a Critical
//!   request while admitting a Low one — a fairness inversion that
//!   would be invisible to single-priority unit tests.
//!
//! - **MR.equal-input-determinism-under-permutation** (Permutative on
//!   call sequence): N back-to-back `decide()` calls with structurally
//!   equal inputs MUST yield N structurally equal decisions. The
//!   `aa920f2cc` proptest sweep already pins single-call determinism;
//!   this MR pins the harder property that determinism survives
//!   ordering effects across a SEQUENCE of calls (no leaking interior
//!   mutability accumulating across calls). Pre-fix concern: a
//!   refactor that added a per-controller call counter or warm-cache
//!   would violate replayability mid-flight.

use fcp_host::{
    BackpressureAction, BackpressureCalibration, BackpressureController,
    BackpressureControllerInput, BackpressureTelemetry, RequestPriority,
};
use proptest::prelude::*;

fn arb_priority() -> impl Strategy<Value = RequestPriority> {
    prop_oneof![
        Just(RequestPriority::Critical),
        Just(RequestPriority::High),
        Just(RequestPriority::Normal),
        Just(RequestPriority::Low),
    ]
}

fn arb_per_mille_opt() -> impl Strategy<Value = Option<u16>> {
    prop_oneof![Just(None), (0u16..=1_000).prop_map(Some)]
}

fn arb_telemetry() -> impl Strategy<Value = BackpressureTelemetry> {
    (
        arb_per_mille_opt(),
        arb_per_mille_opt(),
        arb_per_mille_opt(),
        prop_oneof![Just(None), (0u64..=10_000).prop_map(Some)],
        arb_per_mille_opt(),
        arb_per_mille_opt(),
    )
        .prop_map(
            |(queue, cpu, mem, retry_after, retry_amp, useful)| BackpressureTelemetry {
                queue_pressure_per_mille: queue,
                cpu_pressure_per_mille: cpu,
                memory_pressure_per_mille: mem,
                downstream_retry_after_ms: retry_after,
                retry_amplification_per_mille: retry_amp,
                useful_work_per_mille: useful,
            },
        )
}

proptest! {
    /// MR.subject-string-irrelevance: the decision is invariant under
    /// arbitrary changes to the subject label. The subject is opaque
    /// operator metadata; if it ever leaked into the loss matrix or
    /// the calibration branch the audit replay would break (subjects
    /// vary per request, but replays must reproduce the same decision
    /// from the same telemetry+calibration+priority).
    #[test]
    fn mr_subject_string_does_not_affect_decision(
        subject_a in "[a-z0-9._:/-]{1,32}",
        subject_b in "[a-z0-9._:/-]{1,32}",
        priority in arb_priority(),
        telemetry in arb_telemetry(),
    ) {
        let controller = BackpressureController::default();
        let calibration = BackpressureCalibration::valid();

        let decision_a = controller.decide(BackpressureControllerInput::new(
            subject_a.clone(),
            priority,
            telemetry,
            calibration,
        ));
        let decision_b = controller.decide(BackpressureControllerInput::new(
            subject_b.clone(),
            priority,
            telemetry,
            calibration,
        ));

        prop_assert_eq!(
            decision_a.state,
            decision_b.state,
            "br-817cba87c MR.subject-string-irrelevance: state diverged for \
             subjects '{}' vs '{}' under identical telemetry — subject must \
             not leak into the state classification",
            subject_a, subject_b,
        );
        prop_assert_eq!(
            decision_a.action,
            decision_b.action,
            "br-817cba87c MR.subject-string-irrelevance: action diverged for \
             subjects '{}' vs '{}' — subject must not leak into action selection",
            subject_a, subject_b,
        );
        prop_assert_eq!(
            decision_a.selected_loss_score,
            decision_b.selected_loss_score,
            "br-817cba87c MR.subject-string-irrelevance: selected_loss_score \
             diverged for subjects '{}' vs '{}'",
            subject_a, subject_b,
        );
        prop_assert_eq!(
            decision_a.fallback_trigger,
            decision_b.fallback_trigger,
            "br-817cba87c MR.subject-string-irrelevance: fallback_trigger \
             diverged for subjects '{}' vs '{}'",
            subject_a, subject_b,
        );
        // The replay record carries the subject verbatim (it's the only
        // legitimate place subject content matters), so we explicitly
        // do NOT assert decision_a == decision_b — we assert every
        // field the integration reads off matches.
    }

    /// MR.priority-shed-monotonicity: for the same telemetry, the
    /// propensity to shed is monotonically non-increasing in priority.
    /// Specifically: if a Low-priority request is ADMITTED (action ∈
    /// {Admit, AdmitWithWarning, Delay, FallbackStaticPolicy}), then
    /// a Critical-priority request at the SAME telemetry MUST also be
    /// admitted (it has STRICTLY MORE protection per the loss matrix).
    ///
    /// Equivalently: Critical ∈ {Shed, CancelLowPriority} implies
    /// Low ∈ {Shed, CancelLowPriority} at the same telemetry.
    ///
    /// Catches a refactor that flips the priority_factor mapping in
    /// `dropped_useful_work_loss` or zeroes it for Critical.
    #[test]
    fn mr_priority_shed_monotonicity_critical_protected_when_low_admitted(
        telemetry in arb_telemetry(),
    ) {
        let controller = BackpressureController::default();
        let calibration = BackpressureCalibration::valid();

        let low = controller.decide(BackpressureControllerInput::new(
            "subject",
            RequestPriority::Low,
            telemetry,
            calibration,
        ));
        let critical = controller.decide(BackpressureControllerInput::new(
            "subject",
            RequestPriority::Critical,
            telemetry,
            calibration,
        ));

        // The integration considers Shed and CancelLowPriority as the
        // two work-rejection actions; FallbackStaticPolicy is "deferred
        // to static load_shedder" and isn't structurally a shed (it's
        // a hand-off). Treat only Shed/CancelLowPriority as "rejected".
        let low_rejected = matches!(
            low.action,
            BackpressureAction::Shed | BackpressureAction::CancelLowPriority
        );
        let critical_rejected = matches!(
            critical.action,
            BackpressureAction::Shed | BackpressureAction::CancelLowPriority
        );

        if !low_rejected && critical_rejected {
            prop_assert!(
                false,
                "br-817cba87c MR.priority-shed-monotonicity violated: Critical \
                 rejected ({:?}) while Low admitted ({:?}) at telemetry {:?}. \
                 The loss matrix's priority_factor (Critical=4, Low=1) must \
                 keep Critical strictly more protected than Low; an inversion \
                 here would be a fairness regression invisible to single-\
                 priority unit tests.",
                critical.action, low.action, telemetry,
            );
        }
    }

    /// MR.equal-input-determinism-under-permutation: N back-to-back
    /// decide() calls with structurally equal inputs yield N
    /// structurally equal decisions. The aa920f2cc proptest pins
    /// SINGLE-call determinism; this pins SEQUENCE determinism — the
    /// harder property that no per-controller interior mutability
    /// (call counter, warm cache, RNG state) bleeds across calls.
    ///
    /// We make 5 sequential decisions on the same controller with the
    /// same input, in two different orderings (3-then-2 vs 2-then-3),
    /// and assert all 5 decisions are pairwise equal. If any per-call
    /// state leaked, the 4th decision (after the order swap) would
    /// diverge from the others.
    #[test]
    fn mr_decision_invariant_under_call_sequence_permutation(
        priority in arb_priority(),
        telemetry in arb_telemetry(),
    ) {
        let controller = BackpressureController::default();
        let calibration = BackpressureCalibration::valid();
        let input = BackpressureControllerInput::new(
            "subject",
            priority,
            telemetry,
            calibration,
        );

        let mut sequence_a = Vec::with_capacity(5);
        for _ in 0..5 {
            sequence_a.push(controller.decide(input.clone()));
        }

        // Fresh controller — controller is Copy, but use a fresh
        // construction to defeat any hypothetical interior-mut between
        // controller instances.
        let controller_b = BackpressureController::default();
        let mut sequence_b = Vec::with_capacity(5);
        // Different ordering: interleave with one no-op call to vary
        // the call sequence shape.
        for _ in 0..2 {
            sequence_b.push(controller_b.decide(input.clone()));
        }
        let _throwaway = controller_b.decide(input.clone());
        for _ in 0..3 {
            sequence_b.push(controller_b.decide(input.clone()));
        }

        for (i, decision) in sequence_a.iter().enumerate() {
            prop_assert_eq!(
                decision.action, sequence_a[0].action,
                "br-817cba87c MR.sequence-determinism: action drifted across \
                 calls in sequence A at index {}", i,
            );
            prop_assert_eq!(
                decision.state, sequence_a[0].state,
                "sequence A: state drifted at index {}", i,
            );
        }
        for (i, decision) in sequence_b.iter().enumerate() {
            prop_assert_eq!(
                decision.action, sequence_a[0].action,
                "br-817cba87c MR.sequence-determinism: action diverged between \
                 sequence B (index {}, action {:?}) and sequence A (action {:?}) — \
                 decide() is not permutation-invariant across call orderings",
                i, decision.action, sequence_a[0].action,
            );
            prop_assert_eq!(
                decision.selected_loss_score, sequence_a[0].selected_loss_score,
                "sequence B: loss score diverged at index {}", i,
            );
        }
    }
}

/// Smoke floor combining all three MRs at fixed inputs. Catches
/// regressions even if proptest shrinks aggressively past the
/// load-bearing branches.
#[test]
fn mr_backpressure_action_smoke_floor() {
    let controller = BackpressureController::default();
    let valid = BackpressureCalibration::valid();
    let queue_congested = BackpressureTelemetry {
        queue_pressure_per_mille: Some(900),
        cpu_pressure_per_mille: Some(250),
        useful_work_per_mille: Some(800),
        ..BackpressureTelemetry::default()
    };

    // MR.subject: same decision under different subjects.
    let d_a = controller.decide(BackpressureControllerInput::new(
        "subject-a", RequestPriority::Normal, queue_congested, valid,
    ));
    let d_b = controller.decide(BackpressureControllerInput::new(
        "subject-XYZ-123", RequestPriority::Normal, queue_congested, valid,
    ));
    assert_eq!(d_a.action, d_b.action, "smoke: subject must not affect action");
    assert_eq!(d_a.state, d_b.state, "smoke: subject must not affect state");

    // MR.priority-shed: a Low-priority request that's NOT shed implies
    // a Critical-priority request also NOT shed.
    let cpu_pressed = BackpressureTelemetry {
        queue_pressure_per_mille: Some(200),
        cpu_pressure_per_mille: Some(960),
        useful_work_per_mille: Some(700),
        ..BackpressureTelemetry::default()
    };
    let low = controller.decide(BackpressureControllerInput::new(
        "x", RequestPriority::Low, cpu_pressed, valid,
    ));
    let critical = controller.decide(BackpressureControllerInput::new(
        "x", RequestPriority::Critical, cpu_pressed, valid,
    ));
    let low_rejected = matches!(
        low.action,
        BackpressureAction::Shed | BackpressureAction::CancelLowPriority
    );
    let critical_rejected = matches!(
        critical.action,
        BackpressureAction::Shed | BackpressureAction::CancelLowPriority
    );
    assert!(
        !(critical_rejected && !low_rejected),
        "smoke: Critical rejected ({:?}) while Low admitted ({:?}) — fairness inversion",
        critical.action, low.action,
    );

    // MR.sequence-determinism: 4 back-to-back decisions yield identical actions.
    let inp = BackpressureControllerInput::new(
        "smoke", RequestPriority::Normal, queue_congested, valid,
    );
    let d1 = controller.decide(inp.clone());
    let d2 = controller.decide(inp.clone());
    let d3 = controller.decide(inp.clone());
    let d4 = controller.decide(inp);
    assert_eq!(d1.action, d2.action);
    assert_eq!(d2.action, d3.action);
    assert_eq!(d3.action, d4.action);
}
