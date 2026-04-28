#![no_main]

//! Fuzz target for `RevocationSlaChecker` and `RevocationSlaStatus`
//! (revocation.rs:853-898) — the C1.4 zone-wide revocation freshness
//! SLA primitive.
//!
//! `RevocationSlaChecker` compares a `ZoneCheckpoint`'s
//! `revocation_freshness_sla_secs` against the current time to
//! determine whether the zone is in DEGRADED revocation state.
//! `Critical` operations MUST abort when the SLA is breached;
//! `Risky` and `Safe` operations may always proceed.
//!
//! NOT covered as a discrete unit by any existing fuzz target.
//!
//! A regression that:
//!   - flipped the `<=` boundary in `check_sla` would either reject
//!     fresh-at-boundary checkpoints or accept stale-by-1-second ones.
//!   - dropped the saturating subtraction would panic on a clock
//!     skew where `now < checkpoint_updated_at`.
//!   - made `may_proceed` admit `Critical` under a Breached SLA would
//!     silently let secret access bypass the freshness gate.
//!
//! Properties asserted:
//!
//!   1. **`check_sla` boundary**: age `now - checkpoint_updated_at`
//!      <= `sla_secs` → `Fresh`; > → `Breached{overdue_secs}` where
//!      `overdue_secs == age - sla_secs`.
//!   2. **Saturating-sub on clock skew**: `now < checkpoint_updated_at`
//!      → age = 0 → `Fresh` (does not panic).
//!   3. **`is_fresh`** iff `Fresh` variant.
//!   4. **`may_proceed(Critical)`** ⇔ `check_sla.is_fresh()`.
//!   5. **`may_proceed(Risky)`** always `true`.
//!   6. **`may_proceed(Safe)`** always `true`.
//!   7. **Determinism**: repeated calls yield the same status.
//!
//!   Once-gated anchors verify each boundary + each freshness class
//!   on hand-picked inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{RevocationFreshnessClass, RevocationSlaChecker, RevocationSlaStatus};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static SLA_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    checkpoint_rev_seq: u64,
    checkpoint_updated_at: u64,
    sla_secs: u64,
    now: u64,
    /// Tier discriminant (mod 3).
    tier_disc: u8,
}

fn pick_class(disc: u8) -> RevocationFreshnessClass {
    match disc % 3 {
        0 => RevocationFreshnessClass::Critical,
        1 => RevocationFreshnessClass::Risky,
        _ => RevocationFreshnessClass::Safe,
    }
}

fuzz_target!(|data: &[u8]| {
    SLA_ANCHOR.call_once(assert_sla_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let checker = RevocationSlaChecker::new(
        input.checkpoint_rev_seq,
        input.checkpoint_updated_at,
        input.sla_secs,
    );
    let status = checker.check_sla(input.now);
    let age = input.now.saturating_sub(input.checkpoint_updated_at);

    // ── PROPERTY 1 + 2: check_sla boundary + saturating sub ─────────────
    if age <= input.sla_secs {
        match status {
            RevocationSlaStatus::Fresh => {}
            other => panic!(
                "expected Fresh at age={age} <= sla={}, got {other:?}",
                input.sla_secs
            ),
        }
    } else {
        match status {
            RevocationSlaStatus::Breached { overdue_secs } => {
                assert_eq!(
                    overdue_secs,
                    age - input.sla_secs,
                    "Breached.overdue_secs mismatch: {} vs {}",
                    overdue_secs,
                    age - input.sla_secs
                );
            }
            other => panic!(
                "expected Breached at age={age} > sla={}, got {other:?}",
                input.sla_secs
            ),
        }
    }

    // ── PROPERTY 3: is_fresh ⇔ Fresh variant ────────────────────────────
    let is_fresh = status.is_fresh();
    assert_eq!(
        is_fresh,
        matches!(status, RevocationSlaStatus::Fresh),
        "is_fresh disagreed with Fresh variant"
    );

    // ── PROPERTY 4 + 5 + 6: may_proceed by class ────────────────────────
    let class = pick_class(input.tier_disc);
    let may = checker.may_proceed(input.now, class);
    let expected_may = match class {
        RevocationFreshnessClass::Critical => is_fresh,
        RevocationFreshnessClass::Risky | RevocationFreshnessClass::Safe => true,
    };
    assert_eq!(
        may, expected_may,
        "may_proceed({class:?}) at age={age} sla={} returned {may}; expected {expected_may}",
        input.sla_secs
    );

    // Risky and Safe always pass regardless of staleness.
    assert!(
        checker.may_proceed(input.now, RevocationFreshnessClass::Risky),
        "Risky must always proceed"
    );
    assert!(
        checker.may_proceed(input.now, RevocationFreshnessClass::Safe),
        "Safe must always proceed"
    );

    // ── PROPERTY 7: determinism ─────────────────────────────────────────
    let status2 = checker.check_sla(input.now);
    assert_eq!(status, status2, "check_sla non-deterministic");
});

/// Once-gated anchors: hand-picked boundaries + each freshness class.
fn assert_sla_anchored() {
    // (a) age == sla → Fresh (the <= boundary).
    let checker = RevocationSlaChecker::new(0, 1_000, 60);
    match checker.check_sla(1_060) {
        RevocationSlaStatus::Fresh => {}
        other => panic!("ANCHOR REGRESSION: age==sla expected Fresh, got {other:?}"),
    }

    // (b) age == sla + 1 → Breached{1}.
    match checker.check_sla(1_061) {
        RevocationSlaStatus::Breached { overdue_secs: 1 } => {}
        other => panic!("ANCHOR REGRESSION: age==sla+1 expected Breached{{1}}, got {other:?}"),
    }

    // (c) age = 0 (now == checkpoint_updated_at) → Fresh.
    match checker.check_sla(1_000) {
        RevocationSlaStatus::Fresh => {}
        other => panic!("ANCHOR REGRESSION: age=0 expected Fresh, got {other:?}"),
    }

    // (d) Clock skew: now < checkpoint_updated_at → saturating sub → age=0 → Fresh.
    match checker.check_sla(500) {
        RevocationSlaStatus::Fresh => {}
        other => panic!(
            "ANCHOR REGRESSION: now < checkpoint_updated_at expected Fresh (saturating sub), got {other:?}"
        ),
    }

    // (e) Critical may not proceed when Breached.
    let breached = checker.check_sla(2_000);
    assert!(matches!(breached, RevocationSlaStatus::Breached { .. }));
    assert!(
        !checker.may_proceed(2_000, RevocationFreshnessClass::Critical),
        "ANCHOR REGRESSION: Critical proceeded on Breached SLA"
    );

    // (f) Risky and Safe always proceed.
    assert!(
        checker.may_proceed(2_000, RevocationFreshnessClass::Risky),
        "ANCHOR: Risky must proceed under Breached"
    );
    assert!(
        checker.may_proceed(2_000, RevocationFreshnessClass::Safe),
        "ANCHOR: Safe must proceed under Breached"
    );

    // (g) Critical proceeds when Fresh.
    assert!(
        checker.may_proceed(1_010, RevocationFreshnessClass::Critical),
        "ANCHOR: Critical must proceed when Fresh"
    );

    // (h) is_fresh mapping.
    assert!(RevocationSlaStatus::Fresh.is_fresh());
    assert!(
        !RevocationSlaStatus::Breached { overdue_secs: 5 }.is_fresh(),
        "ANCHOR: Breached.is_fresh must be false"
    );

    // (i) sla_secs = 0 → only age=0 is Fresh.
    let zero_sla = RevocationSlaChecker::new(0, 100, 0);
    match zero_sla.check_sla(100) {
        RevocationSlaStatus::Fresh => {}
        other => panic!("ANCHOR: sla=0, age=0 expected Fresh, got {other:?}"),
    }
    match zero_sla.check_sla(101) {
        RevocationSlaStatus::Breached { overdue_secs: 1 } => {}
        other => panic!("ANCHOR: sla=0, age=1 expected Breached{{1}}, got {other:?}"),
    }
}
