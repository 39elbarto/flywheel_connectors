#![no_main]

//! Fuzz target for `fcp_core::Provenance` construction API + TaintLevel
//! ordering (capability.rs:2496-2603).
//!
//! Distinct from `provenance_record_merge` (hpgza) which covers
//! ProvenanceRecord::merge MIN/MAX/OR rules — this fuzzes the
//! Provenance construction state machine: new, tainted, highly_tainted,
//! with_step, elevated_with.
//!
//! NOT covered by existing fuzz.
//!
//! Properties asserted:
//!
//!   1. **new(zone) defaults**: origin_zone == zone; chain empty;
//!      taint == Untainted; elevated == false; elevation_token == None.
//!   2. **tainted(zone)**: same as new but taint == Tainted.
//!   3. **highly_tainted(zone)**: same as new but taint == HighlyTainted.
//!   4. **with_step appends**: chain length increases by 1 per call;
//!      the appended step is at index chain.len() - 1.
//!   5. **elevated_with(token)**: elevated == true,
//!      elevation_token == Some(token).
//!   6. **TaintLevel Ord lattice**: Untainted < Tainted < HighlyTainted.
//!   7. **TaintLevel Default**: Default::default() == Untainted.
//!
//!   Once-gated anchors verify each constructor + the ordering.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{Provenance, ProvenanceStep, TaintLevel, ZoneId};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_STEPS: usize = 8;

static PROVENANCE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct StepSeed {
    timestamp_ms: u64,
    actor: String,
    action: String,
    resource: String,
}

#[derive(Arbitrary, Debug)]
struct Input {
    zone_disc: u8,
    /// 0 = new (Untainted), 1 = tainted, 2 = highly_tainted.
    constructor_disc: u8,
    /// Step seeds to append via with_step.
    steps: Vec<StepSeed>,
    /// Whether to call elevated_with.
    do_elevate: bool,
    elevation_token: String,
}

fn pick_zone(disc: u8) -> ZoneId {
    match disc % 5 {
        0 => ZoneId::owner(),
        1 => ZoneId::private(),
        2 => ZoneId::work(),
        3 => ZoneId::community(),
        _ => ZoneId::public(),
    }
}

fn build_step(seed: StepSeed, zone: ZoneId) -> ProvenanceStep {
    ProvenanceStep {
        timestamp_ms: seed.timestamp_ms,
        zone,
        actor: seed.actor,
        action: seed.action,
        resource: seed.resource,
    }
}

fuzz_target!(|data: &[u8]| {
    PROVENANCE_ANCHOR.call_once(assert_provenance_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let zone = pick_zone(input.zone_disc);
    let mut prov = match input.constructor_disc % 3 {
        0 => Provenance::new(zone.clone()),
        1 => Provenance::tainted(zone.clone()),
        _ => Provenance::highly_tainted(zone.clone()),
    };

    // ── PROPERTY 1+2+3: constructor defaults ──────────────────────────
    assert_eq!(prov.origin_zone, zone, "origin_zone wrong");
    assert!(prov.chain.is_empty(), "fresh chain should be empty");
    assert!(!prov.elevated, "fresh prov should not be elevated");
    assert!(
        prov.elevation_token.is_none(),
        "fresh prov should have no elevation token"
    );
    let expected_taint = match input.constructor_disc % 3 {
        0 => TaintLevel::Untainted,
        1 => TaintLevel::Tainted,
        _ => TaintLevel::HighlyTainted,
    };
    assert_eq!(prov.taint, expected_taint, "constructor taint wrong");

    // ── PROPERTY 4: with_step appends ─────────────────────────────────
    let n = input.steps.len().min(MAX_STEPS);
    let mut prev_len = prov.chain.len();
    for seed in input.steps.into_iter().take(n) {
        let step = build_step(seed, zone.clone());
        let action_at_start = step.action.clone();
        prov = prov.with_step(step);
        assert_eq!(
            prov.chain.len(),
            prev_len + 1,
            "with_step did not append exactly one step"
        );
        assert_eq!(
            prov.chain.last().unwrap().action,
            action_at_start,
            "appended step action mismatch"
        );
        prev_len = prov.chain.len();
    }
    assert_eq!(prov.chain.len(), n, "final chain length mismatch");

    // ── PROPERTY 5: elevated_with ────────────────────────────────────
    if input.do_elevate {
        let token = input.elevation_token.clone();
        prov = prov.elevated_with(token.clone());
        assert!(prov.elevated, "elevated_with did not set elevated=true");
        assert_eq!(
            prov.elevation_token,
            Some(token),
            "elevated_with did not set elevation_token"
        );
    }
});

/// Once-gated anchors verifying constructor defaults + TaintLevel
/// ordering invariants.
fn assert_provenance_anchored() {
    let zone = ZoneId::work();

    // Constructor defaults.
    let p_new = Provenance::new(zone.clone());
    assert_eq!(p_new.taint, TaintLevel::Untainted, "ANCHOR: new taint");
    assert!(p_new.chain.is_empty(), "ANCHOR: new chain");
    assert!(!p_new.elevated, "ANCHOR: new elevated");

    let p_t = Provenance::tainted(zone.clone());
    assert_eq!(
        p_t.taint,
        TaintLevel::Tainted,
        "ANCHOR REGRESSION: tainted() did not set taint=Tainted"
    );

    let p_ht = Provenance::highly_tainted(zone.clone());
    assert_eq!(
        p_ht.taint,
        TaintLevel::HighlyTainted,
        "ANCHOR REGRESSION: highly_tainted() did not set taint=HighlyTainted"
    );

    // TaintLevel Ord lattice: Untainted < Tainted < HighlyTainted.
    assert!(
        TaintLevel::Untainted < TaintLevel::Tainted,
        "ANCHOR REGRESSION: TaintLevel Ord broken — Untainted not < Tainted"
    );
    assert!(
        TaintLevel::Tainted < TaintLevel::HighlyTainted,
        "ANCHOR REGRESSION: TaintLevel Ord broken — Tainted not < HighlyTainted"
    );
    assert!(TaintLevel::Untainted < TaintLevel::HighlyTainted);

    // Default.
    assert_eq!(
        TaintLevel::default(),
        TaintLevel::Untainted,
        "ANCHOR: TaintLevel::default() not Untainted"
    );

    // with_step appends and is chainable.
    let step1 = ProvenanceStep {
        timestamp_ms: 1,
        zone: zone.clone(),
        actor: "actor1".to_string(),
        action: "action1".to_string(),
        resource: "r1".to_string(),
    };
    let step2 = ProvenanceStep {
        timestamp_ms: 2,
        zone: zone.clone(),
        actor: "actor2".to_string(),
        action: "action2".to_string(),
        resource: "r2".to_string(),
    };
    let chained = Provenance::new(zone.clone())
        .with_step(step1)
        .with_step(step2);
    assert_eq!(chained.chain.len(), 2, "ANCHOR: chained with_step length");
    assert_eq!(chained.chain[0].action, "action1", "ANCHOR: step1 order");
    assert_eq!(chained.chain[1].action, "action2", "ANCHOR: step2 order");

    // elevated_with.
    let p_elev = Provenance::new(zone).elevated_with("auth-token-xyz".to_string());
    assert!(p_elev.elevated, "ANCHOR: elevated_with elevated bit");
    assert_eq!(
        p_elev.elevation_token.as_deref(),
        Some("auth-token-xyz"),
        "ANCHOR REGRESSION: elevated_with did not store the token"
    );
}
