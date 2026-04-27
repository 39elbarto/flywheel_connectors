#![no_main]

//! Fuzz target for `fcp_core::provenance::ProvenanceRecord::merge`
//! (provenance.rs:457-506).
//!
//! `ProvenanceRecord::merge` is the SECURITY CRITICAL combine: per its
//! doc-comment (NORMATIVE):
//!   - integrity      = MIN(records.integrity)        // lowest wins
//!   - confidentiality= MAX(records.confidentiality)  // highest wins
//!   - taint          = OR(records.taint_flags)       // union
//!
//! This prevents "mix trusted with untrusted from upgrading trust." A
//! regression that swapped MIN↔MAX or dropped a taint flag would
//! silently break the trust-flow lattice — high-integrity output from
//! a low-integrity input set, or low-confidentiality output that
//! should have been restricted, or untainted output that smuggled
//! away a PublicInput tag.
//!
//! Existing `taint_flags` (k1qyp) covers `TaintFlags::merge`. NOT
//! covered: the full `ProvenanceRecord::merge` with the integrity +
//! confidentiality + taint composition.
//!
//! Properties asserted:
//!
//!   1. **Empty input → default**: `merge(&[], zone)` returns the
//!      default record for `zone` (untrusted/public).
//!   2. **MIN-integrity rule**: result.integrity_label equals the
//!      minimum across input records.
//!   3. **MAX-confidentiality rule**: result.confidentiality_label
//!      equals the maximum across input records.
//!   4. **OR-taint rule**: result.taint_flags contains every flag in
//!      any input record's taint_flags.
//!   5. **current_zone preservation**: result.current_zone is exactly
//!      the passed-in zone (NOT a record's origin or current).
//!   6. **Single-record identity (labels)**: merge of [r] preserves
//!      r.integrity_label, r.confidentiality_label, r.taint_flags
//!      verbatim.
//!
//!   Once-gated regression anchors:
//!     (a) merge([Owner, Untrusted]) → integrity=Untrusted (MIN —
//!         prevents trust upgrade by mixing).
//!     (b) merge([Public, Owner]) → confidentiality=Owner (MAX —
//!         most restrictive flows up).
//!     (c) merge([+PublicInput, untainted]) → taint contains
//!         PublicInput (OR-union, no flag is dropped).

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ConfidentialityLevel, IntegrityLevel, ProvenanceRecord, TaintFlag, ZoneId};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_RECORDS: usize = 6;

static MERGE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug, Clone, Copy)]
struct RecordSeed {
    /// 0..=4 → IntegrityLevel variant.
    integrity_disc: u8,
    /// 0..=4 → ConfidentialityLevel variant.
    confidentiality_disc: u8,
    /// Bitmask over the 8 TaintFlag variants.
    taint_mask: u8,
    /// Origin zone selector.
    zone_disc: u8,
}

#[derive(Arbitrary, Debug)]
struct Input {
    records: Vec<RecordSeed>,
    /// Selector for current_zone passed to merge.
    current_zone_disc: u8,
}

const TAINT_VARIANTS: [TaintFlag; 8] = [
    TaintFlag::PublicInput,
    TaintFlag::UnverifiedLink,
    TaintFlag::UntrustedTransform,
    TaintFlag::WebhookInjected,
    TaintFlag::UserGenerated,
    TaintFlag::PotentiallyMalicious,
    TaintFlag::AiGenerated,
    TaintFlag::CrossZoneUnapproved,
];

fn integrity_for(disc: u8) -> IntegrityLevel {
    match disc % 5 {
        0 => IntegrityLevel::Untrusted,
        1 => IntegrityLevel::Community,
        2 => IntegrityLevel::Work,
        3 => IntegrityLevel::Private,
        _ => IntegrityLevel::Owner,
    }
}

fn confidentiality_for(disc: u8) -> ConfidentialityLevel {
    match disc % 5 {
        0 => ConfidentialityLevel::Public,
        1 => ConfidentialityLevel::Community,
        2 => ConfidentialityLevel::Work,
        3 => ConfidentialityLevel::Private,
        _ => ConfidentialityLevel::Owner,
    }
}

fn zone_for(disc: u8) -> ZoneId {
    match disc % 5 {
        0 => ZoneId::owner(),
        1 => ZoneId::private(),
        2 => ZoneId::work(),
        3 => ZoneId::community(),
        _ => ZoneId::public(),
    }
}

fn make_record(seed: RecordSeed) -> ProvenanceRecord {
    let zone = zone_for(seed.zone_disc);
    let mut record = ProvenanceRecord::new(zone);
    record.integrity_label = integrity_for(seed.integrity_disc);
    record.confidentiality_label = confidentiality_for(seed.confidentiality_disc);
    for (i, flag) in TAINT_VARIANTS.iter().enumerate() {
        if (seed.taint_mask >> i) & 1 == 1 {
            record.taint_flags.insert(*flag);
        }
    }
    record
}

fuzz_target!(|data: &[u8]| {
    MERGE_ANCHOR.call_once(assert_merge_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let current_zone = zone_for(input.current_zone_disc);

    // ── PROPERTY 1: empty input → default for current_zone ────────────
    let empty: Vec<&ProvenanceRecord> = vec![];
    let merged_empty = ProvenanceRecord::merge(&empty, current_zone.clone());
    assert_eq!(
        merged_empty.current_zone, current_zone,
        "empty merge: current_zone not preserved"
    );

    let records: Vec<ProvenanceRecord> = input
        .records
        .iter()
        .take(MAX_RECORDS)
        .copied()
        .map(make_record)
        .collect();
    if records.is_empty() {
        return;
    }
    let refs: Vec<&ProvenanceRecord> = records.iter().collect();

    let merged = ProvenanceRecord::merge(&refs, current_zone.clone());

    // ── PROPERTY 5: current_zone preservation ────────────────────────
    assert_eq!(
        merged.current_zone, current_zone,
        "current_zone not preserved by merge"
    );

    // ── PROPERTY 2: MIN-integrity ────────────────────────────────────
    let expected_integrity = records
        .iter()
        .map(|r| r.integrity_label)
        .min()
        .expect("non-empty records");
    assert_eq!(
        merged.integrity_label, expected_integrity,
        "MIN-integrity rule violated: got {:?}, expected min={:?}",
        merged.integrity_label, expected_integrity
    );

    // ── PROPERTY 3: MAX-confidentiality ──────────────────────────────
    let expected_confidentiality = records
        .iter()
        .map(|r| r.confidentiality_label)
        .max()
        .expect("non-empty records");
    assert_eq!(
        merged.confidentiality_label, expected_confidentiality,
        "MAX-confidentiality rule violated: got {:?}, expected max={:?}",
        merged.confidentiality_label, expected_confidentiality
    );

    // ── PROPERTY 4: OR-taint ─────────────────────────────────────────
    for flag in TAINT_VARIANTS {
        let any_record_has = records.iter().any(|r| r.taint_flags.contains(flag));
        let merged_has = merged.taint_flags.contains(flag);
        assert_eq!(
            merged_has, any_record_has,
            "OR-taint rule violated for {flag:?}: merged_has={merged_has}, \
             any_record_has={any_record_has}"
        );
    }

    // ── PROPERTY 6: single-record label identity ─────────────────────
    if records.len() == 1 {
        let r = &records[0];
        assert_eq!(merged.integrity_label, r.integrity_label);
        assert_eq!(merged.confidentiality_label, r.confidentiality_label);
        for flag in TAINT_VARIANTS {
            assert_eq!(
                merged.taint_flags.contains(flag),
                r.taint_flags.contains(flag)
            );
        }
    }
});

/// Once-gated regression anchors verifying the documented MIN/MAX/OR
/// rules with hand-picked input pairs.
fn assert_merge_anchored() {
    // (a) MIN-integrity: Owner+Untrusted → Untrusted.
    let mut r_owner = ProvenanceRecord::new(ZoneId::owner());
    r_owner.integrity_label = IntegrityLevel::Owner;
    let mut r_untrusted = ProvenanceRecord::new(ZoneId::public());
    r_untrusted.integrity_label = IntegrityLevel::Untrusted;
    let merged = ProvenanceRecord::merge(&[&r_owner, &r_untrusted], ZoneId::work());
    assert_eq!(
        merged.integrity_label,
        IntegrityLevel::Untrusted,
        "ANCHOR REGRESSION: merge([Owner, Untrusted]) integrity = {:?}, \
         expected Untrusted (MIN). The MIN rule that prevents 'mix trusted \
         with untrusted upgrades trust' has degraded; provenance.rs:462-467 \
         broken.",
        merged.integrity_label
    );

    // Order-independent: same result with reversed input.
    let merged_rev = ProvenanceRecord::merge(&[&r_untrusted, &r_owner], ZoneId::work());
    assert_eq!(
        merged_rev.integrity_label,
        IntegrityLevel::Untrusted,
        "ANCHOR: MIN-integrity not order-independent"
    );

    // (b) MAX-confidentiality: Public+Owner → Owner.
    let mut r_public_c = ProvenanceRecord::new(ZoneId::public());
    r_public_c.confidentiality_label = ConfidentialityLevel::Public;
    let mut r_owner_c = ProvenanceRecord::new(ZoneId::owner());
    r_owner_c.confidentiality_label = ConfidentialityLevel::Owner;
    let merged = ProvenanceRecord::merge(&[&r_public_c, &r_owner_c], ZoneId::work());
    assert_eq!(
        merged.confidentiality_label,
        ConfidentialityLevel::Owner,
        "ANCHOR REGRESSION: merge([Public, Owner]) confidentiality = {:?}, \
         expected Owner (MAX). The MAX rule that ensures the most-restrictive \
         confidentiality flows up has degraded; provenance.rs:469-474 broken.",
        merged.confidentiality_label
    );

    // (c) OR-taint: PublicInput + untainted → result has PublicInput.
    let mut r_tainted = ProvenanceRecord::new(ZoneId::public());
    r_tainted.taint_flags.insert(TaintFlag::PublicInput);
    let r_clean = ProvenanceRecord::new(ZoneId::owner());
    let merged = ProvenanceRecord::merge(&[&r_tainted, &r_clean], ZoneId::work());
    assert!(
        merged.taint_flags.contains(TaintFlag::PublicInput),
        "ANCHOR REGRESSION: merge([+PublicInput, untainted]) lost the \
         PublicInput flag — OR-taint rule has degraded; provenance.rs:476-482 \
         broken; trust upgrade via taint stripping is now possible."
    );

    // current_zone preservation in the canonical anchor case.
    assert_eq!(
        merged.current_zone,
        ZoneId::work(),
        "ANCHOR: current_zone not preserved"
    );
}
