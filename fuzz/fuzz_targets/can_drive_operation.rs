#![no_main]

//! Fuzz target for `ProvenanceRecord::can_drive_operation` decision
//! matrix per SafetyTier (provenance.rs:517-557).
//!
//! SECURITY-CRITICAL: this gates every operation on the (SafetyTier,
//! taint_flags, integrity_label) tuple. A regression that flipped a
//! single check would let an attacker drive a Dangerous operation
//! from public/malicious input.
//!
//! Decision matrix per docstring:
//!   - Safe → always Ok
//!   - Forbidden → always ForbiddenOperation
//!   - Risky → reject Malicious; reject critical-taint w/ integrity<Work
//!   - Dangerous / Critical (same path): reject in order PublicInput →
//!     Malicious → CrossZoneUnapproved → InsufficientIntegrity (<Work)
//!
//! NOT covered by existing fuzz.
//!
//! Properties asserted:
//!
//!   1. **Safe always Ok**.
//!   2. **Forbidden always ForbiddenOperation**.
//!   3. **Dangerous/Critical PublicInput rejection**: a record with
//!      PublicInput on D/C tier MUST yield PublicInputForDangerousOperation.
//!   4. **Dangerous/Critical Malicious rejection** (when no
//!      PublicInput): yields MaliciousInputDetected.
//!   5. **Dangerous/Critical CrossZoneUnapproved rejection** (when
//!      no PublicInput, no Malicious): yields
//!      CrossZoneUnapprovedForDangerousOperation.
//!   6. **Dangerous/Critical InsufficientIntegrity** (clean taint,
//!      integrity < Work): yields InsufficientIntegrity { required:
//!      Work, actual }.
//!   7. **Risky Malicious rejection**: PotentiallyMalicious on Risky
//!      yields MaliciousInputDetected.
//!
//!   Once-gated anchors verify each branch + the documented ordering
//!   on Dangerous/Critical (PublicInput beats Malicious beats
//!   CrossZone beats Integrity).

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{
    IntegrityLevel, ProvenanceRecord, ProvenanceViolation, SafetyTier, TaintFlag, ZoneId,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static CAN_DRIVE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    integrity_disc: u8,
    taint_mask: u8,
    /// Picks among 5 SafetyTier variants.
    tier_disc: u8,
}

fn integrity_for(disc: u8) -> IntegrityLevel {
    match disc % 5 {
        0 => IntegrityLevel::Untrusted,
        1 => IntegrityLevel::Community,
        2 => IntegrityLevel::Work,
        3 => IntegrityLevel::Private,
        _ => IntegrityLevel::Owner,
    }
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

fn pick_tier(disc: u8) -> SafetyTier {
    match disc % 5 {
        0 => SafetyTier::Safe,
        1 => SafetyTier::Risky,
        2 => SafetyTier::Dangerous,
        3 => SafetyTier::Critical,
        _ => SafetyTier::Forbidden,
    }
}

fn make_record(integrity: IntegrityLevel, mask: u8) -> ProvenanceRecord {
    let mut r = ProvenanceRecord::new(ZoneId::work());
    r.integrity_label = integrity;
    for (i, flag) in TAINT_VARIANTS.iter().enumerate() {
        if (mask >> i) & 1 == 1 {
            r.taint_flags.insert(*flag);
        }
    }
    r
}

fuzz_target!(|data: &[u8]| {
    CAN_DRIVE_ANCHOR.call_once(assert_can_drive_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let integrity = integrity_for(input.integrity_disc);
    let r = make_record(integrity, input.taint_mask);
    let tier = pick_tier(input.tier_disc);

    let result = r.can_drive_operation(tier);

    match tier {
        // ── PROPERTY 1: Safe always Ok ────────────────────────────────
        SafetyTier::Safe => {
            assert!(result.is_ok(), "Safe tier rejected: {result:?}");
        }
        // ── PROPERTY 2: Forbidden always ForbiddenOperation ───────────
        SafetyTier::Forbidden => match result {
            Err(ProvenanceViolation::ForbiddenOperation) => {}
            other => panic!("Forbidden tier returned {other:?}"),
        },
        SafetyTier::Risky => {
            // ── PROPERTY 7: Risky Malicious rejection ─────────────────
            if r.taint_flags.contains(TaintFlag::PotentiallyMalicious) {
                match result {
                    Err(ProvenanceViolation::MaliciousInputDetected) => {}
                    other => panic!("Risky+Malicious returned {other:?}"),
                }
            }
        }
        SafetyTier::Dangerous | SafetyTier::Critical => {
            // Order: PublicInput → Malicious → CrossZoneUnapproved → Integrity.
            if r.taint_flags.contains(TaintFlag::PublicInput) {
                // ── PROPERTY 3: Dangerous/Critical PublicInput ───────
                match result {
                    Err(ProvenanceViolation::PublicInputForDangerousOperation) => {}
                    other => panic!("D/C+PublicInput returned {other:?}"),
                }
            } else if r.taint_flags.contains(TaintFlag::PotentiallyMalicious) {
                // ── PROPERTY 4: Dangerous/Critical Malicious ─────────
                match result {
                    Err(ProvenanceViolation::MaliciousInputDetected) => {}
                    other => panic!("D/C+Malicious returned {other:?}"),
                }
            } else if r.taint_flags.contains(TaintFlag::CrossZoneUnapproved) {
                // ── PROPERTY 5: Dangerous/Critical CrossZone ─────────
                match result {
                    Err(ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation) => {}
                    other => panic!("D/C+CrossZone returned {other:?}"),
                }
            } else if integrity < IntegrityLevel::Work {
                // ── PROPERTY 6: Dangerous/Critical InsufficientIntegrity ──
                match result {
                    Err(ProvenanceViolation::InsufficientIntegrity { required, actual }) => {
                        assert_eq!(required, IntegrityLevel::Work);
                        assert_eq!(actual, integrity);
                    }
                    other => panic!("D/C+lowIntegrity returned {other:?}"),
                }
            } else {
                // Clean record on D/C tier MUST be accepted.
                assert!(result.is_ok(), "D/C clean record rejected: {result:?}");
            }
        }
    }
});

/// Once-gated anchors verifying each branch + ordering on Dangerous.
fn assert_can_drive_anchored() {
    let mut clean = ProvenanceRecord::new(ZoneId::work());
    clean.integrity_label = IntegrityLevel::Work;

    // (a) Safe → Ok regardless of taint.
    let mut tainted_safe = clean.clone();
    tainted_safe.taint_flags.insert(TaintFlag::PublicInput);
    tainted_safe
        .can_drive_operation(SafetyTier::Safe)
        .expect("ANCHOR: Safe with PublicInput should be Ok");

    // (b) Forbidden → ForbiddenOperation always.
    match clean.can_drive_operation(SafetyTier::Forbidden) {
        Err(ProvenanceViolation::ForbiddenOperation) => {}
        other => panic!("ANCHOR: Forbidden returned {other:?}"),
    }

    // (c) Dangerous + PublicInput → PublicInputForDangerousOperation
    // (even with high integrity, PublicInput is rejected).
    let mut public = clean.clone();
    public.integrity_label = IntegrityLevel::Owner;
    public.taint_flags.insert(TaintFlag::PublicInput);
    match public.can_drive_operation(SafetyTier::Dangerous) {
        Err(ProvenanceViolation::PublicInputForDangerousOperation) => {}
        other => panic!(
            "ANCHOR REGRESSION: Dangerous+PublicInput returned {other:?}; \
             expected PublicInputForDangerousOperation"
        ),
    }

    // (d) Order: PublicInput beats Malicious. With BOTH set on
    // Dangerous, the result MUST be PublicInputForDangerousOperation
    // (PublicInput check fires first per provenance.rs:539-541).
    let mut both = clean.clone();
    both.integrity_label = IntegrityLevel::Owner;
    both.taint_flags.insert(TaintFlag::PublicInput);
    both.taint_flags.insert(TaintFlag::PotentiallyMalicious);
    match both.can_drive_operation(SafetyTier::Dangerous) {
        Err(ProvenanceViolation::PublicInputForDangerousOperation) => {}
        other => panic!(
            "ANCHOR REGRESSION: Dangerous+(PublicInput|Malicious) returned \
             {other:?}; expected PublicInputForDangerousOperation (gate ordering \
             at provenance.rs:539 fires first)"
        ),
    }

    // (e) Dangerous + clean + integrity Untrusted → InsufficientIntegrity.
    let mut low_int = ProvenanceRecord::new(ZoneId::public());
    low_int.integrity_label = IntegrityLevel::Untrusted;
    match low_int.can_drive_operation(SafetyTier::Dangerous) {
        Err(ProvenanceViolation::InsufficientIntegrity { required, actual }) => {
            assert_eq!(required, IntegrityLevel::Work);
            assert_eq!(actual, IntegrityLevel::Untrusted);
        }
        other => panic!(
            "ANCHOR: Dangerous+lowIntegrity returned {other:?}; \
             expected InsufficientIntegrity"
        ),
    }

    // (f) Risky + Malicious → MaliciousInputDetected.
    let mut risky_mal = clean.clone();
    risky_mal
        .taint_flags
        .insert(TaintFlag::PotentiallyMalicious);
    match risky_mal.can_drive_operation(SafetyTier::Risky) {
        Err(ProvenanceViolation::MaliciousInputDetected) => {}
        other => {
            panic!("ANCHOR: Risky+Malicious returned {other:?}; expected MaliciousInputDetected")
        }
    }

    // (g) Acceptance: clean record at Work integrity on Dangerous → Ok.
    clean
        .can_drive_operation(SafetyTier::Dangerous)
        .expect("ANCHOR: clean record at Work should drive Dangerous");
}
