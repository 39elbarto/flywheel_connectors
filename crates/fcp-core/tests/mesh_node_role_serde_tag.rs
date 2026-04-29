//! Pin role-classifier serde tags on the closest analogues to
//! "MeshNodeRole" (flywheel_connectors-jtbfy).
//!
//! Bead asks for `MeshNodeRole serde tag`. No type literally named
//! `MeshNodeRole` exists in fcp-core. The role-shaped classifiers
//! that decide what a mesh node is doing in a quorum operation
//! split across two enums in `quorum.rs`:
//!
//!  - `RiskTier` (quorum.rs:56) — 4-variant tier classifier
//!    (Safe / Risky / Dangerous / CriticalWrite) that determines
//!    how many mesh-node signatures a quorum requires.
//!  - `QuorumPurpose` (quorum.rs:88) — 8-variant operation purpose
//!    that a mesh node participates in
//!    (AuditHead / ZoneCheckpoint / RevocationHead /
//!    DangerousLease / RiskyLease / SafeLease / KeyRotation /
//!    MembershipChange).
//!
//! NEITHER carries `#[serde(rename_all = ...)]`, so the wire form
//! is the **PascalCase variant name verbatim** — DIFFERENT from
//! `RiskTier::as_str` / `Display`, which return snake_case. Pin
//! the dual encoding loudly because operator tooling that filters
//! audit logs by token MUST know which form to expect from each
//! channel.
//!
//! Targets:
//!
//!   1. **`RiskTier::as_str` snake_case tokens** pinned per variant
//!      (the documented Display surface).
//!   2. **`RiskTier::Display` byte-for-byte agrees with `as_str`**.
//!   3. **`RiskTier` serde JSON form is PascalCase variant name**
//!      — pin the documented mismatch between Display and serde so
//!      a future `rename_all` swap is loud.
//!   4. **`RiskTier` JSON + CBOR round-trip** preserves variant.
//!   5. **`QuorumPurpose` serde JSON form is PascalCase variant
//!      name** for every variant.
//!   6. **`QuorumPurpose` JSON + CBOR round-trip** preserves variant.
//!   7. **`QuorumPurpose::default_risk_tier()` truth table** per
//!      variant — the documented mapping at quorum.rs:110.
//!   8. **Pairwise distinct serde forms** for both enums.
//!   9. **Both enums reject lower snake_case** as wire input — the
//!      mismatch is part of the wire contract.

use ciborium::value::Value as CborValue;
use fcp_core::{QuorumPurpose, RiskTier};

const RISK_TIER_AS_STR: &[(RiskTier, &str)] = &[
    (RiskTier::Safe, "safe"),
    (RiskTier::Risky, "risky"),
    (RiskTier::Dangerous, "dangerous"),
    (RiskTier::CriticalWrite, "critical_write"),
];

const RISK_TIER_SERDE: &[(RiskTier, &str)] = &[
    (RiskTier::Safe, "Safe"),
    (RiskTier::Risky, "Risky"),
    (RiskTier::Dangerous, "Dangerous"),
    (RiskTier::CriticalWrite, "CriticalWrite"),
];

const QUORUM_PURPOSE_SERDE: &[(QuorumPurpose, &str)] = &[
    (QuorumPurpose::AuditHead, "AuditHead"),
    (QuorumPurpose::ZoneCheckpoint, "ZoneCheckpoint"),
    (QuorumPurpose::RevocationHead, "RevocationHead"),
    (QuorumPurpose::DangerousLease, "DangerousLease"),
    (QuorumPurpose::RiskyLease, "RiskyLease"),
    (QuorumPurpose::SafeLease, "SafeLease"),
    (QuorumPurpose::KeyRotation, "KeyRotation"),
    (QuorumPurpose::MembershipChange, "MembershipChange"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. RiskTier::as_str snake_case tokens
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_tier_as_str_snake_case_tokens_pinned() {
    for (variant, expected) in RISK_TIER_AS_STR {
        assert_eq!(
            variant.as_str(),
            *expected,
            "AUDIT REGRESSION: RiskTier::as_str drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. RiskTier::Display agrees with as_str byte-for-byte
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_tier_display_agrees_with_as_str_byte_for_byte() {
    for (variant, expected) in RISK_TIER_AS_STR {
        let displayed = variant.to_string();
        let stringy = variant.as_str();
        assert_eq!(displayed, *expected, "Display drift on {variant:?}");
        assert_eq!(displayed, stringy, "Display vs as_str disagreement");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. RiskTier serde JSON form is PascalCase (DIFFERENT from Display)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_tier_serde_json_form_is_pascal_case_variant_name() {
    // RiskTier has NO #[serde(rename_all = ...)] — the wire form is
    // therefore the PascalCase variant name verbatim. Pin this
    // explicitly because it's a DIFFERENT encoding from Display
    // (which returns snake_case via as_str).
    for (variant, expected_pascal) in RISK_TIER_SERDE {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected_pascal}\""),
            "MESH-NODE-ROLE REGRESSION: RiskTier serde JSON form drift on {variant:?} — \
             current contract is PascalCase verbatim, NOT the snake_case Display"
        );
    }
}

#[test]
fn risk_tier_display_and_serde_disagree_intentionally() {
    // Document the mismatch loud and clear: the Display surface and
    // the serde wire form produce different bytes for every variant
    // EXCEPT Safe/Risky/Dangerous which collide via the
    // {snake_case, PascalCase} ASCII coincidence on single-word
    // variants. Pin the multi-word variant explicitly.
    let display_critical = RiskTier::CriticalWrite.to_string();
    let serde_critical = serde_json::to_string(&RiskTier::CriticalWrite).unwrap();
    assert_eq!(display_critical, "critical_write");
    assert_eq!(serde_critical, r#""CriticalWrite""#);
    assert_ne!(
        display_critical,
        serde_critical.trim_matches('"'),
        "Display and serde MUST disagree on CriticalWrite — drift sentinel \
         for any future rename_all swap"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. RiskTier JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_tier_json_roundtrip_preserves_every_variant() {
    for (variant, _) in RISK_TIER_SERDE {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: RiskTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn risk_tier_cbor_roundtrip_preserves_every_variant() {
    for (variant, _) in RISK_TIER_SERDE {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: RiskTier = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn risk_tier_cbor_encodes_as_text_pascal_case() {
    for (variant, expected) in RISK_TIER_SERDE {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => panic!("RiskTier MUST encode as Text({expected:?}); got {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. QuorumPurpose serde JSON form
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn quorum_purpose_serde_json_form_is_pascal_case_variant_name() {
    for (variant, expected) in QUORUM_PURPOSE_SERDE {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "QuorumPurpose serde JSON form drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. QuorumPurpose JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn quorum_purpose_json_roundtrip_preserves_every_variant() {
    for (variant, _) in QUORUM_PURPOSE_SERDE {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: QuorumPurpose = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn quorum_purpose_cbor_roundtrip_preserves_every_variant() {
    for (variant, _) in QUORUM_PURPOSE_SERDE {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: QuorumPurpose = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. QuorumPurpose::default_risk_tier() truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn quorum_purpose_default_risk_tier_truth_table_pinned() {
    // Mapping pinned by quorum.rs:110-121:
    //   {AuditHead, ZoneCheckpoint, RevocationHead}     → CriticalWrite
    //   {DangerousLease, KeyRotation, MembershipChange} → Dangerous
    //   {RiskyLease}                                    → Risky
    //   {SafeLease}                                     → Safe
    let cases = [
        (QuorumPurpose::AuditHead, RiskTier::CriticalWrite),
        (QuorumPurpose::ZoneCheckpoint, RiskTier::CriticalWrite),
        (QuorumPurpose::RevocationHead, RiskTier::CriticalWrite),
        (QuorumPurpose::DangerousLease, RiskTier::Dangerous),
        (QuorumPurpose::KeyRotation, RiskTier::Dangerous),
        (QuorumPurpose::MembershipChange, RiskTier::Dangerous),
        (QuorumPurpose::RiskyLease, RiskTier::Risky),
        (QuorumPurpose::SafeLease, RiskTier::Safe),
    ];
    for (purpose, expected_tier) in cases {
        assert_eq!(
            purpose.default_risk_tier(),
            expected_tier,
            "default_risk_tier drift on {purpose:?} — quorum threshold semantics changed"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Pairwise distinctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_tier_serde_forms_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in RISK_TIER_SERDE {
        assert!(seen.insert(*label), "duplicate token {label}");
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn quorum_purpose_serde_forms_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in QUORUM_PURPOSE_SERDE {
        assert!(seen.insert(*label), "duplicate token {label}");
    }
    assert_eq!(seen.len(), 8);
}

#[test]
fn risk_tier_variants_pairwise_unequal() {
    for i in 0..RISK_TIER_SERDE.len() {
        for j in (i + 1)..RISK_TIER_SERDE.len() {
            assert_ne!(
                RISK_TIER_SERDE[i].0, RISK_TIER_SERDE[j].0,
                "{:?} and {:?} MUST be distinct",
                RISK_TIER_SERDE[i].0, RISK_TIER_SERDE[j].0
            );
        }
    }
}

#[test]
fn quorum_purpose_variants_pairwise_unequal() {
    for i in 0..QUORUM_PURPOSE_SERDE.len() {
        for j in (i + 1)..QUORUM_PURPOSE_SERDE.len() {
            assert_ne!(QUORUM_PURPOSE_SERDE[i].0, QUORUM_PURPOSE_SERDE[j].0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Lower snake_case rejected (wire contract is PascalCase)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_tier_rejects_lower_snake_case_for_multi_word_variant() {
    // The multi-word variant is the unambiguous test: snake_case
    // `critical_write` MUST be rejected since the wire contract is
    // PascalCase.
    let parsed = serde_json::from_str::<RiskTier>(r#""critical_write""#);
    assert!(
        parsed.is_err(),
        "snake_case 'critical_write' MUST be rejected — wire form is PascalCase 'CriticalWrite'"
    );
}

#[test]
fn quorum_purpose_rejects_lower_snake_case() {
    for bad in [
        r#""audit_head""#,
        r#""zone_checkpoint""#,
        r#""key_rotation""#,
        r#""membership_change""#,
    ] {
        let parsed = serde_json::from_str::<QuorumPurpose>(bad);
        assert!(
            parsed.is_err(),
            "snake_case {bad} MUST be rejected — wire form is PascalCase"
        );
    }
}

#[test]
fn risk_tier_count_matches_documented_four() {
    assert_eq!(RISK_TIER_SERDE.len(), 4);
    assert_eq!(RISK_TIER_AS_STR.len(), 4);
}

#[test]
fn quorum_purpose_count_matches_documented_eight() {
    assert_eq!(QUORUM_PURPOSE_SERDE.len(), 8);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Cross-format consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_tier_json_and_cbor_decode_to_same_variant() {
    for (variant, _) in RISK_TIER_SERDE {
        let json = serde_json::to_string(variant).expect("JSON serialize");
        let from_json: RiskTier = serde_json::from_str(&json).expect("JSON deserialize");

        let mut cbor = Vec::new();
        ciborium::ser::into_writer(variant, &mut cbor).expect("CBOR encode");
        let from_cbor: RiskTier = ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");

        assert_eq!(
            from_json, from_cbor,
            "JSON and CBOR disagree on {variant:?}"
        );
    }
}
