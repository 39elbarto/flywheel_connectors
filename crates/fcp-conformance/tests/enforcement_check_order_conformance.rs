//! `EnforcementCheckOrder` canonical 11-stage pipeline +
//! `CheckOutcome` predicate conformance.
//!
//! `fcp_core::EnforcementCheckOrder::canonical_order` is the NORMATIVE
//! ordering every FCP runtime MUST follow when evaluating an
//! enforcement decision. The docstring is explicit: "All FCP runtimes
//! MUST evaluate enforcement checks in this order". Drift between
//! the host, SDK, or any future runtime would silently change which
//! check fails first, masking the real failure behind an incidental
//! one (e.g., a revoked capability surfacing as a budget error).
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **Canonical sequence** — exactly 11 entries in the documented
//!    order: CanonicalDecode → ZoneMembership → CapabilityVerify →
//!    HolderProof → CheckpointFreshness → RevocationFreshness →
//!    TaintApproval → PolicyCeiling → ConnectorManifest → Budget →
//!    RateLimit.
//! 2. **`COUNT` matches the array length** (= 11).
//! 3. **`index_of` agrees with array position** for every variant.
//! 4. **`runs_before` is the < relation on indices.**
//! 5. **`as_str` snake_case wire form** for each variant.
//! 6. **`Display` equals `as_str`.**
//! 7. **Pipeline determinism** — repeated calls yield identical
//!    arrays (no allocation surprise, no re-ordering).
//! 8. **Cheap-first ordering** — the documented design rule that
//!    decode/zone run before crypto, which run before stateful
//!    checks. Pinned via specific runs_before assertions.
//! 9. **`CheckOutcome::is_allow` / `is_deny` are mutually exclusive**
//!    and reflect their variants.

use fcp_prelude::{CheckOutcome, EnforcementCheckId, EnforcementCheckOrder};

#[test]
fn canonical_order_returns_documented_eleven_check_sequence() {
    let order = EnforcementCheckOrder::canonical_order();
    assert_eq!(order.len(), 11);
    assert_eq!(
        order,
        [
            EnforcementCheckId::CanonicalDecode,
            EnforcementCheckId::ZoneMembership,
            EnforcementCheckId::CapabilityVerify,
            EnforcementCheckId::HolderProof,
            EnforcementCheckId::CheckpointFreshness,
            EnforcementCheckId::RevocationFreshness,
            EnforcementCheckId::TaintApproval,
            EnforcementCheckId::PolicyCeiling,
            EnforcementCheckId::ConnectorManifest,
            EnforcementCheckId::Budget,
            EnforcementCheckId::RateLimit,
        ],
        "canonical_order MUST return the documented 11-check sequence — drift here \
         would change which check fails first across runtimes"
    );
}

#[test]
fn count_constant_matches_canonical_order_length() {
    assert_eq!(
        EnforcementCheckOrder::COUNT,
        EnforcementCheckOrder::canonical_order().len(),
        "COUNT constant MUST equal the canonical array length"
    );
    assert_eq!(EnforcementCheckOrder::COUNT, 11);
}

#[test]
fn index_of_agrees_with_canonical_order_position() {
    let order = EnforcementCheckOrder::canonical_order();
    for (idx, check) in order.iter().enumerate() {
        assert_eq!(
            EnforcementCheckOrder::index_of(*check),
            idx,
            "index_of({check:?}) MUST equal canonical_order position {idx}"
        );
    }
}

#[test]
fn runs_before_is_strict_less_than_on_indices() {
    let order = EnforcementCheckOrder::canonical_order();
    for (i, &a) in order.iter().enumerate() {
        for (j, &b) in order.iter().enumerate() {
            let expected = i < j;
            assert_eq!(
                EnforcementCheckOrder::runs_before(a, b),
                expected,
                "runs_before({a:?}, {b:?}) MUST equal (index_of(a) < index_of(b)) = {expected}"
            );
        }
    }
}

#[test]
fn runs_before_is_irreflexive() {
    // No check runs before itself.
    for &check in EnforcementCheckOrder::canonical_order().iter() {
        assert!(
            !EnforcementCheckOrder::runs_before(check, check),
            "runs_before({check:?}, {check:?}) MUST be false (irreflexive)"
        );
    }
}

#[test]
fn as_str_matches_snake_case_wire_form_for_each_variant() {
    let pairs = [
        (EnforcementCheckId::CanonicalDecode, "canonical_decode"),
        (EnforcementCheckId::ZoneMembership, "zone_membership"),
        (EnforcementCheckId::CapabilityVerify, "capability_verify"),
        (EnforcementCheckId::HolderProof, "holder_proof"),
        (
            EnforcementCheckId::CheckpointFreshness,
            "checkpoint_freshness",
        ),
        (
            EnforcementCheckId::RevocationFreshness,
            "revocation_freshness",
        ),
        (EnforcementCheckId::TaintApproval, "taint_approval"),
        (EnforcementCheckId::PolicyCeiling, "policy_ceiling"),
        (EnforcementCheckId::ConnectorManifest, "connector_manifest"),
        (EnforcementCheckId::Budget, "budget"),
        (EnforcementCheckId::RateLimit, "rate_limit"),
    ];
    for (variant, expected) in pairs {
        assert_eq!(
            variant.as_str(),
            expected,
            "as_str MUST be the documented snake_case wire form for {variant:?}"
        );
    }
}

#[test]
fn display_equals_as_str_for_every_variant() {
    for &variant in EnforcementCheckOrder::canonical_order().iter() {
        assert_eq!(
            format!("{variant}"),
            variant.as_str(),
            "Display MUST equal as_str for {variant:?}"
        );
    }
}

#[test]
fn json_serde_roundtrip_uses_snake_case() {
    for &variant in EnforcementCheckOrder::canonical_order().iter() {
        let json = serde_json::to_string(&variant).expect("serialize");
        let expected = format!("\"{}\"", variant.as_str());
        assert_eq!(
            json, expected,
            "JSON serialization MUST match snake_case wire form for {variant:?}"
        );
        let parsed: EnforcementCheckId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

#[test]
fn canonical_order_is_deterministic_under_repeated_calls() {
    let first = EnforcementCheckOrder::canonical_order();
    for _ in 0..16 {
        let again = EnforcementCheckOrder::canonical_order();
        assert_eq!(first, again, "canonical_order MUST be deterministic");
    }
}

#[test]
fn cheap_structural_checks_run_before_crypto_checks() {
    // Documented design rule: decode + zone-membership run BEFORE
    // expensive crypto verification. Pin specific orderings.
    use EnforcementCheckId::*;
    assert!(EnforcementCheckOrder::runs_before(
        CanonicalDecode,
        CapabilityVerify
    ));
    assert!(EnforcementCheckOrder::runs_before(
        ZoneMembership,
        CapabilityVerify
    ));
    assert!(EnforcementCheckOrder::runs_before(
        ZoneMembership,
        HolderProof
    ));
}

#[test]
fn crypto_checks_run_before_stateful_checks() {
    // CapabilityVerify (crypto) runs BEFORE Budget and RateLimit
    // (stateful). Otherwise an attacker could enumerate budget
    // state via forged tokens.
    use EnforcementCheckId::*;
    assert!(EnforcementCheckOrder::runs_before(CapabilityVerify, Budget));
    assert!(EnforcementCheckOrder::runs_before(
        CapabilityVerify,
        RateLimit
    ));
    assert!(EnforcementCheckOrder::runs_before(HolderProof, Budget));
}

#[test]
fn freshness_checks_precede_business_logic() {
    // CheckpointFreshness + RevocationFreshness must run BEFORE
    // PolicyCeiling, ConnectorManifest, Budget, RateLimit. Stale
    // policy ceiling or budget windows cannot be evaluated against
    // unverified state.
    use EnforcementCheckId::*;
    assert!(EnforcementCheckOrder::runs_before(
        RevocationFreshness,
        PolicyCeiling
    ));
    assert!(EnforcementCheckOrder::runs_before(
        CheckpointFreshness,
        Budget
    ));
}

#[test]
fn check_outcome_allow_is_only_for_allow_variant() {
    let allow = CheckOutcome::Allow;
    assert!(allow.is_allow());
    assert!(!allow.is_deny());
}

#[test]
fn check_outcome_deny_is_only_for_deny_variant() {
    let deny = CheckOutcome::Deny {
        reason_code: "zone_violation".into(),
        explanation: "request from disallowed zone".into(),
    };
    assert!(!deny.is_allow());
    assert!(deny.is_deny());
}

#[test]
fn check_outcome_skip_is_neither_allow_nor_deny() {
    // Skip is the third variant — it MUST NOT be classified as
    // either allow or deny so callers handle it explicitly.
    let skip = CheckOutcome::Skip {
        reason: "not applicable for this request type".into(),
    };
    assert!(
        !skip.is_allow(),
        "Skip MUST NOT be classified as Allow — caller must handle Skip explicitly"
    );
    assert!(!skip.is_deny(), "Skip MUST NOT be classified as Deny");
}

#[test]
fn check_outcome_serde_roundtrip_for_all_variants() {
    let outcomes = [
        CheckOutcome::Allow,
        CheckOutcome::Deny {
            reason_code: "code".into(),
            explanation: "exp".into(),
        },
        CheckOutcome::Skip {
            reason: "skip".into(),
        },
    ];
    for outcome in outcomes {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let parsed: CheckOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, outcome);
    }
}

#[test]
fn check_outcome_uses_outcome_tag_in_json() {
    let allow_json = serde_json::to_string(&CheckOutcome::Allow).expect("serialize");
    assert!(
        allow_json.contains("\"outcome\":\"allow\""),
        "CheckOutcome JSON MUST use 'outcome' internal tag with snake_case rename; got {allow_json}"
    );
}

#[test]
fn every_enforcement_check_id_appears_in_canonical_order_exactly_once() {
    // Sanity: no duplicates, no missing variants. Otherwise
    // index_of would have undefined behavior or canonical_order
    // would silently skip a stage.
    let order = EnforcementCheckOrder::canonical_order();
    // EnforcementCheckId derives Hash but not Ord — use HashSet.
    let mut seen = std::collections::HashSet::new();
    for &check in order.iter() {
        assert!(
            seen.insert(check),
            "canonical_order MUST NOT contain duplicates; saw {check:?} twice"
        );
    }
    assert_eq!(seen.len(), 11);
}
