//! Pin "registry acceptance"-shaped verdict enums in fcp-core
//! (flywheel_connectors-zncpi).
//!
//! Bead asks for `RegistryAcceptance variants + Display per documented
//! contract`. No type literally named `RegistryAcceptance` exists in
//! fcp-core. The verdict-shaped surface that decides whether registry
//! artifacts (and resume attempts and policy previews) are accepted
//! splits across several enums:
//!
//!  - `VerificationDecision` (supply_chain.rs:926) — primary
//!    registry-acceptance verdict: Allow / Deny on a verified artifact.
//!  - `VerificationReasonCode` (supply_chain.rs above) — the
//!    SCREAMING_SNAKE_CASE reason classifier paired with the decision.
//!  - `ResumeDisposition` (connector_state.rs:1126) — 4-variant
//!    disposition with a documented `.label()` Display analogue
//!    (Attach/Retry/Deny/Reconcile).
//!  - `ResumeOutcome` (connector_state.rs:1153) — 2-variant final
//!    verdict (Accepted/Denied).
//!  - `PolicyPreviewDecision` (policy.rs:1869) — 3-variant preview
//!    decision (Allow/Deny/RequireApproval).
//!
//! This test pins the "variants + Display per documented contract"
//! contract for each, since drift in any of these tokens silently
//! breaks registry/audit/preview tooling.
//!
//! Targets per enum:
//!   1. **All variants enumerated** — count + identity guard against
//!      silent additions.
//!   2. **Per-variant JSON tag form** in the documented case
//!      convention (snake_case for most, SCREAMING_SNAKE_CASE for
//!      `VerificationReasonCode`).
//!   3. **JSON + CBOR round-trip** preserves variant identity.
//!   4. **`.label()` (where present) agrees with serde tag form**.
//!   5. **PascalCase + unknown rejected** — only documented tokens
//!      are canonical.

use fcp_core::{
    PolicyPreviewDecision, ResumeDisposition, ResumeOutcome, VerificationDecision,
    VerificationReasonCode,
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. VerificationDecision — primary registry-acceptance verdict
// ─────────────────────────────────────────────────────────────────────────────

const VERIFICATION_DECISION_CASES: &[(VerificationDecision, &str)] = &[
    (VerificationDecision::Allow, "allow"),
    (VerificationDecision::Deny, "deny"),
];

#[test]
fn verification_decision_json_form_pinned_per_variant() {
    for (variant, expected) in VERIFICATION_DECISION_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "REGISTRY-ACCEPTANCE REGRESSION: VerificationDecision token \
             drift on {variant:?} — registry audit logs filter on this exact string"
        );
    }
}

#[test]
fn verification_decision_json_and_cbor_roundtrip_per_variant() {
    for (variant, _) in VERIFICATION_DECISION_CASES {
        // JSON
        let json = serde_json::to_string(variant).expect("JSON serialize");
        let from_json: VerificationDecision =
            serde_json::from_str(&json).expect("JSON deserialize");
        assert_eq!(*variant, from_json);

        // CBOR
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("CBOR encode");
        let from_cbor: VerificationDecision =
            ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, from_cbor);
    }
}

#[test]
fn verification_decision_rejects_pascal_case_and_unknown() {
    for bad in [r#""Allow""#, r#""Deny""#, r#""ALLOW""#, r#""accept""#] {
        let parsed = serde_json::from_str::<VerificationDecision>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only snake_case `allow` / `deny` are canonical"
        );
    }
}

#[test]
fn verification_decision_count_is_two() {
    assert_eq!(
        VERIFICATION_DECISION_CASES.len(),
        2,
        "VerificationDecision has 2 documented variants — drift surfaces here"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. VerificationReasonCode — SCREAMING_SNAKE_CASE reason classifier
// ─────────────────────────────────────────────────────────────────────────────
//
// This enum carries `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`
// (NOT the snake_case used everywhere else). Pin a representative
// subset of variants — the exact format convention is the part that
// can drift silently and break registry log filters.

#[test]
fn verification_reason_code_uses_screaming_snake_case_format() {
    let cases = [
        (VerificationReasonCode::Verified, "VERIFIED"),
        (
            VerificationReasonCode::ArtifactDigestInvalid,
            "ARTIFACT_DIGEST_INVALID",
        ),
        (
            VerificationReasonCode::AttestationMissing,
            "ATTESTATION_MISSING",
        ),
        (
            VerificationReasonCode::AttestationInvalid,
            "ATTESTATION_INVALID",
        ),
        (
            VerificationReasonCode::SlsaLevelInsufficient,
            "SLSA_LEVEL_INSUFFICIENT",
        ),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "VerificationReasonCode case-convention drift on {variant:?} — \
             pinned at SCREAMING_SNAKE_CASE (NOT the snake_case used elsewhere)"
        );
        let back: VerificationReasonCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn verification_reason_code_rejects_lower_snake_case() {
    // The case convention is part of the wire contract; lower
    // snake_case MUST be rejected so a future rename_all swap is
    // immediately observable.
    for bad in [r#""verified""#, r#""attestation_missing""#] {
        let parsed = serde_json::from_str::<VerificationReasonCode>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — VerificationReasonCode is SCREAMING_SNAKE_CASE only"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ResumeDisposition — 4-variant verdict with documented .label()
// ─────────────────────────────────────────────────────────────────────────────

const RESUME_DISPOSITION_CASES: &[(ResumeDisposition, &str)] = &[
    (ResumeDisposition::Attach, "attach"),
    (ResumeDisposition::Retry, "retry"),
    (ResumeDisposition::Deny, "deny"),
    (ResumeDisposition::Reconcile, "reconcile"),
];

#[test]
fn resume_disposition_label_pinned_per_variant() {
    // ResumeDisposition::label() at connector_state.rs:1140 returns
    // a stable label used in logs and evidence — operator-facing and
    // pinned-at-pinning-time.
    for (variant, expected) in RESUME_DISPOSITION_CASES {
        assert_eq!(
            variant.label(),
            *expected,
            "AUDIT REGRESSION: ResumeDisposition.label() drift on {variant:?}"
        );
    }
}

#[test]
fn resume_disposition_label_agrees_with_serde_snake_case_tag() {
    // The hand-written `.label()` MUST match the rename_all
    // snake_case JSON tag byte-for-byte. Drift between them would
    // produce two different operator-facing tokens for the same
    // variant.
    for (variant, expected) in RESUME_DISPOSITION_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "ResumeDisposition serde tag drift on {variant:?}"
        );
        let stripped = json.trim_matches('"');
        assert_eq!(
            stripped,
            variant.label(),
            "label() vs serde tag MUST agree byte-for-byte for {variant:?}"
        );
    }
}

#[test]
fn resume_disposition_json_and_cbor_roundtrip_per_variant() {
    for (variant, _) in RESUME_DISPOSITION_CASES {
        let json = serde_json::to_string(variant).expect("JSON serialize");
        let from_json: ResumeDisposition = serde_json::from_str(&json).expect("JSON deserialize");
        assert_eq!(*variant, from_json);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("CBOR encode");
        let from_cbor: ResumeDisposition =
            ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, from_cbor);
    }
}

#[test]
fn resume_disposition_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Attach""#,
        r#""DENY""#,
        r#""accept""#,
        r#""reconciliation""#,
    ] {
        let parsed = serde_json::from_str::<ResumeDisposition>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

#[test]
fn resume_disposition_variants_pairwise_distinct() {
    let mut seen_labels = std::collections::HashSet::new();
    for (_, label) in RESUME_DISPOSITION_CASES {
        assert!(seen_labels.insert(*label), "duplicate label {label:?}");
    }
    assert_eq!(seen_labels.len(), 4);
    for i in 0..RESUME_DISPOSITION_CASES.len() {
        for j in (i + 1)..RESUME_DISPOSITION_CASES.len() {
            assert_ne!(RESUME_DISPOSITION_CASES[i].0, RESUME_DISPOSITION_CASES[j].0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. ResumeOutcome — final accept/deny verdict
// ─────────────────────────────────────────────────────────────────────────────

const RESUME_OUTCOME_CASES: &[(ResumeOutcome, &str)] = &[
    (ResumeOutcome::Accepted, "accepted"),
    (ResumeOutcome::Denied, "denied"),
];

#[test]
fn resume_outcome_json_form_pinned_per_variant() {
    for (variant, expected) in RESUME_OUTCOME_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(json, format!("\"{expected}\""));
    }
}

#[test]
fn resume_outcome_roundtrip_per_variant() {
    for (variant, _) in RESUME_OUTCOME_CASES {
        let json = serde_json::to_string(variant).expect("JSON serialize");
        let back: ResumeOutcome = serde_json::from_str(&json).expect("JSON deserialize");
        assert_eq!(*variant, back);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("CBOR encode");
        let from_cbor: ResumeOutcome =
            ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, from_cbor);
    }
}

#[test]
fn resume_outcome_token_is_past_tense_not_imperative() {
    // ResumeOutcome is the FINAL verdict (past tense),
    // ResumeDisposition is the CHOSEN action (present tense / verb).
    // Pin the lexical distinction since both surfaces feed into the
    // same audit log.
    let outcome_json = serde_json::to_string(&ResumeOutcome::Accepted).unwrap();
    let disposition_json = serde_json::to_string(&ResumeDisposition::Attach).unwrap();
    assert_eq!(outcome_json, r#""accepted""#);
    assert!(
        outcome_json.contains("ed"),
        "ResumeOutcome variants are past-tense (`accepted` / `denied`)"
    );
    assert!(
        !disposition_json.contains("ed"),
        "ResumeDisposition variants are imperative verbs (`attach` / `retry` / `deny` / `reconcile`)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PolicyPreviewDecision — 3-variant preview verdict (RequireApproval)
// ─────────────────────────────────────────────────────────────────────────────

const POLICY_PREVIEW_CASES: &[(PolicyPreviewDecision, &str)] = &[
    (PolicyPreviewDecision::Allow, "allow"),
    (PolicyPreviewDecision::Deny, "deny"),
    (PolicyPreviewDecision::RequireApproval, "require_approval"),
];

#[test]
fn policy_preview_decision_json_form_pinned_per_variant() {
    for (variant, expected) in POLICY_PREVIEW_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "PolicyPreviewDecision tag drift on {variant:?}"
        );
    }
}

#[test]
fn policy_preview_decision_require_approval_uses_underscore() {
    let json = serde_json::to_string(&PolicyPreviewDecision::RequireApproval).unwrap();
    assert_eq!(json, r#""require_approval""#);
    assert!(!json.contains('-'), "snake_case MUST NOT use hyphens");
}

#[test]
fn policy_preview_decision_roundtrip_per_variant() {
    for (variant, _) in POLICY_PREVIEW_CASES {
        let json = serde_json::to_string(variant).expect("JSON serialize");
        let back: PolicyPreviewDecision = serde_json::from_str(&json).expect("JSON deserialize");
        assert_eq!(*variant, back);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("CBOR encode");
        let from_cbor: PolicyPreviewDecision =
            ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, from_cbor);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Cross-enum: shared `deny` token convention is consistent
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn deny_token_shared_across_acceptance_enums_is_consistent() {
    // VerificationDecision::Deny, ResumeDisposition::Deny, and
    // PolicyPreviewDecision::Deny all serialize to `"deny"`. Pin
    // that — operator dashboards filter on this single token across
    // multiple registry/preview/resume audit streams.
    assert_eq!(
        serde_json::to_string(&VerificationDecision::Deny).unwrap(),
        r#""deny""#
    );
    assert_eq!(
        serde_json::to_string(&ResumeDisposition::Deny).unwrap(),
        r#""deny""#
    );
    assert_eq!(
        serde_json::to_string(&PolicyPreviewDecision::Deny).unwrap(),
        r#""deny""#
    );
}

#[test]
fn allow_token_shared_across_acceptance_enums_is_consistent() {
    assert_eq!(
        serde_json::to_string(&VerificationDecision::Allow).unwrap(),
        r#""allow""#
    );
    assert_eq!(
        serde_json::to_string(&PolicyPreviewDecision::Allow).unwrap(),
        r#""allow""#
    );
    // ResumeDisposition has no Allow — the affirmative is `attach` /
    // `retry`. Pin that absence.
    let json = serde_json::to_string(&ResumeDisposition::Attach).unwrap();
    assert_ne!(
        json, r#""allow""#,
        "ResumeDisposition uses `attach` / `retry` instead of `allow`"
    );
}
