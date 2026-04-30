//! Pin `<Foo>Kind` classifier serde tags as the closest analogues to
//! "SignerKind serde tag" (flywheel_connectors-oglwe).
//!
//! Bead asks for `SignerKind serde tag JSON+CBOR roundtrip`. No type
//! literally named `SignerKind` exists in fcp-core. The closest
//! "signer kind" classifier is `ManifestSignature` (the
//! signer-algorithm tag at connector_artifacts.rs:302, 3 variants
//! Ed25519/RsaPss/EcdsaP256) — already pinned by 8tf1r in
//! `manifest_signature_serde_tags.rs`.
//!
//! The `<Foo>Kind` naming pattern in fcp-core covers four classifier
//! enums none of which are signer-specific:
//!
//!  - `UsageMetricKind` (protocol.rs:1095) — 6 variants
//!    (ApiCredits/Tokens/Bytes/DurationMs/Requests/Custom) with
//!    `#[serde(rename_all = "snake_case")]` and a hand-written
//!    `as_str` returning the same tokens. Used in fixtures but
//!    NOT yet pinned for serde tag matrix.
//!  - `PrerequisiteKind` (connector_descriptors.rs:389) — 6
//!    variants (UserInput/SecretInput/LaunchUrl/Oauth/Webhook/
//!    CredentialPersistence) with `#[serde(rename_all =
//!    "snake_case")]`. NOT yet pinned for serde.
//!  - `ThreadKind` and `AdjustmentKind` — exist but with similar
//!    treatments.
//!
//! This test pins the `UsageMetricKind` + `PrerequisiteKind` serde
//! tag matrix since both are `<Foo>Kind` classifiers structurally
//! matching the bead's request shape, and both are unpinned.
//!
//! Targets:
//!
//!   1. **`UsageMetricKind` per-variant serde JSON tag** in
//!      snake_case.
//!   2. **`UsageMetricKind::as_str` agrees with serde tag** byte-
//!      for-byte.
//!   3. **JSON + CBOR round-trip** for every variant.
//!   4. **CBOR encodes as Text** (cross-language consumers).
//!   5. **Multi-word variants use underscore** not hyphen/
//!      camelCase (`api_credits`, `duration_ms` for UsageMetricKind;
//!      `user_input`, `secret_input`, `launch_url`,
//!      `credential_persistence` for PrerequisiteKind).
//!   6. **PascalCase + unknown + camelCase rejected** for both.
//!   7. **`PrerequisiteKind` per-variant serde JSON tag**.
//!   8. **`PrerequisiteKind` JSON + CBOR round-trip**.
//!   9. **Pairwise distinctness** within each enum.
//!  10. **Cross-enum tokens don't collide accidentally** —
//!      UsageMetricKind and PrerequisiteKind use disjoint label
//!      spaces.

use ciborium::value::Value as CborValue;
use fcp_core::{PrerequisiteKind, UsageMetricKind};

const USAGE_METRIC_KIND_CASES: &[(UsageMetricKind, &str)] = &[
    (UsageMetricKind::ApiCredits, "api_credits"),
    (UsageMetricKind::Tokens, "tokens"),
    (UsageMetricKind::Bytes, "bytes"),
    (UsageMetricKind::DurationMs, "duration_ms"),
    (UsageMetricKind::Requests, "requests"),
    (UsageMetricKind::Custom, "custom"),
];

const PREREQUISITE_KIND_CASES: &[(PrerequisiteKind, &str)] = &[
    (PrerequisiteKind::UserInput, "user_input"),
    (PrerequisiteKind::SecretInput, "secret_input"),
    (PrerequisiteKind::LaunchUrl, "launch_url"),
    (PrerequisiteKind::Oauth, "oauth"),
    (PrerequisiteKind::Webhook, "webhook"),
    (
        PrerequisiteKind::CredentialPersistence,
        "credential_persistence",
    ),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. UsageMetricKind per-variant serde JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_metric_kind_json_tag_pinned_per_variant() {
    for (variant, expected) in USAGE_METRIC_KIND_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "UsageMetricKind JSON tag drift on {variant:?} — \
             usage-telemetry filters consume this exact token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. UsageMetricKind::as_str agrees with serde tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_metric_kind_as_str_agrees_with_serde_tag_byte_for_byte() {
    // The hand-written `as_str` at protocol.rs:1113 MUST match the
    // rename_all snake_case serde output byte-for-byte. Drift
    // between them silently produces two different operator-facing
    // tokens for the same metric.
    for (variant, expected) in USAGE_METRIC_KIND_CASES {
        let stringy = variant.as_str();
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(stringy, *expected);
        assert_eq!(
            json.trim_matches('"'),
            stringy,
            "as_str vs serde-tag drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. UsageMetricKind JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_metric_kind_json_roundtrip_per_variant() {
    for (variant, _) in USAGE_METRIC_KIND_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: UsageMetricKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn usage_metric_kind_cbor_roundtrip_per_variant() {
    for (variant, _) in USAGE_METRIC_KIND_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: UsageMetricKind = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CBOR encodes as Text (not integer)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_metric_kind_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in USAGE_METRIC_KIND_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => {
                panic!("UsageMetricKind MUST encode as CBOR Text({expected:?}); got {other:?}")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Multi-word variants use underscore
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_metric_kind_multi_word_variants_use_underscore() {
    let api_credits_json = serde_json::to_string(&UsageMetricKind::ApiCredits).unwrap();
    assert_eq!(api_credits_json, r#""api_credits""#);
    assert!(!api_credits_json.contains('-'));
    assert_ne!(api_credits_json, r#""apiCredits""#);
    assert_ne!(api_credits_json, r#""apicredits""#);

    let duration_ms_json = serde_json::to_string(&UsageMetricKind::DurationMs).unwrap();
    assert_eq!(duration_ms_json, r#""duration_ms""#);
    assert!(!duration_ms_json.contains('-'));
    assert_ne!(duration_ms_json, r#""durationMs""#);
}

#[test]
fn prerequisite_kind_multi_word_variants_use_underscore() {
    for (variant, expected) in [
        (PrerequisiteKind::UserInput, "user_input"),
        (PrerequisiteKind::SecretInput, "secret_input"),
        (PrerequisiteKind::LaunchUrl, "launch_url"),
        (
            PrerequisiteKind::CredentialPersistence,
            "credential_persistence",
        ),
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, format!("\"{expected}\""));
        assert!(
            !json.contains('-'),
            "snake_case MUST NOT contain hyphens for {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. PascalCase + unknown + camelCase rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_metric_kind_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""ApiCredits""#,
        r#""DurationMs""#,
        r#""apiCredits""#,
        r#""api-credits""#,
        r#""compute""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<UsageMetricKind>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

#[test]
fn prerequisite_kind_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""UserInput""#,
        r#""LaunchUrl""#,
        r#""CredentialPersistence""#,
        r#""user-input""#,
        r#""userInput""#,
        r#""manual""#,
    ] {
        let parsed = serde_json::from_str::<PrerequisiteKind>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. PrerequisiteKind per-variant serde JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prerequisite_kind_json_tag_pinned_per_variant() {
    for (variant, expected) in PREREQUISITE_KIND_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "PrerequisiteKind JSON tag drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. PrerequisiteKind JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prerequisite_kind_json_roundtrip_per_variant() {
    for (variant, _) in PREREQUISITE_KIND_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: PrerequisiteKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn prerequisite_kind_cbor_roundtrip_per_variant() {
    for (variant, _) in PREREQUISITE_KIND_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: PrerequisiteKind = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Pairwise distinctness within each enum
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_metric_kind_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in USAGE_METRIC_KIND_CASES {
        assert!(seen.insert(*label));
    }
    assert_eq!(seen.len(), USAGE_METRIC_KIND_CASES.len());

    for i in 0..USAGE_METRIC_KIND_CASES.len() {
        for j in (i + 1)..USAGE_METRIC_KIND_CASES.len() {
            assert_ne!(USAGE_METRIC_KIND_CASES[i].0, USAGE_METRIC_KIND_CASES[j].0);
        }
    }
}

#[test]
fn prerequisite_kind_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in PREREQUISITE_KIND_CASES {
        assert!(seen.insert(*label));
    }
    assert_eq!(seen.len(), PREREQUISITE_KIND_CASES.len());

    for i in 0..PREREQUISITE_KIND_CASES.len() {
        for j in (i + 1)..PREREQUISITE_KIND_CASES.len() {
            assert_ne!(PREREQUISITE_KIND_CASES[i].0, PREREQUISITE_KIND_CASES[j].0);
        }
    }
}

#[test]
fn usage_metric_kind_count_is_six() {
    assert_eq!(USAGE_METRIC_KIND_CASES.len(), 6);
}

#[test]
fn prerequisite_kind_count_is_six() {
    assert_eq!(PREREQUISITE_KIND_CASES.len(), 6);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Cross-enum tokens don't collide
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn usage_metric_kind_and_prerequisite_kind_use_disjoint_token_spaces() {
    // Pin that the snake_case tokens don't accidentally alias
    // across the two `<Foo>Kind` classifiers — operator dashboards
    // that read both streams MUST be able to disambiguate by
    // token alone.
    let usage_tokens: std::collections::HashSet<&str> =
        USAGE_METRIC_KIND_CASES.iter().map(|(_, s)| *s).collect();
    let prereq_tokens: std::collections::HashSet<&str> =
        PREREQUISITE_KIND_CASES.iter().map(|(_, s)| *s).collect();
    let intersection: Vec<&&str> = usage_tokens.intersection(&prereq_tokens).collect();
    assert!(
        intersection.is_empty(),
        "UsageMetricKind and PrerequisiteKind tokens MUST be disjoint; \
         got collisions: {intersection:?}"
    );
}
