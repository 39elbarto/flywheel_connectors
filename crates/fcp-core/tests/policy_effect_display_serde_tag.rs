//! Pin the policy-effect-shaped preview delta tag contract.
//!
//! fcp-core does not expose a type literally named `PolicyEffect`. The exported
//! policy-change effect classifier is `PolicyPreviewDelta`, carried by
//! `PolicyPreviewEntry::delta`. It does not implement `Display`; the stable
//! operator-facing token is the serde scalar pinned here.

use ciborium::value::Value as CborValue;
use fcp_core::PolicyPreviewDelta;

const POLICY_EFFECT_CASES: &[(PolicyPreviewDelta, &str)] = &[
    (PolicyPreviewDelta::WouldAllow, "would_allow"),
    (PolicyPreviewDelta::WouldDeny, "would_deny"),
    (
        PolicyPreviewDelta::WouldRequireApproval,
        "would_require_approval",
    ),
    (PolicyPreviewDelta::ReasonChanged, "reason_changed"),
];

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
struct PreviewDeltaField {
    delta: PolicyPreviewDelta,
}

#[test]
fn policy_effect_json_tags_are_pinned_per_variant() {
    for (variant, expected) in POLICY_EFFECT_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "PolicyPreviewDelta serde tag drift on {variant:?}"
        );
    }
}

#[test]
fn policy_effect_json_and_cbor_roundtrip_preserves_variants() {
    for (variant, _) in POLICY_EFFECT_CASES {
        let json = serde_json::to_string(variant).expect("JSON serialize");
        let from_json: PolicyPreviewDelta =
            serde_json::from_str(&json).expect("JSON deserialize");
        assert_eq!(*variant, from_json, "JSON round-trip lost {variant:?}");

        let mut cbor = Vec::new();
        ciborium::ser::into_writer(variant, &mut cbor).expect("CBOR encode");
        let from_cbor: PolicyPreviewDelta =
            ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");
        assert_eq!(*variant, from_cbor, "CBOR round-trip lost {variant:?}");
    }
}

#[test]
fn policy_effect_cbor_tags_are_text_scalars() {
    for (variant, expected) in POLICY_EFFECT_CASES {
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(variant, &mut cbor).expect("CBOR encode");

        let value: CborValue = ciborium::de::from_reader(cbor.as_slice()).expect("CBOR value");
        assert_eq!(
            value,
            CborValue::Text((*expected).to_string()),
            "PolicyPreviewDelta MUST encode as CBOR Text({expected:?}) for {variant:?}"
        );
    }
}

#[test]
fn policy_effect_tokens_are_stable_inside_preview_delta_field() {
    for (variant, expected) in POLICY_EFFECT_CASES {
        let field = PreviewDeltaField { delta: *variant };
        let json = serde_json::to_value(&field).expect("serialize field");
        assert_eq!(
            json,
            serde_json::json!({ "delta": expected }),
            "PolicyPreviewEntry::delta token drift on {variant:?}"
        );

        let back: PreviewDeltaField = serde_json::from_value(json).expect("deserialize field");
        assert_eq!(back, field);
    }
}

#[test]
fn policy_effect_rejects_noncanonical_tags() {
    for bad in [
        r#""WouldAllow""#,
        r#""WouldRequireApproval""#,
        r#""would-allow""#,
        r#""require_approval""#,
        r#""allow""#,
        r#""deny""#,
        r#""would_skip""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<PolicyPreviewDelta>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected");
    }
}

#[test]
fn policy_effect_tokens_are_pairwise_distinct_and_count_is_four() {
    let mut seen = std::collections::HashSet::new();
    for (_, token) in POLICY_EFFECT_CASES {
        assert!(seen.insert(*token), "duplicate policy effect token {token}");
    }

    assert_eq!(
        seen.len(),
        4,
        "PolicyPreviewDelta has four documented effect variants"
    );
}
