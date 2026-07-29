//! Pin the zone-rule variant Display and serde tag matrix.
//!
//! fcp-core does not expose a public type literally named `ZoneRule`.
//! The public variant surface for zone-policy rule outcomes is the
//! `DecisionReasonCode` zone-policy subset emitted by the policy engine:
//! deny-list hits and allow-list misses for principals, connectors, and
//! capabilities. Since a258d6976 ("align `DecisionReasonCode` serde tags with
//! dotted Display form") the serde wire tag IS the dotted Display token; the
//! pre-alignment `snake_case` tags are legacy and must be rejected on the
//! wire.

use ciborium::value::Value as CborValue;
use fcp_core::DecisionReasonCode;

/// `(variant, canonical dotted token, legacy snake_case tag)`.
///
/// The dotted token is simultaneously the Display form and the serde wire
/// tag. The legacy tag is pinned only so we can assert it stays rejected.
const ZONE_RULE_VARIANTS: &[(DecisionReasonCode, &str, &str)] = &[
    (
        DecisionReasonCode::ZonePolicyPrincipalDenied,
        "zone_policy.principal_denied",
        "zone_policy_principal_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyConnectorDenied,
        "zone_policy.connector_denied",
        "zone_policy_connector_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyCapabilityDenied,
        "zone_policy.capability_denied",
        "zone_policy_capability_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed,
        "zone_policy.principal_not_allowed",
        "zone_policy_principal_not_allowed",
    ),
    (
        DecisionReasonCode::ZonePolicyConnectorNotAllowed,
        "zone_policy.connector_not_allowed",
        "zone_policy_connector_not_allowed",
    ),
    (
        DecisionReasonCode::ZonePolicyCapabilityNotAllowed,
        "zone_policy.capability_not_allowed",
        "zone_policy_capability_not_allowed",
    ),
];

#[test]
fn zone_rule_display_tokens_are_pinned() {
    for (variant, display, _) in ZONE_RULE_VARIANTS {
        assert_eq!(
            variant.as_str(),
            *display,
            "Zone-rule as_str token drifted for {variant:?}"
        );
        assert_eq!(
            variant.to_string(),
            *display,
            "Zone-rule Display token drifted for {variant:?}"
        );
        assert_eq!(
            format!("{variant}"),
            *display,
            "Zone-rule formatter drifted for {variant:?}"
        );
    }
}

#[test]
fn zone_rule_json_serde_tags_are_pinned() {
    for (variant, token, _) in ZONE_RULE_VARIANTS {
        let json = serde_json::to_string(variant).expect("serialize zone-rule variant");
        assert_eq!(
            json,
            format!("\"{token}\""),
            "Zone-rule serde JSON tag drifted for {variant:?}"
        );

        let decoded: DecisionReasonCode =
            serde_json::from_str(&json).expect("deserialize zone-rule variant");
        assert_eq!(
            decoded, *variant,
            "Zone-rule JSON roundtrip lost {variant:?}"
        );
    }
}

#[test]
fn zone_rule_cbor_serde_tags_are_text_and_roundtrip() {
    for (variant, token, _) in ZONE_RULE_VARIANTS {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(variant, &mut bytes).expect("encode zone-rule variant");

        let value: CborValue =
            ciborium::de::from_reader(bytes.as_slice()).expect("decode CBOR value");
        assert_eq!(
            value,
            CborValue::Text((*token).to_string()),
            "Zone-rule CBOR tag drifted for {variant:?}"
        );

        let decoded: DecisionReasonCode =
            ciborium::de::from_reader(bytes.as_slice()).expect("decode zone-rule variant");
        assert_eq!(
            decoded, *variant,
            "Zone-rule CBOR roundtrip lost {variant:?}"
        );
    }
}

#[test]
fn zone_rule_display_and_serde_forms_are_aligned() {
    for (variant, token, legacy_tag) in ZONE_RULE_VARIANTS {
        assert_eq!(
            variant.to_string(),
            serde_json::to_value(variant)
                .expect("serialize zone-rule variant")
                .as_str()
                .expect("zone-rule tag is a JSON string"),
            "Display token and serde wire tag must stay aligned (a258d6976): {variant:?}"
        );
        assert!(
            token.starts_with("zone_policy."),
            "Zone-rule canonical token must stay in the dotted zone_policy namespace: {variant:?}"
        );
        assert!(
            legacy_tag.starts_with("zone_policy_"),
            "Zone-rule legacy tag pin must stay in the snake_case namespace: {variant:?}"
        );
    }
}

#[test]
fn zone_rule_variant_count_and_distinctness_are_pinned() {
    assert_eq!(
        ZONE_RULE_VARIANTS.len(),
        6,
        "Zone-rule surface is principal/connector/capability deny plus allow-miss outcomes"
    );

    let mut display_tokens = std::collections::HashSet::new();
    let mut legacy_tags = std::collections::HashSet::new();
    for (variant, display, legacy_tag) in ZONE_RULE_VARIANTS {
        assert!(
            display_tokens.insert(*display),
            "duplicate Zone-rule Display token {display}"
        );
        assert!(
            legacy_tags.insert(*legacy_tag),
            "duplicate Zone-rule legacy tag {legacy_tag}"
        );

        for (other, _, _) in ZONE_RULE_VARIANTS {
            if variant != other {
                assert_ne!(
                    serde_json::to_string(variant).expect("serialize left"),
                    serde_json::to_string(other).expect("serialize right"),
                    "distinct Zone-rule variants serialized to the same tag"
                );
            }
        }
    }
}

#[test]
fn zone_rule_rejects_legacy_snake_case_tags_as_serde_input() {
    for (_, token, legacy_tag) in ZONE_RULE_VARIANTS {
        let legacy_json = format!("\"{legacy_tag}\"");
        assert!(
            serde_json::from_str::<DecisionReasonCode>(&legacy_json).is_err(),
            "legacy snake_case tag must not be accepted as serde input: {legacy_tag}"
        );

        let token_json = format!("\"{token}\"");
        assert!(
            serde_json::from_str::<DecisionReasonCode>(&token_json).is_ok(),
            "canonical dotted tag must be accepted: {token}"
        );
    }
}
