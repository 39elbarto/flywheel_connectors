//! Pin the zone-rule variant Display and serde tag matrix.
//!
//! fcp-core does not expose a public type literally named `ZoneRule`.
//! The public variant surface for zone-policy rule outcomes is the
//! `DecisionReasonCode` zone-policy subset emitted by the policy engine:
//! deny-list hits and allow-list misses for principals, connectors, and
//! capabilities. These variants intentionally use dotted Display tokens while
//! serde uses snake_case enum tags.

use ciborium::value::Value as CborValue;
use fcp_core::DecisionReasonCode;

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
    for (variant, _, serde_tag) in ZONE_RULE_VARIANTS {
        let json = serde_json::to_string(variant).expect("serialize zone-rule variant");
        assert_eq!(
            json,
            format!("\"{serde_tag}\""),
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
    for (variant, _, serde_tag) in ZONE_RULE_VARIANTS {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(variant, &mut bytes).expect("encode zone-rule variant");

        let value: CborValue =
            ciborium::de::from_reader(bytes.as_slice()).expect("decode CBOR value");
        assert_eq!(
            value,
            CborValue::Text((*serde_tag).to_string()),
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
fn zone_rule_display_and_serde_forms_remain_distinct() {
    for (variant, display, serde_tag) in ZONE_RULE_VARIANTS {
        assert_ne!(
            display, serde_tag,
            "Zone-rule Display uses dotted operator tokens while serde uses snake_case: {variant:?}"
        );
        assert!(
            display.starts_with("zone_policy."),
            "Zone-rule Display must stay in the dotted zone_policy namespace: {variant:?}"
        );
        assert!(
            serde_tag.starts_with("zone_policy_"),
            "Zone-rule serde tag must stay in the snake_case zone_policy namespace: {variant:?}"
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
    let mut serde_tags = std::collections::HashSet::new();
    for (variant, display, serde_tag) in ZONE_RULE_VARIANTS {
        assert!(
            display_tokens.insert(*display),
            "duplicate Zone-rule Display token {display}"
        );
        assert!(
            serde_tags.insert(*serde_tag),
            "duplicate Zone-rule serde tag {serde_tag}"
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
fn zone_rule_rejects_display_tokens_as_serde_input() {
    for (_, display, serde_tag) in ZONE_RULE_VARIANTS {
        let display_json = format!("\"{display}\"");
        assert!(
            serde_json::from_str::<DecisionReasonCode>(&display_json).is_err(),
            "dotted Display token must not be accepted as serde input: {display}"
        );

        let serde_tag_json = format!("\"{serde_tag}\"");
        assert!(
            serde_json::from_str::<DecisionReasonCode>(&serde_tag_json).is_ok(),
            "canonical serde tag must be accepted: {serde_tag}"
        );
    }
}
