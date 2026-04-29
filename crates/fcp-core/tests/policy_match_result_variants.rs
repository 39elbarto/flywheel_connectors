//! Pin policy match result variants and Display labels.
//!
//! fcp-core does not expose a type named `PolicyMatchResult`; policy matching
//! outcomes are surfaced as `DecisionReasonCode` values produced by
//! `PolicyEngine`. This test pins the match-related subset of that public
//! result surface.

use std::collections::HashSet;

use fcp_core::DecisionReasonCode;

const POLICY_MATCH_RESULTS: &[(DecisionReasonCode, &str)] = &[
    (DecisionReasonCode::Allow, "allow"),
    (
        DecisionReasonCode::ZonePolicyPrincipalDenied,
        "zone_policy.principal_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyConnectorDenied,
        "zone_policy.connector_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyCapabilityDenied,
        "zone_policy.capability_denied",
    ),
    (
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed,
        "zone_policy.principal_not_allowed",
    ),
    (
        DecisionReasonCode::ZonePolicyConnectorNotAllowed,
        "zone_policy.connector_not_allowed",
    ),
    (
        DecisionReasonCode::ZonePolicyCapabilityNotAllowed,
        "zone_policy.capability_not_allowed",
    ),
];

#[test]
fn policy_match_result_display_tokens_are_pinned() {
    for (variant, token) in POLICY_MATCH_RESULTS {
        assert_eq!(
            variant.as_str(),
            *token,
            "stable policy match token drifted for {variant:?}"
        );
        assert_eq!(
            variant.to_string(),
            *token,
            "Display must emit the stable policy match token for {variant:?}"
        );
        assert_eq!(format!("{variant}"), *token);
    }
}

#[test]
fn policy_match_result_variants_are_pairwise_distinct() {
    for (index, (left, _)) in POLICY_MATCH_RESULTS.iter().enumerate() {
        for (right, _) in &POLICY_MATCH_RESULTS[index + 1..] {
            assert_ne!(
                left, right,
                "policy match result variants must remain distinct: {left:?} vs {right:?}"
            );
        }
    }
}

#[test]
fn policy_match_result_display_tokens_are_pairwise_distinct() {
    let tokens: HashSet<&'static str> = POLICY_MATCH_RESULTS
        .iter()
        .map(|(_, token)| *token)
        .collect();

    assert_eq!(
        tokens.len(),
        POLICY_MATCH_RESULTS.len(),
        "policy match Display tokens must remain unambiguous"
    );
}

#[test]
fn policy_match_result_variant_count_is_pinned() {
    assert_eq!(
        POLICY_MATCH_RESULTS.len(),
        7,
        "policy match result surface should cover allow plus six zone-policy match outcomes"
    );
}
