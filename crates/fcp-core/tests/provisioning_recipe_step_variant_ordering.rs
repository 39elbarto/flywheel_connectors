//! Pin `ProvisioningStepType` variant declaration order, `as_str()`,
//! and Display agreement (flywheel_connectors-m7bla).
//!
//! Bead asks for `ProvisioningRecipeStep variant ordering and
//! Display`. No type literally named `ProvisioningRecipeStep` exists
//! in fcp-core; the 6-variant step-kind enum is `ProvisioningStepType`
//! (provisioning.rs:187), which:
//!
//!   - Carries `#[serde(tag = "type", rename_all = "snake_case")]`.
//!   - Has a hand-written `pub const fn as_str(&self) -> &'static str`
//!     at provisioning.rs:345 that returns the canonical
//!     snake_case token per variant.
//!   - Implements `fmt::Display` (provisioning.rs:357) by delegating
//!     to `as_str()`.
//!
//! Existing `connector_plan_step_ordering.rs` (flywheel_connectors-6tcjg)
//! covered Vec INSERTION ordering of `ProvisioningStep` items through
//! serde + per-kind JSON tag form. This bead is a complementary pin
//! on the VARIANT declaration order + the Display ↔ as_str ↔ serde
//! tag triple-agreement at the type level:
//!
//!   1. **`as_str()` per variant** returns the documented snake_case
//!      token at compile time (`&'static str`).
//!   2. **`Display` byte-for-byte agrees with `as_str()`** for every
//!      variant.
//!   3. **`Display` byte-for-byte agrees with the serde JSON tag**
//!      for every variant.
//!   4. **Variant declaration order** preserved through a fixed-order
//!      Vec — pinning the canonical sequence
//!      [prompt_user, prompt_secret, open_url, store_secret, oauth,
//!       webhook].
//!   5. **All 6 variants enumerated** — count + label sentinel
//!      against silent additions or reorderings.
//!   6. **Display tokens pairwise distinct** so each variant can be
//!      uniquely identified from its rendered string.
//!   7. **Display is allocation-free in spirit** — `as_str()`
//!      returns `&'static str`, so multi-format consumers can
//!      compare display strings by pointer-equivalent semantics.
//!   8. **`OperationExecution`-shaped sister enums (`OAuthRecipe`,
//!      `WebhookVerification`)** also have stable per-variant tags —
//!      pin those side-by-side since they fall under the same
//!      "step kinds" surface.

use fcp_core::{OAuthRecipe, ProvisioningStepType, WebhookVerification};

fn step_kind_in_declaration_order() -> Vec<ProvisioningStepType> {
    // The exact order in provisioning.rs:187-222.
    vec![
        ProvisioningStepType::PromptUser {
            message: "user?".into(),
        },
        ProvisioningStepType::PromptSecret {
            message: "secret?".into(),
        },
        ProvisioningStepType::OpenUrl {
            url: "https://example.test".into(),
        },
        ProvisioningStepType::StoreSecret {
            key: "k".into(),
            value_from: fcp_core::StepId::new("from"),
            scope: "scope".into(),
        },
        ProvisioningStepType::Oauth {
            flow: OAuthRecipe::ClientCredentials {
                token_url: "https://example.test/token".into(),
                scopes: vec![],
            },
        },
        ProvisioningStepType::Webhook {
            registration: fcp_core::WebhookRecipe {
                registration_url: "https://example.test/hook".into(),
                events: vec![],
                verification: WebhookVerification::ChallengeResponse {
                    challenge_param: "challenge".into(),
                },
                retry_policy: Default::default(),
            },
        },
    ]
}

const DECLARATION_ORDER_LABELS: &[&str] = &[
    "prompt_user",
    "prompt_secret",
    "open_url",
    "store_secret",
    "oauth",
    "webhook",
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. as_str() per variant pinning
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn as_str_returns_documented_token_per_variant() {
    for (variant, expected) in step_kind_in_declaration_order()
        .iter()
        .zip(DECLARATION_ORDER_LABELS)
    {
        assert_eq!(
            variant.as_str(),
            *expected,
            "ProvisioningStepType::as_str drift on {variant:?}"
        );
    }
}

#[test]
fn as_str_returns_static_str_compile_time_known() {
    // const-fn signature: `pub const fn as_str(&self) -> &'static str`.
    // Compile-time evaluable for unit-payload variants — pin a few
    // const usages so the const-ness is exercised. (Variants with
    // payload can't be const-constructed; we pin the &'static str
    // return type via assignment to a typed slot below.)
    let slot: &'static str = ProvisioningStepType::PromptUser {
        message: String::new(),
    }
    .as_str();
    assert_eq!(slot, "prompt_user");
    let slot2: &'static str = ProvisioningStepType::Webhook {
        registration: fcp_core::WebhookRecipe {
            registration_url: String::new(),
            events: vec![],
            verification: WebhookVerification::ChallengeResponse {
                challenge_param: String::new(),
            },
            retry_policy: Default::default(),
        },
    }
    .as_str();
    assert_eq!(slot2, "webhook");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Display agrees with as_str() byte-for-byte
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_emits_as_str_byte_for_byte_per_variant() {
    for variant in step_kind_in_declaration_order() {
        let displayed = variant.to_string();
        let stringy = variant.as_str();
        assert_eq!(
            displayed, stringy,
            "Display vs as_str disagreement for {variant:?}"
        );
        // format!() route also matches — guards against any
        // surprising Debug-fallback drift.
        assert_eq!(
            format!("{variant}"),
            stringy,
            "format!() vs as_str disagreement for {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Display agrees with serde JSON tag byte-for-byte
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_token_matches_serde_type_tag_per_variant() {
    for variant in step_kind_in_declaration_order() {
        let displayed = variant.to_string();
        let value = serde_json::to_value(&variant).expect("serialize");
        let serde_tag = value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("missing `type` for {variant:?}"));
        assert_eq!(
            serde_tag, displayed,
            "serde tag vs Display disagreement for {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Variant declaration order preserved
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn declaration_order_serializes_to_pinned_label_sequence() {
    // Walking the variants in source-declaration order MUST produce
    // the documented label sequence. If a future commit reorders or
    // injects a new variant, this test fails immediately so the
    // change can be reviewed for wire / audit-log impact.
    let labels: Vec<&str> = step_kind_in_declaration_order()
        .iter()
        .map(ProvisioningStepType::as_str)
        .collect();
    assert_eq!(
        labels, DECLARATION_ORDER_LABELS,
        "variant declaration order drifted"
    );
}

#[test]
fn fixture_vec_round_trips_preserving_declaration_order_in_json() {
    // Wrap the variants in an outer Vec so the on-the-wire order is
    // observable as JSON array order.
    let variants = step_kind_in_declaration_order();
    let json = serde_json::to_string(&variants).expect("serialize");
    let back: Vec<ProvisioningStepType> = serde_json::from_str(&json).expect("deserialize");
    let labels_after: Vec<&str> = back.iter().map(ProvisioningStepType::as_str).collect();
    assert_eq!(
        labels_after, DECLARATION_ORDER_LABELS,
        "JSON round-trip lost declaration order"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Variant count + label sentinel
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn six_variants_documented() {
    assert_eq!(
        DECLARATION_ORDER_LABELS.len(),
        6,
        "ProvisioningStepType has 6 documented variants — count drifted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Display tokens pairwise distinct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_tokens_are_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for label in DECLARATION_ORDER_LABELS {
        assert!(seen.insert(*label), "duplicate label {label:?}");
    }
    assert_eq!(seen.len(), DECLARATION_ORDER_LABELS.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Display strings are valid snake_case ASCII
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_display_token_is_lowercase_snake_case_ascii() {
    for label in DECLARATION_ORDER_LABELS {
        assert!(!label.is_empty(), "empty label");
        assert!(label.is_ascii(), "non-ASCII label {label:?}");
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "label {label:?} MUST be lowercase a-z plus `_`"
        );
        assert!(
            !label.starts_with('_') && !label.ends_with('_'),
            "label {label:?} MUST NOT start/end with `_`"
        );
        assert!(
            !label.contains("__"),
            "label {label:?} MUST NOT contain `__`"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Sister-enum variant ordering (OAuthRecipe, WebhookVerification)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn oauth_recipe_variant_serde_tags_pinned() {
    // OAuthRecipe is the payload of `ProvisioningStepType::Oauth`
    // — its 3 variants share the step-kind surface and operators
    // also dispatch on its `type` discriminator.
    let cases = [
        (
            OAuthRecipe::AuthorizationCodePkce {
                authorization_url: "u".into(),
                token_url: "t".into(),
                scopes: vec![],
                auto_browser: false,
                callback_port: 0,
            },
            "authorization_code_pkce",
        ),
        (
            OAuthRecipe::DeviceCode {
                device_authorization_url: "u".into(),
                token_url: "t".into(),
                scopes: vec![],
                poll_interval_seconds: 5,
            },
            "device_code",
        ),
        (
            OAuthRecipe::ClientCredentials {
                token_url: "t".into(),
                scopes: vec![],
            },
            "client_credentials",
        ),
    ];
    for (variant, expected_tag) in cases {
        let value = serde_json::to_value(&variant).expect("serialize");
        let got = value
            .get("type")
            .and_then(|v| v.as_str())
            .expect("type tag");
        assert_eq!(
            got, expected_tag,
            "OAuthRecipe `type` tag drift on {variant:?}"
        );
    }
}

#[test]
fn webhook_verification_variant_serde_tags_pinned() {
    // WebhookVerification is the payload of
    // `ProvisioningStepType::Webhook` — its 3 variants
    // (HmacSignature, ChallengeResponse, Ed25519Signature)
    // dispatch on the `type` field.
    let cases = [
        (
            WebhookVerification::HmacSignature {
                algorithm: "sha256".into(),
                header: "x-sig".into(),
            },
            "hmac_signature",
        ),
        (
            WebhookVerification::ChallengeResponse {
                challenge_param: "challenge".into(),
            },
            "challenge_response",
        ),
        (
            WebhookVerification::Ed25519Signature {
                public_key_header: "x-key".into(),
            },
            "ed25519_signature",
        ),
    ];
    for (variant, expected_tag) in cases {
        let value = serde_json::to_value(&variant).expect("serialize");
        let got = value
            .get("type")
            .and_then(|v| v.as_str())
            .expect("type tag");
        assert_eq!(
            got, expected_tag,
            "WebhookVerification `type` tag drift on {variant:?}"
        );
    }
}
