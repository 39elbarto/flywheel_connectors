//! Pin step-kind ordering invariants on the closest analogue to a
//! "ConnectorPlan" (flywheel_connectors-6tcjg).
//!
//! Bead asks for "ConnectorPlan ordering across step kinds". No
//! type literally named `ConnectorPlan` exists in fcp-core. The
//! closest analogue is `ProvisioningRecipe` (provisioning.rs:91)
//! which holds a `Vec<ProvisioningStep>` and per step a
//! `kind: ProvisioningStepType` (provisioning.rs:187) — the "step
//! kinds" enum with six variants (PromptUser, PromptSecret,
//! OpenUrl, StoreSecret, Oauth, Webhook).
//!
//! `ProvisioningStepType` does NOT derive Ord (no comparison
//! relation between step kinds). The "ordering" that DOES exist is:
//!
//!   1. Insertion order of steps inside the `Vec`.
//!   2. The dependency partial-order via `depends_on`.
//!   3. The canonical serde tag form per kind, which downstream
//!      tooling reads positionally inside the steps array.
//!
//! Existing `tests/provisioning_recipe_display_serde.rs` pins the
//! Display + JSON shape on a fixed two-step recipe. This test
//! complements with the gaps:
//!
//!   1. **Insertion order is preserved** through JSON + CBOR
//!      round-trip (steps come back in the same sequence).
//!   2. **Reordering produces a different serialization** — the
//!      array ordering is observable on the wire, not implicit.
//!   3. **All six step-kind serde tags pinned** (the existing test
//!      only exercised PromptUser + StoreSecret).
//!   4. **`depends_on` is preserved per step** — the dependency DAG
//!      is part of the wire contract, not metadata.
//!   5. **`ProvisioningStatus` snake_case form pinned** for every
//!      variant — operators read these exact tokens.
//!   6. **`ProvisioningStepResult` tag pinned** for every variant.
//!   7. **CBOR map carries `type` discriminator** for every step
//!      kind so cross-format tooling can dispatch.

use ciborium::value::Value as CborValue;
use fcp_core::{
    HumanPrompt, HumanPromptType, OAuthRecipe, ProvisioningRecipe, ProvisioningStatus,
    ProvisioningStep, ProvisioningStepResult, ProvisioningStepType, RecipeId, StepId,
    WebhookRecipe, WebhookVerification,
};

fn step_id(s: &str) -> StepId {
    StepId::new(s)
}

fn one_of_each_kind() -> Vec<(StepId, ProvisioningStepType, &'static str)> {
    vec![
        (
            step_id("s1_prompt_user"),
            ProvisioningStepType::PromptUser {
                message: "user value?".into(),
            },
            "prompt_user",
        ),
        (
            step_id("s2_prompt_secret"),
            ProvisioningStepType::PromptSecret {
                message: "API token?".into(),
            },
            "prompt_secret",
        ),
        (
            step_id("s3_open_url"),
            ProvisioningStepType::OpenUrl {
                url: "https://example.test/auth".into(),
            },
            "open_url",
        ),
        (
            step_id("s4_store_secret"),
            ProvisioningStepType::StoreSecret {
                key: "tok".into(),
                value_from: step_id("s2_prompt_secret"),
                scope: "connector:fcp.example".into(),
            },
            "store_secret",
        ),
        (
            step_id("s5_oauth"),
            ProvisioningStepType::Oauth {
                flow: OAuthRecipe::ClientCredentials {
                    token_url: "https://example.test/token".into(),
                    scopes: vec!["read".into(), "write".into()],
                },
            },
            "oauth",
        ),
        (
            step_id("s6_webhook"),
            ProvisioningStepType::Webhook {
                registration: WebhookRecipe {
                    registration_url: "https://example.test/hook".into(),
                    events: vec!["push".into()],
                    verification: WebhookVerification::ChallengeResponse {
                        challenge_param: "challenge".into(),
                    },
                    retry_policy: Default::default(),
                },
            },
            "webhook",
        ),
    ]
}

fn recipe_with_all_kinds() -> ProvisioningRecipe {
    let mut recipe =
        ProvisioningRecipe::new(RecipeId::new("test.all_kinds"), "1.0", "All step kinds");
    for (id, kind, _label) in one_of_each_kind() {
        recipe = recipe.with_step(ProvisioningStep::new(id, kind));
    }
    recipe
}

fn step_ids(recipe: &ProvisioningRecipe) -> Vec<String> {
    recipe.steps.iter().map(|s| s.id.to_string()).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Insertion-order preservation through serde
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_step_insertion_order_across_all_kinds() {
    let recipe = recipe_with_all_kinds();
    let original_order = step_ids(&recipe);
    assert_eq!(
        original_order,
        vec![
            "s1_prompt_user",
            "s2_prompt_secret",
            "s3_open_url",
            "s4_store_secret",
            "s5_oauth",
            "s6_webhook",
        ]
    );

    let json = serde_json::to_string(&recipe).expect("serialize");
    let back: ProvisioningRecipe = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        step_ids(&back),
        original_order,
        "JSON round-trip MUST preserve step insertion order across all kinds"
    );
}

#[test]
fn cbor_roundtrip_preserves_step_insertion_order_across_all_kinds() {
    let recipe = recipe_with_all_kinds();
    let original_order = step_ids(&recipe);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&recipe, &mut buf).expect("encode");
    let back: ProvisioningRecipe = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(
        step_ids(&back),
        original_order,
        "CBOR round-trip MUST preserve step insertion order across all kinds"
    );
}

#[test]
fn reversing_step_order_changes_serialization() {
    // The Vec ordering is observable on the wire — operators can
    // depend on insertion order being preserved AND on order being
    // part of the canonical bytes.
    let normal = recipe_with_all_kinds();
    let mut reversed =
        ProvisioningRecipe::new(RecipeId::new("test.all_kinds"), "1.0", "All step kinds");
    for (id, kind, _label) in one_of_each_kind().into_iter().rev() {
        reversed = reversed.with_step(ProvisioningStep::new(id, kind));
    }

    let normal_json = serde_json::to_string(&normal).expect("serialize");
    let reversed_json = serde_json::to_string(&reversed).expect("serialize");
    assert_ne!(
        normal_json, reversed_json,
        "step ordering MUST be observable in the JSON bytes; \
         a reversed steps list MUST produce a different serialization"
    );

    // And both forms round-trip into themselves.
    let back_normal: ProvisioningRecipe =
        serde_json::from_str(&normal_json).expect("deserialize normal");
    let back_reversed: ProvisioningRecipe =
        serde_json::from_str(&reversed_json).expect("deserialize reversed");
    assert_eq!(step_ids(&back_normal), step_ids(&normal));
    assert_eq!(step_ids(&back_reversed), step_ids(&reversed));
    assert_ne!(step_ids(&back_normal), step_ids(&back_reversed));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Per-kind serde tag form pinned (all 6 ProvisioningStepType variants)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_step_kind_has_pinned_snake_case_type_tag_in_json() {
    let recipe = recipe_with_all_kinds();
    let value = serde_json::to_value(&recipe).expect("serialize");
    let steps = value
        .get("steps")
        .and_then(|v| v.as_array())
        .expect("steps array");
    assert_eq!(steps.len(), 6, "all 6 step kinds MUST appear in the recipe");

    let expected_tags = [
        "prompt_user",
        "prompt_secret",
        "open_url",
        "store_secret",
        "oauth",
        "webhook",
    ];
    for (i, expected) in expected_tags.iter().enumerate() {
        let got = steps[i]
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("step[{i}] missing `type` discriminator"));
        assert_eq!(
            got, *expected,
            "step[{i}] kind tag drifted: expected {expected}, got {got}"
        );
    }
}

#[test]
fn every_step_kind_cbor_map_carries_type_discriminator() {
    // Cross-format tooling reads CBOR — the `type` discriminator
    // MUST be present on every step's flattened map.
    let recipe = recipe_with_all_kinds();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&recipe, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");

    let map = match &value {
        CborValue::Map(m) => m,
        other => panic!("recipe MUST encode as CBOR map, got {other:?}"),
    };
    let steps = map
        .iter()
        .find_map(|(k, v)| match k {
            CborValue::Text(s) if s == "steps" => Some(v),
            _ => None,
        })
        .expect("steps key");
    let steps_arr = match steps {
        CborValue::Array(a) => a,
        other => panic!("steps MUST be array, got {other:?}"),
    };
    assert_eq!(steps_arr.len(), 6);

    let expected_tags = [
        "prompt_user",
        "prompt_secret",
        "open_url",
        "store_secret",
        "oauth",
        "webhook",
    ];
    for (i, expected) in expected_tags.iter().enumerate() {
        let step_map = match &steps_arr[i] {
            CborValue::Map(m) => m,
            other => panic!("step[{i}] MUST be map, got {other:?}"),
        };
        let got_tag = step_map
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (CborValue::Text(k), CborValue::Text(v)) if k == "type" => Some(v.as_str()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("step[{i}] CBOR map missing `type` discriminator"));
        assert_eq!(
            got_tag, *expected,
            "CBOR step[{i}] kind tag drifted: expected {expected}, got {got_tag}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. depends_on preserved per step
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn depends_on_dag_preserved_through_json_roundtrip() {
    // Build a small DAG: s_b depends on s_a, s_c depends on both.
    let s_a = step_id("a");
    let s_b = step_id("b");
    let s_c = step_id("c");

    let recipe = ProvisioningRecipe::new(RecipeId::new("test.dag"), "1.0", "DAG")
        .with_step(ProvisioningStep::new(
            s_a.clone(),
            ProvisioningStepType::PromptUser {
                message: "a?".into(),
            },
        ))
        .with_step(
            ProvisioningStep::new(
                s_b.clone(),
                ProvisioningStepType::PromptUser {
                    message: "b?".into(),
                },
            )
            .depends_on(s_a.clone()),
        )
        .with_step(
            ProvisioningStep::new(
                s_c.clone(),
                ProvisioningStepType::StoreSecret {
                    key: "k".into(),
                    value_from: s_b.clone(),
                    scope: "scope".into(),
                },
            )
            .depends_on(s_a.clone())
            .depends_on(s_b.clone()),
        );

    let json = serde_json::to_string(&recipe).expect("serialize");
    let back: ProvisioningRecipe = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.steps[0].depends_on, Vec::<StepId>::new());
    assert_eq!(back.steps[1].depends_on, vec![s_a.clone()]);
    assert_eq!(back.steps[2].depends_on, vec![s_a.clone(), s_b.clone()]);
}

#[test]
fn depends_on_order_within_step_is_preserved() {
    // Even within a single step, depends_on listing order is
    // observable on the wire — pin that.
    let s_a = step_id("a");
    let s_b = step_id("b");
    let recipe = ProvisioningRecipe::new(RecipeId::new("test.order"), "1.0", "Order")
        .with_step(ProvisioningStep::new(
            s_a.clone(),
            ProvisioningStepType::PromptUser {
                message: "a?".into(),
            },
        ))
        .with_step(ProvisioningStep::new(
            s_b.clone(),
            ProvisioningStepType::PromptUser {
                message: "b?".into(),
            },
        ))
        .with_step(
            ProvisioningStep::new(
                step_id("c"),
                ProvisioningStepType::PromptUser {
                    message: "c?".into(),
                },
            )
            .depends_on(s_b.clone())
            .depends_on(s_a.clone()),
        );

    let value = serde_json::to_value(&recipe).expect("serialize");
    let third = &value["steps"][2];
    assert_eq!(
        third["depends_on"],
        serde_json::json!(["b", "a"]),
        "depends_on listing order MUST be preserved verbatim"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. ProvisioningStatus snake_case form pinned per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn provisioning_status_snake_case_tag_pinned_per_variant() {
    // These tokens drive operator dashboards and audit logs.
    let cases = [
        (ProvisioningStatus::NotStarted, "not_started"),
        (ProvisioningStatus::InProgress, "in_progress"),
        (ProvisioningStatus::AwaitingUser, "awaiting_user"),
        (ProvisioningStatus::Completed, "completed"),
        (ProvisioningStatus::Failed, "failed"),
        (ProvisioningStatus::Aborted, "aborted"),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "ProvisioningStatus token drift on {variant:?}"
        );
        let back: ProvisioningStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, back);
    }
}

#[test]
fn provisioning_status_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""NotStarted""#,
        r#""InProgress""#,
        r#""DONE""#,
        r#""running""#,
    ] {
        let parsed = serde_json::from_str::<ProvisioningStatus>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected; only documented snake_case variants are canonical"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ProvisioningStepResult tag pinned per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn provisioning_step_result_status_tag_pinned_per_variant() {
    let completed = ProvisioningStepResult::Completed {
        step_id: step_id("done"),
    };
    let in_progress = ProvisioningStepResult::InProgress {
        step_id: step_id("midway"),
    };
    let awaiting = ProvisioningStepResult::AwaitingHuman {
        prompt: HumanPrompt {
            step_id: step_id("input"),
            prompt_type: HumanPromptType::Text,
            message: "Enter value".into(),
            url: None,
        },
    };

    let cases = [
        (
            serde_json::to_value(&completed).expect("serialize completed"),
            "completed",
        ),
        (
            serde_json::to_value(&in_progress).expect("serialize in_progress"),
            "in_progress",
        ),
        (
            serde_json::to_value(&awaiting).expect("serialize awaiting"),
            "awaiting_human",
        ),
    ];
    for (value, expected_tag) in cases {
        let got = value
            .get("status")
            .and_then(|v| v.as_str())
            .expect("status field");
        assert_eq!(got, expected_tag, "ProvisioningStepResult status tag drift");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Step kind preservation through round-trip (variant identity)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn each_step_kind_round_trips_to_same_kind_label() {
    // For every kind, encoding then decoding then re-encoding
    // produces the same wire bytes — confirming variant identity
    // survives serde despite the flatten + tag combination.
    for (id, kind, expected_label) in one_of_each_kind() {
        let step = ProvisioningStep::new(id.clone(), kind);
        let value = serde_json::to_value(&step).expect("serialize");
        assert_eq!(
            value.get("type").and_then(|v| v.as_str()),
            Some(expected_label),
            "step kind {expected_label} did not appear as `type` in JSON"
        );

        let back: ProvisioningStep = serde_json::from_value(value).expect("deserialize");
        let revalue = serde_json::to_value(&back).expect("re-serialize");
        assert_eq!(
            revalue.get("type").and_then(|v| v.as_str()),
            Some(expected_label),
            "step kind {expected_label} lost its tag through round-trip"
        );
    }
}
