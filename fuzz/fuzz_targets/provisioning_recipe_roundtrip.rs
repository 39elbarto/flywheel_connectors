#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{
    HumanPrompt, HumanPromptType, OAuthRecipe, ProvisioningProgress, ProvisioningRecipe,
    ProvisioningState, ProvisioningStatus, ProvisioningStep, ProvisioningStepResult,
    ProvisioningStepType, ProvisioningValidation, RecipeId, RetryConfig, SetupDescriptor, StepId,
    WebhookRecipe, WebhookVerification,
};
use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Once;

const MAX_STRING_LEN: usize = 96;
const MAX_VEC_LEN: usize = 8;

static ANCHORS: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    recipe_id: String,
    version: String,
    description: String,
    steps: Vec<StepSeed>,
    current_step: Option<String>,
    completed_steps: Vec<String>,
    remaining_steps: Vec<String>,
    prompts: Vec<PromptSeed>,
    error_message: Option<String>,
    valid: bool,
    validation_errors: Vec<String>,
    estimated_duration_ms: Option<u64>,
}

#[derive(Arbitrary, Debug)]
struct StepSeed {
    id: String,
    kind_disc: u8,
    requires_approval: bool,
    depends_on: Vec<String>,
    message: String,
    url: String,
    key: String,
    scope: String,
    value_from: String,
    scopes: Vec<String>,
    callback_port: u16,
    poll_interval_seconds: u64,
    verification_disc: u8,
    events: Vec<String>,
}

#[derive(Arbitrary, Debug)]
struct PromptSeed {
    step_id: String,
    prompt_disc: u8,
    message: String,
    url: Option<String>,
}

fn bounded(mut value: String) -> String {
    value.truncate(MAX_STRING_LEN);
    value
}

fn step_id(value: String) -> StepId {
    StepId::new(bounded(value))
}

fn bounded_vec(values: Vec<String>) -> Vec<String> {
    values.into_iter().take(MAX_VEC_LEN).map(bounded).collect()
}

fn build_oauth(seed: &StepSeed) -> OAuthRecipe {
    match seed.kind_disc % 3 {
        0 => OAuthRecipe::AuthorizationCodePkce {
            authorization_url: bounded(seed.url.clone()),
            token_url: bounded(seed.key.clone()),
            scopes: bounded_vec(seed.scopes.clone()),
            auto_browser: seed.requires_approval,
            callback_port: seed.callback_port,
        },
        1 => OAuthRecipe::DeviceCode {
            device_authorization_url: bounded(seed.url.clone()),
            token_url: bounded(seed.key.clone()),
            scopes: bounded_vec(seed.scopes.clone()),
            poll_interval_seconds: seed.poll_interval_seconds,
        },
        _ => OAuthRecipe::ClientCredentials {
            token_url: bounded(seed.url.clone()),
            scopes: bounded_vec(seed.scopes.clone()),
        },
    }
}

fn build_webhook_verification(seed: &StepSeed) -> WebhookVerification {
    match seed.verification_disc % 3 {
        0 => WebhookVerification::HmacSignature {
            algorithm: bounded(seed.key.clone()),
            header: bounded(seed.value_from.clone()),
        },
        1 => WebhookVerification::ChallengeResponse {
            challenge_param: bounded(seed.key.clone()),
        },
        _ => WebhookVerification::Ed25519Signature {
            public_key_header: bounded(seed.key.clone()),
        },
    }
}

fn build_step(seed: StepSeed) -> ProvisioningStep {
    let kind = match seed.kind_disc % 6 {
        0 => ProvisioningStepType::PromptUser {
            message: bounded(seed.message.clone()),
        },
        1 => ProvisioningStepType::PromptSecret {
            message: bounded(seed.message.clone()),
        },
        2 => ProvisioningStepType::OpenUrl {
            url: bounded(seed.url.clone()),
        },
        3 => ProvisioningStepType::StoreSecret {
            key: bounded(seed.key.clone()),
            value_from: step_id(seed.value_from.clone()),
            scope: bounded(seed.scope.clone()),
        },
        4 => ProvisioningStepType::Oauth {
            flow: build_oauth(&seed),
        },
        _ => ProvisioningStepType::Webhook {
            registration: WebhookRecipe {
                registration_url: bounded(seed.url.clone()),
                events: bounded_vec(seed.events.clone()),
                verification: build_webhook_verification(&seed),
                retry_policy: RetryConfig::default(),
            },
        },
    };

    let mut step = ProvisioningStep::new(step_id(seed.id), kind);
    for dependency in seed.depends_on.into_iter().take(MAX_VEC_LEN) {
        step = step.depends_on(step_id(dependency));
    }
    if seed.requires_approval {
        step = step.with_approval();
    }
    step
}

fn build_prompt(seed: PromptSeed) -> HumanPrompt {
    let prompt_type = match seed.prompt_disc % 4 {
        0 => HumanPromptType::Text,
        1 => HumanPromptType::Secret,
        2 => HumanPromptType::Approval,
        _ => HumanPromptType::Url,
    };
    HumanPrompt {
        step_id: step_id(seed.step_id),
        prompt_type,
        message: bounded(seed.message),
        url: seed.url.map(bounded),
    }
}

fn assert_json_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_value(value).expect("provisioning value must serialize");
    let decoded: T =
        serde_json::from_value(encoded.clone()).expect("provisioning value must deserialize");
    let reencoded = serde_json::to_value(decoded).expect("decoded value must serialize");
    assert_eq!(
        reencoded, encoded,
        "provisioning serde round-trip changed canonical JSON shape"
    );
}

fuzz_target!(|data: &[u8]| {
    ANCHORS.call_once(assert_anchors);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let mut recipe = ProvisioningRecipe::new(
        RecipeId::new(bounded(input.recipe_id)),
        bounded(input.version),
        bounded(input.description),
    );
    for seed in input.steps.into_iter().take(MAX_VEC_LEN) {
        recipe = recipe.with_step(build_step(seed));
    }
    assert_json_roundtrip(&recipe);

    let prompts: Vec<HumanPrompt> = input
        .prompts
        .into_iter()
        .take(MAX_VEC_LEN)
        .map(build_prompt)
        .collect();
    for prompt in &prompts {
        assert_json_roundtrip(prompt);
    }

    let current_step = input.current_step.map(step_id);
    let completed_steps = input
        .completed_steps
        .into_iter()
        .take(MAX_VEC_LEN)
        .map(step_id)
        .collect::<Vec<_>>();
    let remaining_steps = input
        .remaining_steps
        .into_iter()
        .take(MAX_VEC_LEN)
        .map(step_id)
        .collect::<Vec<_>>();

    let state = ProvisioningState {
        status: if input.valid {
            ProvisioningStatus::Completed
        } else {
            ProvisioningStatus::Failed
        },
        current_step: current_step.clone(),
        completed_steps: completed_steps.clone(),
        remaining_steps: remaining_steps.clone(),
        awaiting_human: prompts.clone(),
        error_message: input.error_message.map(bounded),
    };
    assert_json_roundtrip(&state);

    let progress = ProvisioningProgress {
        current_step: current_step.clone(),
        completed: completed_steps,
        remaining: remaining_steps,
        awaiting_human: prompts.clone(),
    };
    assert_json_roundtrip(&progress);

    let validation = if input.valid {
        ProvisioningValidation::ok()
    } else {
        ProvisioningValidation::failed(bounded_vec(input.validation_errors))
    };
    assert_json_roundtrip(&validation);

    let result = if let Some(prompt) = prompts.into_iter().next() {
        ProvisioningStepResult::AwaitingHuman { prompt }
    } else if input.valid {
        ProvisioningStepResult::Completed {
            step_id: current_step.unwrap_or_else(|| StepId::new("default-step")),
        }
    } else {
        ProvisioningStepResult::InProgress {
            step_id: current_step.unwrap_or_else(|| StepId::new("default-step")),
        }
    };
    assert_json_roundtrip(&result);

    let descriptor = SetupDescriptor {
        tool_descriptor: serde_json::json!({
            "name": recipe.id.as_str(),
            "version": recipe.version,
            "steps": recipe.steps.len(),
        }),
        human_prompts: Vec::new(),
        estimated_duration_ms: input.estimated_duration_ms,
    };
    assert_json_roundtrip(&descriptor);
});

fn assert_anchors() {
    let recipe = ProvisioningRecipe::new(RecipeId::new("github.setup"), "1", "GitHub setup")
        .with_step(ProvisioningStep::new(
            StepId::new("oauth"),
            ProvisioningStepType::Oauth {
                flow: OAuthRecipe::AuthorizationCodePkce {
                    authorization_url: "https://github.com/login/oauth/authorize".to_string(),
                    token_url: "https://github.com/login/oauth/access_token".to_string(),
                    scopes: vec!["repo".to_string(), "read:user".to_string()],
                    auto_browser: true,
                    callback_port: 8732,
                },
            },
        ))
        .with_step(
            ProvisioningStep::new(
                StepId::new("webhook"),
                ProvisioningStepType::Webhook {
                    registration: WebhookRecipe {
                        registration_url: "https://api.github.com/repos/o/r/hooks".to_string(),
                        events: vec!["push".to_string()],
                        verification: WebhookVerification::HmacSignature {
                            algorithm: "sha256".to_string(),
                            header: "x-hub-signature-256".to_string(),
                        },
                        retry_policy: RetryConfig::default(),
                    },
                },
            )
            .depends_on(StepId::new("oauth"))
            .with_approval(),
        );

    assert_eq!(recipe.steps.len(), 2);
    assert_eq!(recipe.steps[1].depends_on[0].as_str(), "oauth");
    assert!(recipe.steps[1].requires_approval);
    assert_json_roundtrip(&recipe);

    let default_state = ProvisioningState::default();
    assert_json_roundtrip(&default_state);
    assert_json_roundtrip(&ProvisioningValidation::ok());
    assert_json_roundtrip(&ProvisioningValidation::failed(vec![
        "missing webhook signing secret".to_string(),
    ]));
}
