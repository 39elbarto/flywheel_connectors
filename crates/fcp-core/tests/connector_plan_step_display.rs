use fcp_core::{OAuthRecipe, ProvisioningStepType, WebhookRecipe, WebhookVerification};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct StepDisplayCase {
    kind: ProvisioningStepType,
    display: &'static str,
}

fn connector_plan_step_display_cases() -> Vec<StepDisplayCase> {
    vec![
        StepDisplayCase {
            kind: ProvisioningStepType::PromptUser {
                message: "workspace name".into(),
            },
            display: "prompt_user",
        },
        StepDisplayCase {
            kind: ProvisioningStepType::PromptSecret {
                message: "api token".into(),
            },
            display: "prompt_secret",
        },
        StepDisplayCase {
            kind: ProvisioningStepType::OpenUrl {
                url: "https://example.test/authorize".into(),
            },
            display: "open_url",
        },
        StepDisplayCase {
            kind: ProvisioningStepType::StoreSecret {
                key: "api_token".into(),
                value_from: "capture_secret".into(),
                scope: "connector:fcp.example".into(),
            },
            display: "store_secret",
        },
        StepDisplayCase {
            kind: ProvisioningStepType::Oauth {
                flow: OAuthRecipe::ClientCredentials {
                    token_url: "https://example.test/token".into(),
                    scopes: vec!["read".into(), "write".into()],
                },
            },
            display: "oauth",
        },
        StepDisplayCase {
            kind: ProvisioningStepType::Webhook {
                registration: WebhookRecipe {
                    registration_url: "https://example.test/webhook".into(),
                    events: vec!["push".into()],
                    verification: WebhookVerification::ChallengeResponse {
                        challenge_param: "challenge".into(),
                    },
                    retry_policy: Default::default(),
                },
            },
            display: "webhook",
        },
    ]
}

#[test]
fn connector_plan_step_variant_display_format_is_pinned() {
    for case in connector_plan_step_display_cases() {
        assert_eq!(case.kind.to_string(), case.display);
        assert_eq!(case.kind.as_str(), case.display);
    }
}

#[test]
fn connector_plan_step_display_matches_json_type_discriminator() -> TestResult {
    for case in connector_plan_step_display_cases() {
        let value = serde_json::to_value(&case.kind)?;
        let type_tag = value
            .get("type")
            .and_then(|tag| tag.as_str())
            .ok_or("missing type discriminator")?;
        assert_eq!(type_tag, case.display);
        assert_eq!(case.kind.to_string(), type_tag);
    }

    Ok(())
}

#[test]
fn connector_plan_step_display_omits_payload_values() {
    for case in connector_plan_step_display_cases() {
        let display = case.kind.to_string();
        assert!(!display.contains("workspace name"));
        assert!(!display.contains("api token"));
        assert!(!display.contains("example.test"));
        assert!(!display.contains("connector:fcp.example"));
    }
}
