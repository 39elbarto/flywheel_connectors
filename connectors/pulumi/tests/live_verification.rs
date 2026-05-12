//! Gated sandbox live verification for the FCP Pulumi connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::env;

use fcp_pulumi::connector::PulumiConnector;
use serde_json::json;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_TOKEN_ENV: &str = "PULUMI_SANDBOX_ACCESS_TOKEN";
const ORGANIZATION_ENV: &str = "PULUMI_SANDBOX_ORGANIZATION";
const PROJECT_ENV: &str = "PULUMI_SANDBOX_PROJECT";
const BASE_URL_ENV: &str = "PULUMI_SANDBOX_BASE_URL";
const DEFAULT_BASE_URL: &str = "https://api.pulumi.com/api";
const REQUIRED_ENV: [&str; 3] = [ACCESS_TOKEN_ENV, ORGANIZATION_ENV, PROJECT_ENV];

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn live_gate_enabled() -> bool {
    env_value(LIVE_GATE_ENV).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn print_skip(reason: &str, missing_env: &[&str]) {
    let artifact = json!({
        "connector": "pulumi",
        "suite_class": "live_sandbox",
        "acceptance_suite_class": "live",
        "live_gate": LIVE_GATE_ENV,
        "status": "skipped",
        "reason": reason,
        "missing_env": missing_env,
        "operation": "pulumi.stacks.list",
        "mutation": "none"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn gated_sandbox_stack_list_read_only() {
    if !live_gate_enabled() {
        print_skip("live gate disabled", &[LIVE_GATE_ENV]);
        return;
    }

    let missing_env = REQUIRED_ENV
        .iter()
        .copied()
        .filter(|name| env_value(name).is_none())
        .collect::<Vec<_>>();
    if !missing_env.is_empty() {
        print_skip("required sandbox environment missing", &missing_env);
        return;
    }

    let access_token = env_value(ACCESS_TOKEN_ENV).expect("checked access token env");
    let organization = env_value(ORGANIZATION_ENV).expect("checked organization env");
    let project = env_value(PROJECT_ENV).expect("checked project env");
    let base_url = env_value(BASE_URL_ENV).unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

    let mut connector = PulumiConnector::new();
    connector
        .handle_configure(json!({
            "access_token": access_token,
            "base_url": base_url
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({"session_id": "live-sandbox"}))
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {
                "organization": organization,
                "project": project
            }
        }))
        .await
        .expect("list sandbox Pulumi stacks");
    let stack_count = result["stacks"]
        .as_array()
        .expect("Pulumi stack list response includes stacks array")
        .len();

    let artifact = json!({
        "connector": "pulumi",
        "suite_class": "live_sandbox",
        "acceptance_suite_class": "live",
        "live_gate": LIVE_GATE_ENV,
        "status": "passed",
        "operation": "pulumi.stacks.list",
        "mutation": "none",
        "base_url_env_present": env_value(BASE_URL_ENV).is_some(),
        "organization_env_present": true,
        "project_env_present": true,
        "stack_count": stack_count
    });
    println!("{artifact}");
}
