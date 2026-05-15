//! Environment-gated live verification for the `PostHog` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_posthog::client::{PostHogAuth, PostHogClient};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const API_KEY_ENV: &str = "POSTHOG_SANDBOX_API_KEY";
const PROJECT_ID_ENV: &str = "POSTHOG_SANDBOX_PROJECT_ID";
const BASE_URL_ENV: &str = "POSTHOG_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_INSIGHTS: &str = "posthog.insights.list";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("posthog", "PostHog sandbox")
        .with_env_secret(
            "api_key",
            API_KEY_ENV,
            "PostHog API key scoped to the sandbox project",
        )
        .with_env_var(
            PROJECT_ID_ENV,
            "PostHog sandbox project id used for read-only insight listing",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(BASE_URL_ENV, "https://app.posthog.com/api", "PostHog API endpoint")
        .with_account_setup(
            "Use a disposable PostHog project or sanitized self-hosted workspace for connector verification.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "POSTHOG_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "posthog_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": API_KEY_ENV,
            "required_env": [PROJECT_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_LIST_INSIGHTS,
            "status": status,
            "provider": "PostHog sandbox",
            "environment": "sandbox",
            "resource_class": "insight_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only insight listing against the sandbox project.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

#[fcp_async_core::runtime::test]
async fn posthog_live_sandbox_insight_listing_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            &env.evidence_summary(),
        );
        return;
    }

    let client = configured_client(&env);
    match client.list_insights().await {
        Ok(value) => {
            let observed_count = value
                .get("results")
                .and_then(serde_json::Value::as_array)
                .map_or(0, std::vec::Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "posthog.insights.list completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("PostHog sandbox insight listing failed: {error}");
        }
    }
    client.shutdown();
}

fn configured_client(env: &LiveEnvironment) -> PostHogClient {
    PostHogClient::new(
        PostHogAuth::ApiKey(env.secrets.require("api_key").to_string()),
        env.env_vars
            .get(PROJECT_ID_ENV)
            .expect("project id env is ready"),
        Some(
            env.env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
        ),
    )
    .expect("construct PostHog live client")
}
