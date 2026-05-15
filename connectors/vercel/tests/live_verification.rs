//! Environment-gated live verification for the Vercel connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use std::time::Duration;

use fcp_sdk::migration::HttpRetryConfig;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use fcp_vercel::client::VercelClient;
use fcp_vercel::types::{TeamScope, VercelAuth};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "VERCEL_SANDBOX_TOKEN";
const TEAM_ID_ENV: &str = "VERCEL_SANDBOX_TEAM_ID";
const PROJECT_ID_ENV: &str = "VERCEL_SANDBOX_PROJECT_ID";
const BASE_URL_ENV: &str = "VERCEL_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_PROJECTS_LIST: &str = "vercel.projects.list";
const OP_PROJECTS_GET: &str = "vercel.projects.get";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("vercel", "Vercel sandbox")
        .with_env_secret(
            "access_token",
            TOKEN_ENV,
            "Vercel token scoped to the sandbox team",
        )
        .with_env_var(TEAM_ID_ENV, "Vercel sandbox team id used for read-only project listing")
        .with_env_var(
            PROJECT_ID_ENV,
            "Vercel sandbox project id used for read-only project lookup",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(BASE_URL_ENV, "https://api.vercel.com", "Vercel API endpoint")
        .with_account_setup(
            "Use a dedicated Vercel team for connector verification; do not point this suite at production projects.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "VERCEL_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "vercel_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [TEAM_ID_ENV, PROJECT_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": [OP_PROJECTS_LIST, OP_PROJECTS_GET],
            "status": status,
            "provider": "Vercel sandbox",
            "environment": "sandbox",
            "resource_class": "project_listing",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one read-only project listing and one project lookup against the sandbox team.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "team_id_logged": false,
            "project_id_logged": false,
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

fn no_retry_config() -> HttpRetryConfig {
    HttpRetryConfig {
        max_retries: 0,
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_enabled: false,
    }
}

#[fcp_async_core::runtime::test]
async fn vercel_live_sandbox_project_listing_or_structured_skip_jsonl() {
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
    match client.list_projects(Some(1)).await {
        Ok(value) => {
            let mut observed_count = value.projects.len();
            if let Err(error) = client
                .get_project(
                    env.env_vars
                        .get(PROJECT_ID_ENV)
                        .expect("project id env is ready"),
                )
                .await
            {
                emit_live_jsonl(
                    "failed",
                    &error.to_string(),
                    observed_count,
                    &env.evidence_summary(),
                );
                panic!("Vercel sandbox project lookup failed: {error}");
            }
            observed_count += 1;
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "projects.list and projects.get completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Vercel sandbox project listing failed: {error}");
        }
    }
    client.shutdown();
}

fn configured_client(env: &LiveEnvironment) -> VercelClient {
    VercelClient::new(
        VercelAuth::AccessToken {
            access_token: env.secrets.require("access_token").to_string(),
        },
        TeamScope {
            team_id: Some(
                env.env_vars
                    .get(TEAM_ID_ENV)
                    .expect("team id env is ready")
                    .to_string(),
            ),
            team_slug: None,
        },
        no_retry_config(),
        Duration::from_secs(10),
    )
    .expect("construct Vercel live client")
    .with_base_url(
        env.env_vars
            .get(BASE_URL_ENV)
            .expect("base URL env is ready"),
    )
}
