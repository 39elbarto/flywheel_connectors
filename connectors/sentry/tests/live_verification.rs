//! Environment-gated live verification for the `Sentry` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_sentry::client::{SentryAuth, SentryClient};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const AUTH_TOKEN_ENV: &str = "SENTRY_SANDBOX_AUTH_TOKEN";
const ORG_SLUG_ENV: &str = "SENTRY_SANDBOX_ORG_SLUG";
const BASE_URL_ENV: &str = "SENTRY_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_PROJECTS: &str = "sentry.projects.list";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("sentry", "Sentry sandbox")
        .with_env_secret(
            "auth_token",
            AUTH_TOKEN_ENV,
            "Sentry API token scoped to read projects in the sandbox organization",
        )
        .with_env_var(
            ORG_SLUG_ENV,
            "Sentry sandbox organization slug used for read-only project listing",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(BASE_URL_ENV, "https://sentry.io/api/0", "Sentry API endpoint")
        .with_account_setup(
            "Use a disposable Sentry organization or sanitized self-hosted instance for connector verification.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "SENTRY_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "sentry_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": AUTH_TOKEN_ENV,
            "required_env": [ORG_SLUG_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_LIST_PROJECTS,
            "status": status,
            "provider": "Sentry sandbox",
            "environment": "sandbox",
            "resource_class": "project_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only project listing against the sandbox organization.",
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
async fn sentry_live_sandbox_project_listing_or_structured_skip_jsonl() {
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
    match client
        .list_projects(
            env.env_vars
                .get(ORG_SLUG_ENV)
                .expect("organization slug env is ready"),
            None,
        )
        .await
    {
        Ok(value) => {
            let observed_count = value.as_array().map_or(0, std::vec::Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "sentry.projects.list completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Sentry sandbox project listing failed: {error}");
        }
    }
    client.shutdown();
}

fn configured_client(env: &LiveEnvironment) -> SentryClient {
    SentryClient::new(
        SentryAuth::BearerToken(env.secrets.require("auth_token").to_string()),
        Some(
            env.env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
        ),
    )
    .expect("construct Sentry live client")
}
