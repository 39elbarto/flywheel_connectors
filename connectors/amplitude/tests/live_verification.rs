//! Environment-gated live verification for the Amplitude connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use fcp_amplitude::connector::AmplitudeConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const API_KEY_ENV: &str = "AMPLITUDE_SANDBOX_API_KEY";
const SECRET_KEY_ENV: &str = "AMPLITUDE_SANDBOX_SECRET_KEY";
const PROJECT_ID_ENV: &str = "AMPLITUDE_SANDBOX_PROJECT_ID";
const BASE_URL_ENV: &str = "AMPLITUDE_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_COHORTS_LIST: &str = "amplitude.cohorts.list";
const OP_HEALTH: &str = "amplitude.health";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("amplitude", "Amplitude sandbox")
        .with_env_secret(
            "api_key",
            API_KEY_ENV,
            "Amplitude API key scoped to the sandbox analytics project",
        )
        .with_env_secret(
            "secret_key",
            SECRET_KEY_ENV,
            "Amplitude secret key paired with the sandbox API key",
        )
        .with_env_var(
            PROJECT_ID_ENV,
            "Amplitude sandbox project id recorded for evidence scoping",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://amplitude.com/api/2",
            "Amplitude API endpoint for the sandbox project",
        )
        .with_account_setup(
            "Use a disposable Amplitude analytics project with read access to cohort metadata; do not point this suite at production behavioral analytics.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "AMPLITUDE_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "amplitude_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [API_KEY_ENV, SECRET_KEY_ENV],
            "required_env": [PROJECT_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": [OP_HEALTH, OP_COHORTS_LIST],
            "status": status,
            "provider": "Amplitude sandbox",
            "environment": "sandbox",
            "resource_class": "cohort_listing_and_health",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one idempotent auth health probe and one read-only cohort listing against the sandbox analytics project.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "project_id_logged": false,
            "request_category": ["health", "cohorts.list"],
            "idempotent_probe": OP_HEALTH,
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
async fn amplitude_live_sandbox_cohort_listing_or_structured_skip_jsonl() {
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

    let connector = configured_connector(&env).await;
    let _health = connector
        .handle_invoke(json!({
            "operation_id": OP_HEALTH,
            "input": {},
        }))
        .await
        .expect("check live Amplitude health");
    match connector
        .handle_invoke(json!({
            "operation_id": OP_COHORTS_LIST,
            "input": {},
        }))
        .await
    {
        Ok(value) => {
            let observed_count = value["cohorts"].as_array().map_or(0, Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "health and cohorts.list completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Amplitude sandbox cohort listing failed: {error}");
        }
    }
}

async fn configured_connector(env: &LiveEnvironment) -> AmplitudeConnector {
    let mut connector = AmplitudeConnector::new();
    connector
        .handle_configure(json!({
            "api_key": env.secrets.require("api_key"),
            "secret_key": env.secrets.require("secret_key"),
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
        }))
        .await
        .expect("configure Amplitude live connector");
    connector
        .handle_handshake(json!({"session_id": "live-verification"}))
        .await
        .expect("handshake Amplitude live connector");
    connector
}
