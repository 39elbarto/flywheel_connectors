//! Environment-gated live verification for the `Home Assistant` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_homeassistant::client::{HomeAssistantAuth, HomeAssistantClient};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_TOKEN_ENV: &str = "HOMEASSISTANT_SANDBOX_ACCESS_TOKEN";
const BASE_URL_ENV: &str = "HOMEASSISTANT_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_STATES: &str = "homeassistant.list_states";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("homeassistant", "Home Assistant sandbox")
        .with_env_secret(
            "access_token",
            ACCESS_TOKEN_ENV,
            "Home Assistant long-lived access token scoped to the sandbox instance",
        )
        .with_env_var(
            BASE_URL_ENV,
            "Home Assistant sandbox REST base URL including the /api prefix",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_account_setup(
            "Use a disposable Home Assistant instance or sanitized LAN sandbox for connector verification.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "HOMEASSISTANT_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "homeassistant_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": ACCESS_TOKEN_ENV,
            "required_env": [BASE_URL_ENV, NAMESPACE_ENV],
            "operation": OP_LIST_STATES,
            "status": status,
            "provider": "Home Assistant sandbox",
            "environment": "sandbox",
            "resource_class": "state_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only state listing against the sandbox instance.",
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
async fn homeassistant_live_sandbox_state_listing_or_structured_skip_jsonl() {
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
    match client.list_states().await {
        Ok(value) => {
            let observed_count = value.as_array().map_or(0, std::vec::Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "homeassistant.list_states completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Home Assistant sandbox state listing failed: {error}");
        }
    }
    client.shutdown();
}

fn configured_client(env: &LiveEnvironment) -> HomeAssistantClient {
    HomeAssistantClient::new(
        HomeAssistantAuth::BearerToken(env.secrets.require("access_token").to_string()),
        Some(
            env.env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
        ),
    )
    .expect("construct Home Assistant live client")
}
