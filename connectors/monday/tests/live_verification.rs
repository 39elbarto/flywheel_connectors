//! Environment-gated live verification for the `Monday.com` connector.

#![allow(
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_monday::client::{MondayAuth, MondayClient};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const API_TOKEN_ENV: &str = "MONDAY_SANDBOX_API_TOKEN";
const BASE_URL_ENV: &str = "MONDAY_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_BOARDS: &str = "monday.boards.list";
const BEAD_ID: &str = "flywheel_connectors-sgxsn";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("monday", "Monday.com sandbox")
        .with_env_secret(
            "api_token",
            API_TOKEN_ENV,
            "Monday.com API token scoped to read boards in the sandbox workspace",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://api.monday.com/v2",
            "Monday.com GraphQL API endpoint",
        )
        .with_account_setup(
            "Use a disposable Monday.com workspace or sanitized test account for connector verification.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "MONDAY_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "monday_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": API_TOKEN_ENV,
            "required_env": [NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_LIST_BOARDS,
            "bead_id": BEAD_ID,
            "status": status,
            "provider": "Monday.com sandbox",
            "environment": "sandbox",
            "resource_class": "board_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only board listing against the sandbox workspace.",
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
async fn monday_live_sandbox_board_listing_or_structured_skip_jsonl() {
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
    match client.list_boards(1).await {
        Ok(value) => {
            let observed_count = value
                .get("boards")
                .and_then(serde_json::Value::as_array)
                .map_or(0, std::vec::Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "monday.boards.list completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Monday.com sandbox board listing failed: {error}");
        }
    }
    client.shutdown();
}

fn configured_client(env: &LiveEnvironment) -> MondayClient {
    MondayClient::new(
        MondayAuth::ApiToken(env.secrets.require("api_token").to_string()),
        Some(
            env.env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
        ),
    )
    .expect("construct Monday.com live client")
}
