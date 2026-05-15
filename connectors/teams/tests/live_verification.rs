//! Environment-gated live verification for the Teams connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use std::time::Duration;

use fcp_teams::client::TeamsClient;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "TEAMS_SANDBOX_ACCESS_TOKEN";
const BASE_URL_ENV: &str = "TEAMS_SANDBOX_GRAPH_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_TEAMS: &str = "teams.list_teams";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("teams", "Microsoft Teams sandbox")
        .with_env_secret(
            "access_token",
            TOKEN_ENV,
            "Microsoft Graph access token scoped to the sandbox tenant",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://graph.microsoft.com/v1.0",
            "Microsoft Graph API endpoint",
        )
        .with_account_setup(
            "Use a dedicated Microsoft 365 tenant or sandbox account with read-only Teams Graph permissions.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "TEAMS_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "teams_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_LIST_TEAMS,
            "status": status,
            "provider": "Microsoft Teams sandbox",
            "environment": "sandbox",
            "resource_class": "team_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only /me/joinedTeams call against the sandbox tenant.",
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
async fn teams_live_sandbox_team_listing_or_structured_skip_jsonl() {
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
    match client.list_my_teams().await {
        Ok(teams) => {
            emit_live_jsonl(
                "passed",
                "",
                teams.len(),
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "teams.list_teams completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Teams sandbox team listing failed: {error}");
        }
    }
}

fn configured_client(env: &LiveEnvironment) -> TeamsClient {
    TeamsClient::new(
        env.env_vars
            .get(BASE_URL_ENV)
            .expect("base URL env is ready"),
        env.secrets.require("access_token"),
        Duration::from_secs(10),
    )
    .expect("construct Teams live client")
}
