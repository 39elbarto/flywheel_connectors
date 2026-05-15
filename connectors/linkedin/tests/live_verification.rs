//! Environment-gated live verification for the `LinkedIn` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_linkedin::client::{LinkedInAuth, LinkedInClient};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_TOKEN_ENV: &str = "LINKEDIN_SANDBOX_ACCESS_TOKEN";
const BASE_URL_ENV: &str = "LINKEDIN_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_GET_PROFILE: &str = "linkedin.profile.get";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("linkedin", "LinkedIn sandbox")
        .with_env_secret(
            "access_token",
            ACCESS_TOKEN_ENV,
            "LinkedIn OAuth access token scoped to r_liteprofile for a sandbox member",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://api.linkedin.com/v2",
            "LinkedIn REST v2 API endpoint",
        )
        .with_account_setup(
            "Use a LinkedIn test application and member token with profile-read approval for connector verification.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, profile_seen: bool, evidence: &Value) {
    eprintln!(
        "LINKEDIN_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "linkedin_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": ACCESS_TOKEN_ENV,
            "required_env": [NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_GET_PROFILE,
            "status": status,
            "provider": "LinkedIn sandbox",
            "environment": "sandbox",
            "resource_class": "authenticated_profile",
            "profile_seen": profile_seen,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only authenticated profile request.",
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
async fn linkedin_live_sandbox_profile_get_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            false,
            &env.evidence_summary(),
        );
        return;
    }

    let client = configured_client(&env);
    match client.get_profile().await {
        Ok(value) => {
            let profile_seen = value.get("id").is_some();
            emit_live_jsonl(
                "passed",
                "",
                profile_seen,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "linkedin.profile.get completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), false, &env.evidence_summary());
            panic!("LinkedIn sandbox profile get failed: {error}");
        }
    }
    client.shutdown();
}

fn configured_client(env: &LiveEnvironment) -> LinkedInClient {
    LinkedInClient::new(
        LinkedInAuth::AccessToken(env.secrets.require("access_token").to_string()),
        Some(
            env.env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
        ),
    )
    .expect("construct LinkedIn live client")
}
