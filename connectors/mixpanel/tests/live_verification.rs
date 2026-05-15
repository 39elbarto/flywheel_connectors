//! Environment-gated live verification for the `Mixpanel` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use std::{
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use fcp_mixpanel::client::{MixpanelAuth, MixpanelClient};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const PROJECT_TOKEN_ENV: &str = "MIXPANEL_SANDBOX_PROJECT_TOKEN";
const SERVICE_ACCOUNT_USER_ENV: &str = "MIXPANEL_SANDBOX_SERVICE_ACCOUNT_USER";
const SERVICE_ACCOUNT_SECRET_ENV: &str = "MIXPANEL_SANDBOX_SERVICE_ACCOUNT_SECRET";
const PROJECT_ID_ENV: &str = "MIXPANEL_SANDBOX_PROJECT_ID";
const BASE_URL_ENV: &str = "MIXPANEL_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const DEFAULT_BASE_URL: &str = "https://mixpanel.com/api/2.0";
const DEFAULT_IMPORT_URL: &str = "https://api.mixpanel.com/import";
const OP_LIST_FUNNELS: &str = "mixpanel.funnels.list";
const OP_IMPORT_EVENT: &str = "mixpanel.events.import";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("mixpanel", "Mixpanel sandbox")
        .with_env_secret(
            "project_token",
            PROJECT_TOKEN_ENV,
            "Mixpanel project token for the dedicated sandbox project",
        )
        .with_env_secret(
            "service_account_secret",
            SERVICE_ACCOUNT_SECRET_ENV,
            "Mixpanel service account secret scoped to the sandbox project",
        )
        .with_env_var(
            SERVICE_ACCOUNT_USER_ENV,
            "Mixpanel service account username scoped to the sandbox project",
        )
        .with_env_var(
            PROJECT_ID_ENV,
            "Numeric Mixpanel project id required by service-account Query and Import APIs",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in synthetic event properties and evidence",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            DEFAULT_BASE_URL,
            "Mixpanel Query API base URL for the sandbox project",
        )
        .with_account_setup(
            "Use a dedicated Mixpanel sandbox project. This suite lists saved funnels and imports one namespaced synthetic event.",
        )
        .with_budget(0.02)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.2, true)
        .with_metadata("request_categories", json!(["funnels.list", "events.import"]))
        .with_metadata("provider_ingestion_ceiling", json!("one synthetic event"))
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    import_attempted: bool,
    evidence: &Value,
) {
    eprintln!(
        "MIXPANEL_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "mixpanel_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [PROJECT_TOKEN_ENV, SERVICE_ACCOUNT_SECRET_ENV],
            "required_env": [SERVICE_ACCOUNT_USER_ENV, PROJECT_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": [OP_LIST_FUNNELS, OP_IMPORT_EVENT],
            "status": status,
            "provider": "Mixpanel sandbox",
            "environment": "sandbox",
            "resource_class": "funnel_listing_and_synthetic_event",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one read-only funnel listing and imports one namespaced synthetic event.",
            "mutation_expected": true,
            "cleanup_strategy": "immutable_event_artifact_recorded",
            "cleanup_result": if import_attempted { Some("mixpanel_events_are_immutable; namespaced artifact recorded") } else { None },
            "provider_project_class": "dedicated_sandbox",
            "request_category": ["funnels.list", "events.import"],
            "event_import_attempted": import_attempted,
            "dropped_or_budgeted_count": 0,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "service_account_user_logged": false,
            "project_token_logged": false,
            "project_id_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

#[fcp_async_core::runtime::test]
async fn mixpanel_live_sandbox_funnel_listing_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        let reason = if gate.is_enabled() {
            env.problems().join("; ")
        } else {
            gate.skip_reason()
        };
        emit_live_jsonl("skipped", &reason, 0, false, &env.evidence_summary());
        return;
    }

    let client = configured_client(&env);
    match client.list_funnels().await {
        Ok(value) => {
            let observed_count = value
                .as_array()
                .map_or_else(
                    || value.get("funnels").and_then(serde_json::Value::as_array),
                    Some,
                )
                .map_or(0, std::vec::Vec::len);
            if let Err(error) = import_sandbox_event(&env).await {
                emit_live_jsonl(
                    "failed",
                    &error,
                    observed_count,
                    true,
                    &env.evidence_summary(),
                );
                panic!("Mixpanel sandbox synthetic event import failed: {error}");
            }
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                true,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "mixpanel.funnels.list and mixpanel.events.import completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                0,
                false,
                &env.evidence_summary(),
            );
            panic!("Mixpanel sandbox funnel listing failed: {error}");
        }
    }
    client.shutdown();
}

fn configured_client(env: &LiveEnvironment) -> MixpanelClient {
    MixpanelClient::new(
        MixpanelAuth::ServiceAccount {
            username: env
                .env_vars
                .get(SERVICE_ACCOUNT_USER_ENV)
                .expect("service account user env is ready")
                .to_string(),
            secret: env.secrets.require("service_account_secret").to_string(),
        },
        env.env_vars
            .get(PROJECT_ID_ENV)
            .expect("project id env is ready"),
        env.env_vars.get(BASE_URL_ENV),
    )
    .expect("construct Mixpanel live client")
}

async fn import_sandbox_event(env: &LiveEnvironment) -> Result<(), String> {
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let project_id = env
        .env_vars
        .get(PROJECT_ID_ENV)
        .expect("project id env is ready");
    let user = env
        .env_vars
        .get(SERVICE_ACCOUNT_USER_ENV)
        .expect("service account user env is ready");
    let secret = env.secrets.require("service_account_secret");
    let project_token = env.secrets.require("project_token");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let insert_id = format!("fcp-test-mixpanel-{namespace}-{now}-{}", process::id());
    let body = json!({
        "event": "fcp_sandbox_probe",
        "properties": {
            "token": project_token,
            "distinct_id": format!("fcp-test-mixpanel-{namespace}"),
            "time": now,
            "$insert_id": insert_id,
            "fcp_connector": "mixpanel",
            "fcp_sandbox_run_namespace": namespace,
            "fcp_live_verification": true,
        }
    });
    let response = reqwest::Client::new()
        .post(DEFAULT_IMPORT_URL)
        .basic_auth(user, Some(secret))
        .query(&[("strict", "1"), ("project_id", project_id)])
        .json(&body)
        .send()
        .await
        .map_err(|error| format!("mixpanel import request failed: {error}"))?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("mixpanel import returned HTTP {}", status.as_u16()))
    }
}
