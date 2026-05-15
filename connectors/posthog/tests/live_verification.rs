//! Environment-gated live verification for the `PostHog` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_posthog::{
    client::{api_base_url_from_host, capture_url_from_host},
    connector::PostHogConnector,
};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const PERSONAL_API_KEY_ENV: &str = "POSTHOG_SANDBOX_PERSONAL_API_KEY";
const PROJECT_API_KEY_ENV: &str = "POSTHOG_SANDBOX_PROJECT_API_KEY";
const PROJECT_ID_ENV: &str = "POSTHOG_SANDBOX_PROJECT_ID";
const HOST_ENV: &str = "POSTHOG_SANDBOX_HOST";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_INSIGHTS: &str = "posthog.insights.list";
const OP_CAPTURE_EVENT: &str = "posthog.events.capture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("posthog", "PostHog sandbox")
        .with_env_secret(
            "personal_api_key",
            PERSONAL_API_KEY_ENV,
            "PostHog personal API key scoped to read the sandbox project",
        )
        .with_env_secret(
            "project_api_key",
            PROJECT_API_KEY_ENV,
            "PostHog project API key scoped to the sandbox project",
        )
        .with_env_var(
            PROJECT_ID_ENV,
            "PostHog sandbox project id used for read-only insight listing",
        )
        .with_env_var(HOST_ENV, "PostHog host/root URL for API and capture endpoints")
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_account_setup(
            "Use a disposable PostHog project or sanitized self-hosted workspace for connector verification; capture creates immutable analytics artifacts.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
        .with_metadata(
            "request_categories",
            json!(["personal_api_read", "project_token_capture"]),
        )
        .with_metadata("ingestion_suppression", json!("single namespaced sandbox event"))
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    capture_attempted: bool,
    evidence: &Value,
) {
    eprintln!(
        "POSTHOG_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "posthog_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [PERSONAL_API_KEY_ENV, PROJECT_API_KEY_ENV],
            "required_env": [HOST_ENV, PROJECT_ID_ENV, NAMESPACE_ENV],
            "operation": [OP_LIST_INSIGHTS, OP_CAPTURE_EVENT],
            "status": status,
            "provider": "PostHog sandbox",
            "environment": "sandbox",
            "resource_class": "insight_listing_and_sandbox_event",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one read-only insight listing and one namespaced sandbox event capture.",
            "mutation_expected": true,
            "cleanup_strategy": "immutable_event_artifact_recorded",
            "cleanup_result": if capture_attempted { Some("posthog_events_are_immutable; namespaced artifact recorded") } else { None },
            "provider_project_class": "dedicated_sandbox",
            "request_category": ["personal_api_read", "project_token_capture"],
            "capture_attempted": capture_attempted,
            "dropped_or_budgeted_count": 0,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "personal_api_key_logged": false,
            "project_api_key_logged": false,
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
            false,
            &env.evidence_summary(),
        );
        return;
    }

    let mut connector = configured_connector(&env).await;
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let list_result = connector
        .handle_invoke(json!({
            "operation_id": OP_LIST_INSIGHTS,
            "input": {}
        }))
        .await;
    let observed_count = match list_result {
        Ok(value) => value
            .get("results")
            .and_then(serde_json::Value::as_array)
            .map_or(0, std::vec::Vec::len),
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                0,
                false,
                &env.evidence_summary(),
            );
            panic!("PostHog sandbox insight listing failed: {error}");
        }
    };

    let capture_result = connector
        .handle_invoke(json!({
            "operation_id": OP_CAPTURE_EVENT,
            "input": {
                "event": format!("fcp_sandbox_verification_{namespace}"),
                "distinct_id": format!("fcp-sandbox-{namespace}"),
                "properties": {
                    "$process_person_profile": false,
                    "fcp_sandbox_namespace": namespace,
                    "fcp_connector": "posthog",
                    "source": "fcp-posthog-live-verification"
                }
            }
        }))
        .await;
    match capture_result {
        Ok(_) => emit_live_jsonl(
            "passed",
            "",
            observed_count,
            true,
            &json!({
                "environment": env.evidence_summary(),
                "operation_result": "posthog.insights.list and posthog.events.capture completed",
            }),
        ),
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                observed_count,
                true,
                &env.evidence_summary(),
            );
            panic!("PostHog sandbox event capture failed: {error}");
        }
    }
    connector.handle_shutdown(json!({})).await.unwrap();
}

async fn configured_connector(env: &LiveEnvironment) -> PostHogConnector {
    let host = env.env_vars.get(HOST_ENV).expect("host env is ready");
    let mut connector = PostHogConnector::new();
    connector
        .handle_configure(json!({
            "api_key": env.secrets.require("personal_api_key"),
            "project_api_key": env.secrets.require("project_api_key"),
            "project_id": env.env_vars.get(PROJECT_ID_ENV).expect("project id env is ready"),
            "base_url": api_base_url_from_host(host),
            "capture_url": capture_url_from_host(host),
        }))
        .await
        .expect("configure PostHog live connector");
    connector
        .handle_handshake(json!({"session_id": "posthog-live-sandbox"}))
        .await
        .expect("handshake PostHog live connector");
    connector
}
