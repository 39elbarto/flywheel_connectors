//! Environment-gated live verification for the Grafana connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use fcp_grafana::connector::GrafanaConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "GRAFANA_SANDBOX_TOKEN";
const URL_ENV: &str = "GRAFANA_SANDBOX_URL";
const FOLDER_UID_ENV: &str = "GRAFANA_SANDBOX_FOLDER_UID";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_DATASOURCES_LIST: &str = "grafana.datasources.list";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("grafana", "Grafana sandbox")
        .with_env_secret(
            "auth_token",
            TOKEN_ENV,
            "Grafana service account token scoped to the sandbox stack",
        )
        .with_env_var(URL_ENV, "Grafana sandbox API base URL")
        .with_env_var(
            FOLDER_UID_ENV,
            "Dedicated Grafana folder UID reserved for connector-created dashboards",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_account_setup(
            "Use a dedicated Grafana Cloud stack or disposable self-hosted Grafana instance; never point this suite at production dashboards.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "GRAFANA_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "grafana_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [URL_ENV, FOLDER_UID_ENV, NAMESPACE_ENV],
            "operation": OP_DATASOURCES_LIST,
            "status": status,
            "provider": "Grafana sandbox",
            "environment": "sandbox",
            "resource_class": "datasource_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only datasource listing against the sandbox stack.",
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
async fn grafana_live_sandbox_datasource_listing_or_structured_skip_jsonl() {
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
    match connector
        .handle_invoke(json!({
            "operation_id": OP_DATASOURCES_LIST,
            "input": {},
        }))
        .await
    {
        Ok(value) => {
            let observed_count = value["datasources"].as_array().map_or(0, Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "datasources.list completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Grafana sandbox datasource listing failed: {error}");
        }
    }
}

async fn configured_connector(env: &LiveEnvironment) -> GrafanaConnector {
    let mut connector = GrafanaConnector::new();
    connector
        .handle_configure(json!({
            "auth_token": env.secrets.require("auth_token"),
            "base_url": env.env_vars.get(URL_ENV).expect("Grafana URL env is ready"),
        }))
        .await
        .expect("configure Grafana live connector");
    connector
        .handle_handshake(json!({"session_id": "live-verification"}))
        .await
        .expect("handshake Grafana live connector");
    connector
}
