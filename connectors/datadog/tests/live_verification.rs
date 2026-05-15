//! Environment-gated live verification for the `Datadog` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_datadog::{client::DatadogRegion, connector::DatadogConnector};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const SITE_ENV: &str = "DATADOG_SANDBOX_SITE";
const API_KEY_ENV: &str = "DATADOG_SANDBOX_API_KEY";
const APP_KEY_ENV: &str = "DATADOG_SANDBOX_APP_KEY";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_EVENTS_LIST: &str = "datadog.events.list";
const OP_EVENTS_CREATE: &str = "datadog.events.create";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("datadog", "Datadog sandbox")
        .with_env_secret(
            "api_key",
            API_KEY_ENV,
            "Datadog API key scoped to the sandbox organization",
        )
        .with_env_secret(
            "app_key",
            APP_KEY_ENV,
            "Datadog application key scoped to the sandbox organization",
        )
        .with_env_var(
            SITE_ENV,
            "Datadog sandbox site, region alias, or API base URL",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in Datadog event tags and evidence",
        )
        .with_account_setup(
            "Use a dedicated Datadog sandbox organization; this suite creates one namespaced event.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
        .with_metadata("request_categories", json!(["events.list", "events.create"]))
        .with_metadata("provider_ingestion_ceiling", json!("one low-priority event"))
}

#[fcp_async_core::runtime::test]
async fn live_verification_lists_events_when_enabled() {
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

    let connector = configured_connector(&env).await;
    let now = Utc::now();
    let events = invoke(
        &connector,
        OP_EVENTS_LIST,
        json!({
            "start": (now - ChronoDuration::hours(1)).timestamp(),
            "end": now.timestamp()
        }),
    )
    .await
    .inspect_err(|error| {
        emit_live_jsonl(
            "failed",
            &error.to_string(),
            0,
            false,
            &env.evidence_summary(),
        );
    })
    .expect("list live Datadog events");
    let observed_count = events["events"].as_array().map_or(0, Vec::len);
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let event = invoke(
        &connector,
        OP_EVENTS_CREATE,
        json!({
            "title": format!("FCP sandbox verification {namespace}"),
            "text": "FCP Datadog live verification sandbox event. No production data.",
            "priority": "low",
            "alert_type": "info",
            "source_type_name": "fcp",
            "tags": [
                "fcp_connector:datadog",
                "fcp_live_verification:true",
                format!("fcp_namespace:{namespace}")
            ]
        }),
    )
    .await;
    match event {
        Ok(_) => emit_live_jsonl(
            "passed",
            "events.list and events.create completed",
            observed_count,
            true,
            &json!({
                "environment": env.evidence_summary(),
                "operation_result": "datadog.events.list and datadog.events.create completed",
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
            panic!("create live Datadog sandbox event failed: {error}");
        }
    }
}

async fn configured_connector(env: &LiveEnvironment) -> DatadogConnector {
    let mut connector = DatadogConnector::new();
    connector
        .handle_configure(json!({
            "api_key": env.secrets.require("api_key"),
            "app_key": env.secrets.require("app_key"),
            "base_url": base_url_from_site(env.env_vars.get(SITE_ENV).expect("site env is ready"))
        }))
        .await
        .expect("configure live connector");
    connector
        .handle_handshake(json!({"session_id": "datadog-live-session"}))
        .await
        .expect("handshake live connector");
    connector
}

async fn invoke(
    connector: &DatadogConnector,
    operation: &'static str,
    input: Value,
) -> Result<Value, fcp_prelude::FcpError> {
    connector
        .handle_invoke(json!({
            "operation_id": operation,
            "input": input
        }))
        .await
}

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    event_attempted: bool,
    evidence: &Value,
) {
    eprintln!(
        "DATADOG_LIVE_SANDBOX_JSONL {}",
        json!({
            "connector": "datadog",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [API_KEY_ENV, APP_KEY_ENV],
            "required_env": [SITE_ENV, NAMESPACE_ENV],
            "operation": [OP_EVENTS_LIST, OP_EVENTS_CREATE],
            "status": status,
            "provider": "Datadog sandbox",
            "environment": "sandbox",
            "resource_class": "event_inventory_and_sandbox_event",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one bounded event list and one low-priority namespaced event create.",
            "mutation_expected": true,
            "cleanup_strategy": "immutable_event_artifact_recorded",
            "cleanup_result": if event_attempted { Some("datadog_events_are_immutable; namespaced artifact recorded") } else { None },
            "provider_project_class": "dedicated_sandbox",
            "request_category": ["events.list", "events.create"],
            "event_attempted": event_attempted,
            "dropped_or_budgeted_count": 0,
            "credential_material_logged": false,
            "site_logged": false,
            "event_id_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

fn base_url_from_site(site: &str) -> String {
    let raw = site.trim().trim_end_matches('/');
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return if raw.ends_with("/api/v1") {
            raw.to_string()
        } else {
            format!("{raw}/api/v1")
        };
    }

    let normalized = raw.strip_prefix("api.").unwrap_or(raw);
    if let Some(region) = DatadogRegion::parse_region(normalized) {
        return region.api_base_url().to_string();
    }

    match normalized {
        "datadoghq.com" => DatadogRegion::Us1.api_base_url().to_string(),
        "us3.datadoghq.com" => DatadogRegion::Us3.api_base_url().to_string(),
        "us5.datadoghq.com" => DatadogRegion::Us5.api_base_url().to_string(),
        "datadoghq.eu" => DatadogRegion::Eu1.api_base_url().to_string(),
        "ap1.datadoghq.com" => DatadogRegion::Ap1.api_base_url().to_string(),
        _ => format!("https://api.{normalized}/api/v1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_from_site_accepts_region_alias() {
        assert_eq!(base_url_from_site("eu1"), "https://api.datadoghq.eu/api/v1");
    }

    #[test]
    fn base_url_from_site_accepts_site_domain() {
        assert_eq!(
            base_url_from_site("us3.datadoghq.com"),
            "https://api.us3.datadoghq.com/api/v1"
        );
    }

    #[test]
    fn base_url_from_site_accepts_full_api_url() {
        assert_eq!(
            base_url_from_site("https://api.datadoghq.com/api/v1"),
            "https://api.datadoghq.com/api/v1"
        );
    }
}
