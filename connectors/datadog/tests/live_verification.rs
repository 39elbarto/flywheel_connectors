//! Environment-gated live verification for the `Datadog` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_datadog::connector::DatadogConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const API_KEY_ENV: &str = "DATADOG_API_KEY";
const APP_KEY_ENV: &str = "DATADOG_APP_KEY";
const BASE_URL_ENV: &str = "DATADOG_BASE_URL";
const VERIFY_LOGS_ENV: &str = "DATADOG_VERIFY_LOGS";
const LOG_QUERY_ENV: &str = "DATADOG_LOG_QUERY";
const OP_EVENTS_LIST: &str = "datadog.events.list";
const OP_LOGS_SEARCH: &str = "datadog.logs.search";

#[fcp_async_core::runtime::test]
async fn live_verification_lists_events_when_enabled() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let Some(api_key) = env_nonempty(API_KEY_ENV) else {
        emit_live_jsonl("skipped", &format!("{API_KEY_ENV} is not set"), 0);
        return;
    };
    let Some(app_key) = env_nonempty(APP_KEY_ENV) else {
        emit_live_jsonl("skipped", &format!("{APP_KEY_ENV} is not set"), 0);
        return;
    };
    let base_url =
        env_nonempty(BASE_URL_ENV).unwrap_or_else(|| "https://api.datadoghq.com/api/v1".into());

    let connector = configured_connector(&base_url, &api_key, &app_key).await;
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
    .expect("list live Datadog events");
    let mut observed_count = events["events"].as_array().map_or(0, Vec::len);

    let reason = if std::env::var(VERIFY_LOGS_ENV).ok().as_deref() == Some("1") {
        let Some(query) = env_nonempty(LOG_QUERY_ENV) else {
            emit_live_jsonl(
                "skipped",
                &format!("{LOG_QUERY_ENV} is not set"),
                observed_count,
            );
            return;
        };
        let logs = invoke(
            &connector,
            OP_LOGS_SEARCH,
            json!({
                "query": query,
                "from_ts": "now-1h",
                "to_ts": "now",
                "limit": 1
            }),
        )
        .await
        .expect("search live Datadog logs");
        observed_count = logs["logs"].as_array().map_or(observed_count, Vec::len);
        "events.list and logs.search completed"
    } else {
        "events.list completed"
    };

    emit_live_jsonl("passed", reason, observed_count);
}

async fn configured_connector(
    base_url: &str,
    datadog_api_key: &str,
    datadog_app_key: &str,
) -> DatadogConnector {
    let mut connector = DatadogConnector::new();
    connector
        .handle_configure(json!({
            "api_key": datadog_api_key,
            "app_key": datadog_app_key,
            "base_url": base_url
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

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV).ok().as_deref() == Some("1")
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize) {
    eprintln!(
        "DATADOG_LIVE_SANDBOX_JSONL {}",
        json!({
            "connector": "datadog",
            "suite_class": "live",
            "gate_env_var": LIVE_GATE_ENV,
            "credential_env_vars": [API_KEY_ENV, APP_KEY_ENV],
            "optional_env_vars": [BASE_URL_ENV, VERIFY_LOGS_ENV, LOG_QUERY_ENV],
            "status": status,
            "reason": reason,
            "observed_count": observed_count,
            "credential_material_logged": false,
            "base_url_logged": false,
            "query_logged": false
        })
    );
}
