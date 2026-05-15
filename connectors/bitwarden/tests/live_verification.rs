//! Environment-gated live verification for the `Bitwarden` connector.

#![allow(clippy::missing_panics_doc)]

use fcp_bitwarden::connector::BitwardenConnector;
use serde_json::json;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "BITWARDEN_ACCESS_TOKEN";
const BASE_URL_ENV: &str = "BITWARDEN_BASE_URL";
const COLLECTION_ENV: &str = "BITWARDEN_COLLECTION_ID";
const CONNECTOR_ID: &str = "bitwarden";

#[fcp_async_core::runtime::test]
async fn live_verification_lists_collections_when_enabled() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let Some(token) = env_nonempty(TOKEN_ENV) else {
        emit_live_jsonl("skipped", &format!("{TOKEN_ENV} is not set"), 0);
        return;
    };
    let base_url = env_nonempty(BASE_URL_ENV).unwrap_or_else(|| "https://api.bitwarden.com".into());

    let mut connector = BitwardenConnector::new();
    connector
        .handle_configure(json!({
            "access_token": token,
            "base_url": base_url
        }))
        .await
        .expect("configure live connector");
    connector
        .handle_handshake(json!({"session_id": "bitwarden-live-verification"}))
        .await
        .expect("handshake live connector");

    let collections = connector
        .handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .expect("list live collections");
    let collection_count = collections["data"].as_array().map_or(0, Vec::len);

    if let Some(collection_id) = env_nonempty(COLLECTION_ENV) {
        let items = connector
            .handle_invoke(json!({
                "operation_id": "bitwarden.items.list",
                "input": {"collection_id": collection_id}
            }))
            .await
            .expect("list live collection items");
        emit_live_jsonl(
            "passed",
            "collections.list and items.list completed",
            items["data"].as_array().map_or(collection_count, Vec::len),
        );
    } else {
        emit_live_jsonl("passed", "collections.list completed", collection_count);
    }

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
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
        "BITWARDEN_LIVE_SANDBOX_JSONL {}",
        json!({
            "connector": CONNECTOR_ID,
            "suite_class": "live",
            "gate_env_var": LIVE_GATE_ENV,
            "credential_env_vars": [TOKEN_ENV],
            "optional_env_vars": [BASE_URL_ENV, COLLECTION_ENV],
            "status": status,
            "reason": reason,
            "observed_count": observed_count,
            "credential_material_logged": false
        })
    );
}
