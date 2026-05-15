//! Environment-gated live verification for the `1Password` connector.

#![allow(clippy::missing_panics_doc)]

use fcp_onepassword::connector::OnePasswordConnector;
use serde_json::json;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "ONEPASSWORD_CONNECT_TOKEN";
const BASE_URL_ENV: &str = "ONEPASSWORD_CONNECT_BASE_URL";
const VAULT_ENV: &str = "ONEPASSWORD_CONNECT_VAULT_ID";
const CONNECTOR_ID: &str = "1password";

#[fcp_async_core::runtime::test]
async fn live_verification_lists_vaults_when_enabled() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let Some(token) = env_nonempty(TOKEN_ENV) else {
        emit_live_jsonl("skipped", &format!("{TOKEN_ENV} is not set"), 0);
        return;
    };
    let Some(base_url) = env_nonempty(BASE_URL_ENV) else {
        emit_live_jsonl("skipped", &format!("{BASE_URL_ENV} is not set"), 0);
        return;
    };

    let mut connector = OnePasswordConnector::new();
    connector
        .handle_configure(json!({
            "access_token": token,
            "base_url": base_url
        }))
        .await
        .expect("configure live connector");
    connector
        .handle_handshake(json!({"session_id": "1password-live-verification"}))
        .await
        .expect("handshake live connector");

    let vaults = connector
        .handle_invoke(json!({
            "operation_id": "1password.vaults.list",
            "input": {}
        }))
        .await
        .expect("list live vaults");
    let vault_count = vaults["vaults"].as_array().map_or(0, Vec::len);

    if let Some(vault_id) = env_nonempty(VAULT_ENV) {
        let items = connector
            .handle_invoke(json!({
                "operation_id": "1password.items.list",
                "input": {"vault_id": vault_id}
            }))
            .await
            .expect("list live vault items");
        emit_live_jsonl(
            "passed",
            "vaults.list and items.list completed",
            items["items"].as_array().map_or(vault_count, Vec::len),
        );
    } else {
        emit_live_jsonl("passed", "vaults.list completed", vault_count);
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
        "ONEPASSWORD_LIVE_SANDBOX_JSONL {}",
        json!({
            "connector": CONNECTOR_ID,
            "suite_class": "live",
            "gate_env_var": LIVE_GATE_ENV,
            "credential_env_vars": [TOKEN_ENV, BASE_URL_ENV],
            "optional_env_vars": [VAULT_ENV],
            "status": status,
            "reason": reason,
            "observed_count": observed_count,
            "credential_material_logged": false
        })
    );
}
