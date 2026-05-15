//! Environment-gated live verification for the `1Password` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::panic
)]

use fcp_onepassword::connector::OnePasswordConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "ONEPASSWORD_SANDBOX_CONNECT_TOKEN";
const BASE_URL_ENV: &str = "ONEPASSWORD_SANDBOX_CONNECT_URL";
const VAULT_ENV: &str = "ONEPASSWORD_SANDBOX_VAULT_ID";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CONNECTOR_ID: &str = "1password";
const OP_VAULTS_LIST: &str = "1password.vaults.list";
const OP_ITEMS_LIST: &str = "1password.items.list";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.1";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox(CONNECTOR_ID, "1Password Connect Server sandbox")
        .with_env_secret(
            "connect_token",
            TOKEN_ENV,
            "1Password Connect Server token scoped to a dedicated sandbox vault",
        )
        .with_env_var(BASE_URL_ENV, "1Password Connect Server sandbox base URL")
        .with_env_var(
            VAULT_ENV,
            "1Password sandbox vault id used for bounded item-list proof",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for sandbox-side artifacts",
        )
        .with_account_setup(
            "Use a dedicated 1Password Connect Server instance and sandbox vault. This suite performs read-only vault and item listings; write-path proof belongs in a separate namespaced create/delete flow.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    vault_count: usize,
    item_count: usize,
    evidence: &Value,
) {
    eprintln!(
        "ONEPASSWORD_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "onepassword_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [BASE_URL_ENV, VAULT_ENV, NAMESPACE_ENV],
            "operation": [OP_VAULTS_LIST, OP_ITEMS_LIST],
            "bead_id": BEAD_ID,
            "status": status,
            "provider": "1Password Connect Server sandbox",
            "environment": "sandbox",
            "resource_class": "vault_and_item_listing",
            "vault_count": vault_count,
            "item_count": item_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one vault listing and one item listing against a sandbox vault.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "vault_id_logged": false,
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
async fn onepassword_live_sandbox_lists_vault_and_items_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            0,
            &env.evidence_summary(),
        );
        return;
    }

    let mut connector = configured_connector(&env).await;
    let vaults = match connector
        .handle_invoke(json!({
            "operation_id": OP_VAULTS_LIST,
            "input": {}
        }))
        .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, 0, &env.evidence_summary());
            panic!("1Password sandbox vault listing failed: {error}");
        }
    };
    env.budget.record_api_call(OP_VAULTS_LIST, 0.0);
    let vault_count = vaults["vaults"].as_array().map_or(0, Vec::len);

    let items = match connector
        .handle_invoke(json!({
            "operation_id": OP_ITEMS_LIST,
            "input": {"vault_id": env.env_vars.get(VAULT_ENV).expect("vault env is ready")}
        }))
        .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                vault_count,
                0,
                &env.evidence_summary(),
            );
            panic!("1Password sandbox item listing failed: {error}");
        }
    };
    env.budget.record_api_call(OP_ITEMS_LIST, 0.0);
    let item_count = items["items"].as_array().map_or(0, Vec::len);

    emit_live_jsonl(
        "passed",
        "",
        vault_count,
        item_count,
        &json!({
            "environment": env.evidence_summary(),
            "operation_result": "vaults.list and items.list completed",
        }),
    );

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

async fn configured_connector(env: &LiveEnvironment) -> OnePasswordConnector {
    let mut connector = OnePasswordConnector::new();
    connector
        .handle_configure(json!({
            "access_token": env.secrets.require("connect_token"),
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready")
        }))
        .await
        .expect("configure live connector");
    connector
        .handle_handshake(json!({
            "session_id": format!("1password-live-{}", env.tenant.run_prefix())
        }))
        .await
        .expect("handshake live connector");
    connector
}
