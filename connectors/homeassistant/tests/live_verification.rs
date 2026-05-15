//! Environment-gated live verification for the `Home Assistant` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_homeassistant::client::{HomeAssistantAuth, HomeAssistantClient};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_TOKEN_ENV: &str = "HOMEASSISTANT_SANDBOX_TOKEN";
const BASE_URL_ENV: &str = "HOMEASSISTANT_SANDBOX_URL";
const ENTITY_ID_ENV: &str = "HOMEASSISTANT_SANDBOX_ENTITY_ID";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_STATES: &str = "homeassistant.list_states";
const OP_GET_STATE: &str = "homeassistant.get_state";
const OP_SET_STATE: &str = "homeassistant.set_state";
const CALL_CEILING: usize = 6;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-homeassistant --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("homeassistant", "Home Assistant sandbox")
        .with_env_secret(
            "access_token",
            ACCESS_TOKEN_ENV,
            "Home Assistant long-lived access token scoped to the sandbox instance",
        )
        .with_env_var(BASE_URL_ENV, "Home Assistant sandbox REST base URL including the /api prefix")
        .with_env_var(
            ENTITY_ID_ENV,
            "Dedicated Home Assistant sandbox entity id whose state can be safely overwritten and restored",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_account_setup(
            "Use a disposable Home Assistant instance or sanitized LAN sandbox. HOMEASSISTANT_SANDBOX_ENTITY_ID must point at a dedicated mutable entity whose original state can be restored after the test.",
        )
        .with_budget(0.02)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    cleanup_result: &str,
    auth_denial_verified: bool,
    evidence: &Value,
) {
    eprintln!(
        "HOMEASSISTANT_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "homeassistant_live_sandbox_state_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": ACCESS_TOKEN_ENV,
            "required_env": [BASE_URL_ENV, ENTITY_ID_ENV, NAMESPACE_ENV],
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_LIST_STATES,
                OP_GET_STATE,
                OP_SET_STATE,
                "homeassistant.restore_state"
            ],
            "status": status,
            "provider": "Home Assistant sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_entity_state",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token state listing, one state listing, one entity read, one namespaced state write, one readback, and one restore write.",
            "mutation_expected": true,
            "cleanup_strategy": "restore_original_state",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "state.list",
                "state.read",
                "state.write",
                "state.restore"
            ],
            "auth_denial_verified": auth_denial_verified,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "entity_id_logged": false,
            "state_value_logged": false,
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
async fn homeassistant_live_sandbox_state_listing_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            "not_started",
            false,
            &env.evidence_summary(),
        );
        return;
    }

    let auth_denial_verified = invalid_token_is_denied(&env).await;
    assert!(
        auth_denial_verified,
        "Home Assistant invalid-token state listing must be denied"
    );

    let client = configured_client(&env);
    let base_url = env
        .env_vars
        .get(BASE_URL_ENV)
        .expect("base URL env is ready");
    let entity_id = env
        .env_vars
        .get(ENTITY_ID_ENV)
        .expect("entity id env is ready");
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let marker = format!(
        "fcp-live-{}",
        short_hash(&format!("{namespace}:{}", Uuid::new_v4()))
    );

    let states = match client.list_states().await {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                0,
                "not_started",
                auth_denial_verified,
                &env.evidence_summary(),
            );
            panic!("Home Assistant sandbox state listing failed: {error}");
        }
    };

    let original = match client.get_state(entity_id).await {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                1,
                "not_started",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "entity_hash": redacted_hash(entity_id),
                    "list_count": states.as_array().map_or(0, Vec::len),
                }),
            );
            panic!("Home Assistant sandbox entity read failed: {error}");
        }
    };
    let original_state = original["state"]
        .as_str()
        .expect("Home Assistant state readback includes state")
        .to_string();
    let original_attributes = original
        .get("attributes")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match client
        .set_state(
            entity_id,
            &json!({
                "state": marker,
                "attributes": {
                    "fcp_live_namespace": namespace,
                    "fcp_live_marker_hash": redacted_hash(&marker)
                }
            }),
        )
        .await
    {
        Ok(_) => {}
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                2,
                "not_started",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "entity_hash": redacted_hash(entity_id),
                    "target_state_hash": redacted_hash(&marker),
                }),
            );
            panic!("Home Assistant sandbox entity state write failed: {error}");
        }
    }

    let readback = match client.get_state(entity_id).await {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                3,
                "readback_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "entity_hash": redacted_hash(entity_id),
                    "target_state_hash": redacted_hash(&marker),
                }),
            );
            panic!("Home Assistant sandbox entity readback failed: {error}");
        }
    };
    assert_eq!(
        readback["state"].as_str(),
        Some(marker.as_str()),
        "Home Assistant readback must return the namespaced state"
    );

    match client
        .set_state(
            entity_id,
            &json!({
                "state": original_state,
                "attributes": original_attributes
            }),
        )
        .await
    {
        Ok(restore) => {
            emit_live_jsonl(
                "passed",
                "",
                states
                    .as_array()
                    .map_or(5, |items| items.len().saturating_add(5)),
                "restore_completed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "entity_hash": redacted_hash(entity_id),
                    "target_state_hash": redacted_hash(&marker),
                    "original_state_hash": redacted_hash(&original_state),
                    "list_count": states.as_array().map_or(0, Vec::len),
                    "readback_matched": readback["state"].as_str() == Some(marker.as_str()),
                    "restore_present": restore.get("state").is_some(),
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                4,
                "restore_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "entity_hash": redacted_hash(entity_id),
                    "target_state_hash": redacted_hash(&marker),
                    "original_state_hash": redacted_hash(&original_state),
                }),
            );
            panic!("Home Assistant sandbox entity restore failed: {error}");
        }
    }
    client.shutdown();
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let client = configured_client_with_token(env, "fcp-invalid-homeassistant-live-token");
    let denied = client.list_states().await.is_err();
    client.shutdown();
    denied
}

fn configured_client(env: &LiveEnvironment) -> HomeAssistantClient {
    configured_client_with_token(env, env.secrets.require("access_token"))
}

fn configured_client_with_token(env: &LiveEnvironment, access_token: &str) -> HomeAssistantClient {
    HomeAssistantClient::new(
        HomeAssistantAuth::BearerToken(access_token.to_string()),
        Some(
            env.env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
        ),
    )
    .expect("construct Home Assistant live client")
}

fn redacted_hash(value: &str) -> String {
    format!("sha256:{}", short_hash(value))
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest).chars().take(16).collect()
}
