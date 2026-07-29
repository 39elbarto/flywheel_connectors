//! Environment-gated sandbox verification for the `HubSpot` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use fcp_hubspot::connector::HubSpotConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "HUBSPOT_SANDBOX_TOKEN";
const PORTAL_ID_ENV: &str = "HUBSPOT_SANDBOX_PORTAL_ID";
const BASE_URL_ENV: &str = "HUBSPOT_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_CONTACTS_LIST: &str = "hubspot.contacts.list";
const OP_CONTACTS_CREATE: &str = "hubspot.contacts.create";
const OP_CONTACTS_GET: &str = "hubspot.contacts.get";
const OP_CONTACTS_DELETE: &str = "hubspot.contacts.delete";
const CALL_CEILING: usize = 5;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-hubspot --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("hubspot", "HubSpot sandbox")
        .with_env_secret(
            "access_token",
            TOKEN_ENV,
            "HubSpot private app or OAuth token scoped to the sandbox portal",
        )
        .with_env_var(PORTAL_ID_ENV, "HubSpot sandbox portal id used for evidence scoping")
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(BASE_URL_ENV, "https://api.hubapi.com", "HubSpot API endpoint")
        .with_account_setup(
            "Use a dedicated HubSpot sandbox or developer test portal. This suite performs one invalid-token read, one contact listing, one namespaced contact create, one contact readback, and one cleanup delete.",
        )
        .with_budget(0.02)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
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
        "HUBSPOT_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "hubspot_live_sandbox_contact_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [PORTAL_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_CONTACTS_LIST,
                OP_CONTACTS_CREATE,
                OP_CONTACTS_GET,
                OP_CONTACTS_DELETE
            ],
            "status": status,
            "provider": "HubSpot sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_crm_contact",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token contact listing, one sandbox contact listing, one namespaced contact create, one readback, and one cleanup delete.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "contact.list",
                "contact.create",
                "contact.readback",
                "contact.delete"
            ],
            "auth_denial_verified": auth_denial_verified,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "portal_id_logged": false,
            "contact_id_logged": false,
            "contact_email_logged": false,
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
async fn hubspot_live_sandbox_contact_listing_or_structured_skip_jsonl() {
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
        "HubSpot invalid-token contact listing must be denied"
    );

    let mut connector = configured_connector(&env).await;
    let portal_id = env
        .env_vars
        .get(PORTAL_ID_ENV)
        .expect("portal id env is ready");
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let contact_key = short_hash(&format!("{namespace}:{}", Uuid::new_v4()));
    let email = format!("fcp-live-{contact_key}@example.com");

    let list = match invoke(
        &connector,
        OP_CONTACTS_LIST,
        json!({
            "limit": 1,
            "properties": ["email", "firstname", "lastname"]
        }),
    )
    .await
    {
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
            panic!("HubSpot sandbox contact listing failed: {error}");
        }
    };

    let create = match invoke(
        &connector,
        OP_CONTACTS_CREATE,
        json!({
            "properties": {
                "email": email,
                "firstname": "FCP",
                "lastname": format!("Live {contact_key}")
            }
        }),
    )
    .await
    {
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
                    "portal_hash": redacted_hash(portal_id),
                    "contact_email_hash": redacted_hash(&email),
                    "list_count": list["results"].as_array().map_or(0, Vec::len),
                }),
            );
            panic!("HubSpot sandbox contact create failed: {error}");
        }
    };

    let contact_id = create["contact"]["id"]
        .as_str()
        .or_else(|| create["id"].as_str())
        .expect("HubSpot contact create response includes id");
    let readback = match invoke(
        &connector,
        OP_CONTACTS_GET,
        json!({
            "contact_id": contact_id,
            "properties": ["email", "firstname", "lastname"]
        }),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                2,
                "readback_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "portal_hash": redacted_hash(portal_id),
                    "contact_hash": redacted_hash(contact_id),
                    "contact_email_hash": redacted_hash(&email),
                }),
            );
            panic!("HubSpot sandbox contact readback failed: {error}");
        }
    };

    match invoke(
        &connector,
        OP_CONTACTS_DELETE,
        json!({ "contact_id": contact_id }),
    )
    .await
    {
        Ok(delete) => {
            emit_live_jsonl(
                "passed",
                "",
                list["results"]
                    .as_array()
                    .map_or(3, |results| results.len().saturating_add(3)),
                "delete_completed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "portal_hash": redacted_hash(portal_id),
                    "contact_hash": redacted_hash(contact_id),
                    "contact_email_hash": redacted_hash(&email),
                    "list_count": list["results"].as_array().map_or(0, Vec::len),
                    "readback_present": readback.get("contact").is_some(),
                    "delete_result": delete,
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                3,
                "delete_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "portal_hash": redacted_hash(portal_id),
                    "contact_hash": redacted_hash(contact_id),
                    "contact_email_hash": redacted_hash(&email),
                    "readback_present": readback.get("contact").is_some(),
                }),
            );
            panic!("HubSpot sandbox contact cleanup failed: {error}");
        }
    }

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

async fn configured_connector(env: &LiveEnvironment) -> HubSpotConnector {
    configured_connector_with_token(env, env.secrets.require("access_token")).await
}

async fn configured_connector_with_token(
    env: &LiveEnvironment,
    access_token: &str,
) -> HubSpotConnector {
    let mut connector = HubSpotConnector::new();
    connector
        .handle_configure(json!({
            "access_token": access_token,
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready")
        }))
        .await
        .expect("configure live connector");
    connector
        .handle_handshake(json!({
            "session_id": format!("hubspot-live-{}", env.tenant.run_prefix())
        }))
        .await
        .expect("handshake live connector");
    connector
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let connector = configured_connector_with_token(env, "fcp-invalid-hubspot-live-token").await;
    invoke(
        &connector,
        OP_CONTACTS_LIST,
        json!({
            "limit": 1,
            "properties": ["email"]
        }),
    )
    .await
    .is_err()
}

async fn invoke(
    connector: &HubSpotConnector,
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

fn redacted_hash(value: &str) -> String {
    format!("sha256:{}", short_hash(value))
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest).chars().take(16).collect()
}
