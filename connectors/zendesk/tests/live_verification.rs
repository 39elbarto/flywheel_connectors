//! Environment-gated sandbox verification for the `Zendesk` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use fcp_zendesk::connector::ZendeskConnector;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const SUBDOMAIN_ENV: &str = "ZENDESK_SANDBOX_SUBDOMAIN";
const EMAIL_ENV: &str = "ZENDESK_SANDBOX_EMAIL";
const API_TOKEN_ENV: &str = "ZENDESK_SANDBOX_API_TOKEN";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_CREATE_TICKET: &str = "zendesk.create_ticket";
const OP_GET_TICKET: &str = "zendesk.get_ticket";
const OP_DELETE_TICKET: &str = "zendesk.delete_ticket";
const OP_SEARCH_TICKETS: &str = "zendesk.search_tickets";
const CALL_CEILING: usize = 5;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-zendesk --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("zendesk", "Zendesk sandbox")
        .with_env_secret(
            "api_token",
            API_TOKEN_ENV,
            "Zendesk API token scoped to the sandbox account",
        )
        .with_env_var(SUBDOMAIN_ENV, "Zendesk sandbox subdomain")
        .with_env_var(EMAIL_ENV, "Zendesk sandbox agent email for token auth")
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_account_setup(
            "Use a dedicated Zendesk sandbox or development account. This suite performs one invalid-token ticket search, one sandbox ticket search, one namespaced ticket create, one readback, and one cleanup delete.",
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
        "ZENDESK_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "zendesk_live_sandbox_ticket_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": API_TOKEN_ENV,
            "required_env": [SUBDOMAIN_ENV, EMAIL_ENV, NAMESPACE_ENV],
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_SEARCH_TICKETS,
                OP_CREATE_TICKET,
                OP_GET_TICKET,
                OP_DELETE_TICKET
            ],
            "status": status,
            "provider": "Zendesk sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_ticket",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token ticket search, one sandbox ticket search, one namespaced ticket create, one readback, and one cleanup delete.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "ticket.search",
                "ticket.create",
                "ticket.readback",
                "ticket.delete"
            ],
            "auth_denial_verified": auth_denial_verified,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "subdomain_logged": false,
            "email_logged": false,
            "ticket_id_logged": false,
            "ticket_subjects_logged": false,
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
async fn zendesk_live_sandbox_ticket_search_or_structured_skip_jsonl() {
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
        "Zendesk invalid-token ticket search must be denied"
    );

    let (connector, signing_key) = configured_connector(&env).await;
    let instance_id = connector.instance_id().to_string();
    let subdomain = env
        .env_vars
        .get(SUBDOMAIN_ENV)
        .expect("subdomain env is ready");
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let subject = format!(
        "FCP Zendesk live verification {namespace} {}",
        Uuid::new_v4()
    );

    let search = match invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_SEARCH_TICKETS,
        json!({
            "query": "status<closed",
            "per_page": 1
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
            panic!("Zendesk sandbox ticket search failed: {error}");
        }
    };

    let create = match invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_CREATE_TICKET,
        json!({
            "subject": subject,
            "description": format!("Synthetic FCP live verification ticket for namespace {namespace}."),
            "priority": "low",
            "type": "question",
            "tags": ["fcp_live_verification", "fcp_sandbox"]
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
                    "subdomain_hash": redacted_hash(subdomain),
                    "subject_hash": redacted_hash(&subject),
                    "search_count": search["results"].as_array().map_or(0, Vec::len),
                }),
            );
            panic!("Zendesk sandbox ticket create failed: {error}");
        }
    };

    let ticket_id = create["ticket"]["id"]
        .as_i64()
        .expect("Zendesk ticket create response includes numeric id");
    let readback = match invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_GET_TICKET,
        json!({ "ticket_id": ticket_id }),
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
                    "subdomain_hash": redacted_hash(subdomain),
                    "ticket_hash": redacted_hash(&ticket_id.to_string()),
                    "subject_hash": redacted_hash(&subject),
                }),
            );
            panic!("Zendesk sandbox ticket readback failed: {error}");
        }
    };

    match invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_DELETE_TICKET,
        json!({ "ticket_id": ticket_id }),
    )
    .await
    {
        Ok(delete) => {
            emit_live_jsonl(
                "passed",
                "",
                search["results"]
                    .as_array()
                    .map_or(3, |results| results.len().saturating_add(3)),
                "delete_completed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "subdomain_hash": redacted_hash(subdomain),
                    "ticket_hash": redacted_hash(&ticket_id.to_string()),
                    "subject_hash": redacted_hash(&subject),
                    "search_count": search["results"].as_array().map_or(0, Vec::len),
                    "readback_present": readback.get("ticket").is_some(),
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
                    "subdomain_hash": redacted_hash(subdomain),
                    "ticket_hash": redacted_hash(&ticket_id.to_string()),
                    "subject_hash": redacted_hash(&subject),
                    "readback_present": readback.get("ticket").is_some(),
                }),
            );
            panic!("Zendesk sandbox ticket cleanup failed: {error}");
        }
    }

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

async fn configured_connector(env: &LiveEnvironment) -> (ZendeskConnector, Ed25519SigningKey) {
    configured_connector_with_token(env, env.secrets.require("api_token")).await
}

async fn configured_connector_with_token(
    env: &LiveEnvironment,
    api_token: &str,
) -> (ZendeskConnector, Ed25519SigningKey) {
    let mut connector = ZendeskConnector::new();
    connector
        .handle_configure(json!({
            "subdomain": env.env_vars.get(SUBDOMAIN_ENV).expect("subdomain env is ready"),
            "email": env.env_vars.get(EMAIL_ENV).expect("email env is ready"),
            "api_token": api_token
        }))
        .await
        .expect("configure live connector");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["zendesk.read", "zendesk.write", "zendesk.delete"]
        }))
        .await
        .expect("handshake live connector");
    (connector, signing_key)
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let (connector, signing_key) =
        configured_connector_with_token(env, "fcp-invalid-zendesk-live-token").await;
    let instance_id = connector.instance_id().to_string();
    invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_SEARCH_TICKETS,
        json!({
            "query": "status<closed",
            "per_page": 1
        }),
    )
    .await
    .is_err()
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    operation: &'static str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign capability token");
    fcp_core::CapabilityToken::from_raw(cose)
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_CREATE_TICKET => "zendesk.write",
        OP_DELETE_TICKET => "zendesk.delete",
        OP_GET_TICKET | OP_SEARCH_TICKETS => "zendesk.read",
        _ => panic!("unsupported Zendesk live operation {operation}"),
    }
}

async fn invoke(
    connector: &ZendeskConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    operation: &'static str,
    input: Value,
) -> Result<Value, fcp_prelude::FcpError> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_token(signing_key, instance_id, operation)
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
