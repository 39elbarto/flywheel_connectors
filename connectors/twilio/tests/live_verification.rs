//! Environment-gated sandbox verification for the `Twilio` connector.

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
use fcp_twilio::connector::TwilioConnector;
use serde_json::{Value, json};
use sha2::Digest;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCOUNT_SID_ENV: &str = "TWILIO_SANDBOX_ACCOUNT_SID";
const AUTH_TOKEN_ENV: &str = "TWILIO_SANDBOX_AUTH_TOKEN";
const FROM_ENV: &str = "TWILIO_SANDBOX_FROM";
const TO_ENV: &str = "TWILIO_SANDBOX_TO";
const API_BASE_ENV: &str = "TWILIO_SANDBOX_API_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_MESSAGES: &str = "twilio.list_messages";
const OP_SEND_MESSAGE: &str = "twilio.send_message";
const CALL_CEILING: usize = 3;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-twilio --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("twilio", "Twilio sandbox")
        .with_env_secret(
            "auth_token",
            AUTH_TOKEN_ENV,
            "Twilio auth token scoped to the sandbox or test account",
        )
        .with_env_var(ACCOUNT_SID_ENV, "Twilio sandbox or test account SID")
        .with_env_var(FROM_ENV, "Twilio sandbox sender number or test sender")
        .with_env_var(TO_ENV, "Twilio sandbox recipient number or test recipient")
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            API_BASE_ENV,
            "https://api.twilio.com/2010-04-01/Accounts",
            "Twilio REST API account collection endpoint",
        )
        .with_account_setup(
            "Use a dedicated Twilio test account or subaccount with sandbox sender/recipient numbers. This suite performs one invalid-token read, one message listing, and one namespaced sandbox SMS send.",
        )
        .with_budget(0.05)
        .with_cleanup(CleanupStrategy::None)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    auth_denial_verified: bool,
    evidence: &Value,
) {
    eprintln!(
        "TWILIO_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "twilio_live_sandbox_sms_send",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": AUTH_TOKEN_ENV,
            "required_env": [ACCOUNT_SID_ENV, FROM_ENV, TO_ENV, NAMESPACE_ENV],
            "defaulted_env": API_BASE_ENV,
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_LIST_MESSAGES,
                OP_SEND_MESSAGE
            ],
            "status": status,
            "provider": "Twilio sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_sms_message",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token message listing, one sandbox message listing, and one sandbox SMS send.",
            "mutation_expected": true,
            "cleanup_strategy": "immutable_provider_message",
            "cleanup_result": if status == "passed" { Some("sms_message_provider_artifact_immutable") } else { None },
            "request_category": [
                "auth-denial",
                "message.list",
                "message.send"
            ],
            "auth_denial_verified": auth_denial_verified,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "account_sid_logged": false,
            "phone_numbers_logged": false,
            "api_base_logged": false,
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
async fn twilio_live_sandbox_message_listing_or_structured_skip_jsonl() {
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

    let auth_denial_verified = invalid_token_is_denied(&env).await;
    assert!(
        auth_denial_verified,
        "Twilio invalid-token message listing must be denied"
    );

    let (mut connector, signing_key) = configured_connector(&env).await;
    let instance_id = connector.instance_id().to_string();
    let account_sid = env
        .env_vars
        .get(ACCOUNT_SID_ENV)
        .expect("account SID env is ready");
    let from = env.env_vars.get(FROM_ENV).expect("from env is ready");
    let to = env.env_vars.get(TO_ENV).expect("to env is ready");
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");

    let list = match invoke(
        &mut connector,
        &signing_key,
        &instance_id,
        OP_LIST_MESSAGES,
        json!({
            "to": to,
            "from": from,
            "page_size": 1
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
                auth_denial_verified,
                &env.evidence_summary(),
            );
            panic!("Twilio sandbox message listing failed: {error}");
        }
    };

    let body = format!("FCP Twilio live verification {namespace}");
    let send = match invoke(
        &mut connector,
        &signing_key,
        &instance_id,
        OP_SEND_MESSAGE,
        json!({
            "to": to,
            "from": from,
            "body": body,
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
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "account_hash": redacted_hash(account_sid),
                    "from_hash": redacted_hash(from),
                    "to_hash": redacted_hash(to),
                    "list_count": list["messages"].as_array().map_or(0, Vec::len),
                }),
            );
            panic!("Twilio sandbox message send failed: {error}");
        }
    };

    let sid = send["sid"].as_str().unwrap_or("unknown");
    emit_live_jsonl(
        "passed",
        "",
        list["messages"]
            .as_array()
            .map_or(1, |messages| messages.len().saturating_add(1)),
        auth_denial_verified,
        &json!({
            "environment": env.evidence_summary(),
            "operation_result": "list_messages and send_message completed",
            "account_hash": redacted_hash(account_sid),
            "from_hash": redacted_hash(from),
            "to_hash": redacted_hash(to),
            "message_sid_hash": redacted_hash(sid),
            "message_body_hash": redacted_hash(&body),
            "send_status": send["status"].as_str().unwrap_or("unknown"),
        }),
    );
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

async fn configured_connector(env: &LiveEnvironment) -> (TwilioConnector, Ed25519SigningKey) {
    let account_sid = env
        .env_vars
        .get(ACCOUNT_SID_ENV)
        .expect("account SID env is ready");
    let api_base = env
        .env_vars
        .get(API_BASE_ENV)
        .expect("API base env is ready");
    let base_url = format!("{}/{account_sid}", api_base.trim_end_matches('/'));

    let mut connector = TwilioConnector::new();
    connector
        .handle_configure(json!({
            "account_sid": account_sid,
            "auth_token": env.secrets.require("auth_token"),
            "base_url": base_url
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
            "capabilities_requested": ["twilio.read", "twilio.message"]
        }))
        .await
        .expect("handshake live connector");
    (connector, signing_key)
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let (mut connector, signing_key) =
        configured_connector_with_auth(env, "fcp-invalid-twilio-live-token").await;
    let instance_id = connector.instance_id().to_string();
    invoke(
        &mut connector,
        &signing_key,
        &instance_id,
        OP_LIST_MESSAGES,
        json!({ "page_size": 1 }),
    )
    .await
    .is_err()
}

async fn configured_connector_with_auth(
    env: &LiveEnvironment,
    auth_token: &str,
) -> (TwilioConnector, Ed25519SigningKey) {
    let account_sid = env
        .env_vars
        .get(ACCOUNT_SID_ENV)
        .expect("account SID env is ready");
    let api_base = env
        .env_vars
        .get(API_BASE_ENV)
        .expect("API base env is ready");
    let base_url = format!("{}/{account_sid}", api_base.trim_end_matches('/'));

    let mut connector = TwilioConnector::new();
    connector
        .handle_configure(json!({
            "account_sid": account_sid,
            "auth_token": auth_token,
            "base_url": base_url
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
            "capabilities_requested": ["twilio.read", "twilio.message"]
        }))
        .await
        .expect("handshake live connector");
    (connector, signing_key)
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
        OP_SEND_MESSAGE => "twilio.message",
        OP_LIST_MESSAGES => "twilio.read",
        _ => panic!("unsupported Twilio live operation {operation}"),
    }
}

async fn invoke(
    connector: &mut TwilioConnector,
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
    let mut hasher = sha2::Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest).chars().take(16).collect()
}
