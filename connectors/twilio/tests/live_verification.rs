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

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCOUNT_SID_ENV: &str = "TWILIO_SANDBOX_ACCOUNT_SID";
const AUTH_TOKEN_ENV: &str = "TWILIO_SANDBOX_AUTH_TOKEN";
const API_BASE_ENV: &str = "TWILIO_SANDBOX_API_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_MESSAGES: &str = "twilio.list_messages";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("twilio", "Twilio sandbox")
        .with_env_secret(
            "auth_token",
            AUTH_TOKEN_ENV,
            "Twilio auth token scoped to the sandbox or test account",
        )
        .with_env_var(ACCOUNT_SID_ENV, "Twilio sandbox or test account SID")
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
            "Use a dedicated Twilio test account or subaccount. This suite performs one read-only message listing by default; send-path proof belongs in a dedicated namespaced flow using test credentials.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "TWILIO_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "twilio_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": AUTH_TOKEN_ENV,
            "required_env": [ACCOUNT_SID_ENV, NAMESPACE_ENV],
            "defaulted_env": API_BASE_ENV,
            "operation": OP_LIST_MESSAGES,
            "status": status,
            "provider": "Twilio sandbox",
            "environment": "sandbox",
            "resource_class": "message_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only message listing against the sandbox account.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
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
            &env.evidence_summary(),
        );
        return;
    }

    let (mut connector, signing_key) = configured_connector(&env).await;
    let instance_id = connector.instance_id().to_string();
    let capability_token = capability_token(&signing_key, &instance_id, OP_LIST_MESSAGES);
    match connector
        .handle_invoke(json!({
            "operation": OP_LIST_MESSAGES,
            "input": {
                "page_size": 1
            },
            "capability_token": capability_token
        }))
        .await
    {
        Ok(value) => {
            let observed_count = value["messages"].as_array().map_or(0, Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "list_messages completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Twilio sandbox message listing failed: {error}");
        }
    }
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
            "capabilities_requested": ["twilio.read"]
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
        .capability_id("twilio.read")
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
