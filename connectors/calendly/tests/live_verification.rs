//! Environment-gated live verification for the `Calendly` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_calendly::connector::CalendlyConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "CALENDLY_ACCESS_TOKEN";
const BASE_URL_ENV: &str = "CALENDLY_BASE_URL";
const VERIFY_EVENTS_ENV: &str = "CALENDLY_VERIFY_EVENTS";
const CONNECTOR_ID: &str = "fcp.calendly";
const CAP_EVENTS_READ: &str = "calendly.events.read";
const CAP_EVENTS_WRITE: &str = "calendly.events.write";
const CAP_SCHEDULING_READ: &str = "calendly.scheduling.read";
const CAP_SCHEDULING_WRITE: &str = "calendly.scheduling.write";
const CAP_USER_READ: &str = "calendly.user.read";
const OP_EVENTS_LIST: &str = "calendly.events.list";
const OP_USER_GET: &str = "calendly.user.get";

#[fcp_async_core::runtime::test]
async fn live_verification_reads_authenticated_user_when_enabled() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let Some(token) = env_nonempty(TOKEN_ENV) else {
        emit_live_jsonl("skipped", &format!("{TOKEN_ENV} is not set"), 0);
        return;
    };
    let base_url = env_nonempty(BASE_URL_ENV).unwrap_or_else(|| "https://api.calendly.com".into());

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&base_url, &token, &signing_key).await;
    let user = invoke(&connector, &signing_key, OP_USER_GET, json!({}))
        .await
        .expect("read live Calendly user");
    let user_uri = user["resource"]["uri"].as_str().unwrap_or_default();
    let mut observed_count = usize::from(!user_uri.is_empty());
    let mut reason = "user.get completed";

    if std::env::var(VERIFY_EVENTS_ENV).ok().as_deref() == Some("1") && !user_uri.is_empty() {
        let events = invoke(
            &connector,
            &signing_key,
            OP_EVENTS_LIST,
            json!({
                "user_uri": user_uri,
                "count": 1
            }),
        )
        .await
        .expect("list live Calendly events");
        observed_count = events["collection"]
            .as_array()
            .map_or(observed_count, Vec::len);
        reason = "user.get and events.list completed";
    }

    emit_live_jsonl("passed", reason, observed_count);
}

async fn configured_connector(
    base_url: &str,
    token: &str,
    signing_key: &Ed25519SigningKey,
) -> CalendlyConnector {
    let mut connector = CalendlyConnector::new();
    connector
        .configure(json!({
            "access_token": token,
            "base_url": base_url,
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 250,
                "max_delay_ms": 1_000,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure live connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [23_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_EVENTS_READ),
                CapabilityId::from_static(CAP_EVENTS_WRITE),
                CapabilityId::from_static(CAP_SCHEDULING_READ),
                CapabilityId::from_static(CAP_SCHEDULING_WRITE),
                CapabilityId::from_static(CAP_USER_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake live connector");
    connector
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_EVENTS_LIST => CAP_EVENTS_READ,
        OP_USER_GET => CAP_USER_READ,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &CalendlyConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:calendly-live")
        .operations(&[operation])
        .issuer("node:live-verification")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &CalendlyConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, fcp_prelude::FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("calendly-live-{operation}")),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: capability_for(connector, signing_key, operation),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await?;
    assert_eq!(response.status, InvokeStatus::Ok);
    Ok(response.result.expect("successful response has result"))
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
        "CALENDLY_LIVE_SANDBOX_JSONL {}",
        json!({
            "connector": "calendly",
            "suite_class": "live",
            "gate_env_var": LIVE_GATE_ENV,
            "credential_env_vars": [TOKEN_ENV],
            "optional_env_vars": [BASE_URL_ENV, VERIFY_EVENTS_ENV],
            "status": status,
            "reason": reason,
            "observed_count": observed_count,
            "credential_material_logged": false,
            "pii_logged": false
        })
    );
}
