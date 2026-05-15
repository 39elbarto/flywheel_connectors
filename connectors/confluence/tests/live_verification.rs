//! Environment-gated live verification for the `Confluence` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_confluence::connector::ConfluenceConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const BASE_URL_ENV: &str = "CONFLUENCE_BASE_URL";
const EMAIL_ENV: &str = "CONFLUENCE_EMAIL";
const TOKEN_ENV: &str = "CONFLUENCE_API_TOKEN";
const SPACE_KEY_ENV: &str = "CONFLUENCE_SPACE_KEY";
const VERIFY_PAGES_ENV: &str = "CONFLUENCE_VERIFY_PAGES";
const CONNECTOR_ID: &str = "fcp.confluence";
const CAP_SPACES_READ: &str = "confluence.spaces.read";
const CAP_PAGES_READ: &str = "confluence.pages.read";
const CAP_PAGES_WRITE: &str = "confluence.pages.write";
const OP_PAGES_LIST: &str = "confluence.pages.list";
const OP_SPACES_LIST: &str = "confluence.spaces.list";

#[fcp_async_core::runtime::test]
async fn live_verification_lists_spaces_when_enabled() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let Some(base_url) = env_nonempty(BASE_URL_ENV) else {
        emit_live_jsonl("skipped", &format!("{BASE_URL_ENV} is not set"), 0);
        return;
    };
    let Some(email) = env_nonempty(EMAIL_ENV) else {
        emit_live_jsonl("skipped", &format!("{EMAIL_ENV} is not set"), 0);
        return;
    };
    let Some(token) = env_nonempty(TOKEN_ENV) else {
        emit_live_jsonl("skipped", &format!("{TOKEN_ENV} is not set"), 0);
        return;
    };

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&base_url, &email, &token, &signing_key).await;
    let spaces = invoke(
        &connector,
        &signing_key,
        OP_SPACES_LIST,
        json!({"start": 0, "limit": 1}),
    )
    .await
    .expect("list live Confluence spaces");
    let mut observed_count = spaces["results"].as_array().map_or(0, Vec::len);
    let mut reason = "spaces.list completed";

    if std::env::var(VERIFY_PAGES_ENV).ok().as_deref() == Some("1") {
        let Some(space_key) = env_nonempty(SPACE_KEY_ENV) else {
            emit_live_jsonl(
                "skipped",
                &format!("{SPACE_KEY_ENV} is not set"),
                observed_count,
            );
            return;
        };
        let pages = invoke(
            &connector,
            &signing_key,
            OP_PAGES_LIST,
            json!({
                "space_key": space_key,
                "start": 0,
                "limit": 1
            }),
        )
        .await
        .expect("list live Confluence pages");
        observed_count = pages["results"].as_array().map_or(observed_count, Vec::len);
        reason = "spaces.list and pages.list completed";
    }

    emit_live_jsonl("passed", reason, observed_count);
}

async fn configured_connector(
    base_url: &str,
    email: &str,
    token: &str,
    signing_key: &Ed25519SigningKey,
) -> ConfluenceConnector {
    let mut connector = ConfluenceConnector::new();
    connector
        .configure(json!({
            "base_url": base_url,
            "email": email,
            "api_token": token,
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
                CapabilityId::from_static(CAP_SPACES_READ),
                CapabilityId::from_static(CAP_PAGES_READ),
                CapabilityId::from_static(CAP_PAGES_WRITE),
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
        OP_SPACES_LIST => CAP_SPACES_READ,
        OP_PAGES_LIST => CAP_PAGES_READ,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &ConfluenceConnector,
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
        .principal("user:confluence-live")
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
    connector: &ConfluenceConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, fcp_prelude::FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("confluence-live-{operation}")),
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
        "CONFLUENCE_LIVE_SANDBOX_JSONL {}",
        json!({
            "connector": "confluence",
            "suite_class": "live",
            "gate_env_var": LIVE_GATE_ENV,
            "credential_env_vars": [BASE_URL_ENV, EMAIL_ENV, TOKEN_ENV],
            "optional_env_vars": [SPACE_KEY_ENV, VERIFY_PAGES_ENV],
            "status": status,
            "reason": reason,
            "observed_count": observed_count,
            "credential_material_logged": false,
            "base_url_logged": false,
            "email_logged": false,
            "space_key_logged": false
        })
    );
}
