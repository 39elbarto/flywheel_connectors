//! Connector-local no-mock Teams ingress proof.
//!
//! These tests exercise the FCP Teams connector against host-forwarded Bot
//! Framework activity payloads and a local loopback Graph/Bot endpoint. No live
//! Microsoft service is contacted.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, HandshakeRequest,
    InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_teams::TeamsConnector;
use serde_json::{Value, json};
use wiremock::MockServer;

const CAP_READ: &str = "teams.read";
const CAP_WRITE: &str = "teams.write";
const OP_INGEST_ACTIVITY: &str = "teams.ingest_activity";

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [73u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|capability| CapabilityId::new(*capability).expect("capability id"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
    instance_id: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

fn invoke_request(
    connector: &TeamsConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("teams-integration"),
        connector_id: connector.id().clone(),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

async fn setup_connector(
    server: &MockServer,
    ingress_policy: Value,
) -> (TeamsConnector, Ed25519SigningKey) {
    let mut connector = TeamsConnector::new();
    connector
        .configure(json!({
            "graph_base_url": server.uri(),
            "bot_service_url": server.uri(),
            "auth": { "mode": "access_token", "access_token": "tok" },
            "ingress_policy": ingress_policy,
            "timeout_ms": 500
        }))
        .await
        .expect("loopback Teams config should configure");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &[CAP_READ, CAP_WRITE],
        ))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn invoke_ingest(
    connector: &TeamsConnector,
    signing_key: &Ed25519SigningKey,
    input: Value,
) -> Value {
    connector
        .invoke(invoke_request(
            connector,
            OP_INGEST_ACTIVITY,
            input,
            capability_token(
                signing_key,
                CAP_WRITE,
                &[OP_INGEST_ACTIVITY],
                connector.instance_id(),
            ),
        ))
        .await
        .expect("ingest invoke should succeed")
        .result
        .expect("successful invoke should carry a result")
}

fn channel_message(server: &MockServer, activity_id: &str, channel_id: &str) -> Value {
    json!({
        "type": "message",
        "id": activity_id,
        "timestamp": "2026-01-01T00:00:00Z",
        "serviceUrl": format!("{}/amer/", server.uri()),
        "text": "<at>Test Bot</at> hello",
        "from": { "id": "29:user", "name": "Alice", "aadObjectId": "aad-user" },
        "recipient": { "id": "28:bot", "name": "Test Bot" },
        "conversation": {
            "id": channel_id,
            "conversationType": "channel",
            "tenantId": "tenant_1"
        },
        "channelData": {
            "tenant": { "id": "tenant_1" },
            "team": { "id": "team_1", "name": "Engineering" },
            "channel": { "id": channel_id }
        },
        "attachments": [{
            "contentType": "image/png",
            "contentUrl": "https://example.invalid/image.png",
            "name": "screenshot.png"
        }]
    })
}

#[fcp_async_core::runtime::test]
async fn host_forwarded_ingest_enforces_policy_and_tracks_reference() {
    tracing::info!(
        scenario = "teams_host_forwarded_ingress_policy",
        "starting Teams host-forwarded ingress policy proof",
    );

    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(
        &server,
        json!({
            "allowed_sender_ids": ["29:user"],
            "allowed_team_ids": ["team_1"],
            "allowed_channel_ids": ["channel_1"],
            "bot_user_id": "28:bot"
        }),
    )
    .await;

    let accepted = invoke_ingest(
        &connector,
        &signing_key,
        channel_message(&server, "activity_1", "channel_1"),
    )
    .await;

    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["duplicate"], false);
    assert!(accepted["diagnostic"].is_null());
    assert_eq!(
        accepted["conversation_reference"]["conversation_id"],
        "channel_1"
    );
    assert_eq!(accepted["conversation_reference"]["user_id"], "29:user");
    assert_eq!(accepted["conversation_reference"]["bot_id"], "28:bot");
    assert_eq!(accepted["conversation_reference"]["tenant_id"], "tenant_1");
    assert_eq!(accepted["attachments"][0]["disposition"], "image_reference");
    assert_eq!(accepted["event"]["topic"], "teams.message.received");

    let denied_channel = invoke_ingest(
        &connector,
        &signing_key,
        channel_message(&server, "activity_2", "channel_2"),
    )
    .await;
    assert_eq!(denied_channel["accepted"], false);
    assert_eq!(denied_channel["diagnostic"]["code"], "channel_not_allowed");
    assert!(denied_channel["event"].is_null());
    assert!(denied_channel["conversation_state"].is_null());

    let mut self_message = channel_message(&server, "activity_3", "channel_1");
    self_message["from"] = json!({ "id": "28:bot", "name": "Test Bot" });
    let denied_self = invoke_ingest(&connector, &signing_key, self_message).await;
    assert_eq!(denied_self["accepted"], false);
    assert_eq!(denied_self["diagnostic"]["code"], "bot_self_message");
}

#[fcp_async_core::runtime::test]
async fn file_consent_and_replay_diagnostics_are_explicit() {
    tracing::info!(
        scenario = "teams_file_consent_and_replay_diagnostics",
        "starting Teams file-consent/replay proof",
    );

    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server, json!({})).await;

    let file_consent = invoke_ingest(
        &connector,
        &signing_key,
        json!({
            "type": "invoke",
            "name": "fileConsent/invoke",
            "id": "consent_1",
            "serviceUrl": server.uri(),
            "from": { "id": "29:user", "name": "Alice" },
            "conversation": {
                "id": "chat_1",
                "conversationType": "personal",
                "tenantId": "tenant_1"
            },
            "value": {
                "type": "fileUpload",
                "action": "accept",
                "uploadInfo": {
                    "uploadUrl": "https://contoso.sharepoint.com/upload"
                }
            }
        }),
    )
    .await;
    assert_eq!(file_consent["accepted"], false);
    assert_eq!(file_consent["diagnostic"]["code"], "file_consent_denied");
    assert_eq!(file_consent["file_consent"]["action"], "accept");
    assert_eq!(file_consent["file_consent"]["accepted_by_policy"], false);
    assert_eq!(file_consent["file_consent"]["upload_info_present"], true);

    let message = json!({
        "type": "message",
        "id": "dup_1",
        "serviceUrl": server.uri(),
        "text": "hello",
        "from": { "id": "29:user", "aadObjectId": "aad-user" },
        "conversation": {
            "id": "chat_2",
            "conversationType": "personal",
            "tenantId": "tenant_1"
        }
    });
    let first = invoke_ingest(&connector, &signing_key, message.clone()).await;
    let second = invoke_ingest(&connector, &signing_key, message).await;
    assert_eq!(first["accepted"], true);
    assert_eq!(first["duplicate"], false);
    assert_eq!(second["accepted"], true);
    assert_eq!(second["duplicate"], true);
    assert_eq!(second["diagnostic"]["code"], "duplicate_activity");
    assert_eq!(second["conversation_state"]["lastSequence"], 1);
}

#[fcp_async_core::runtime::test]
async fn malformed_activity_and_contract_metadata_remain_typed() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server, json!({})).await;

    let error = connector
        .invoke(invoke_request(
            &connector,
            OP_INGEST_ACTIVITY,
            json!({ "type": "message", "id": "missing_conversation" }),
            capability_token(
                &signing_key,
                CAP_WRITE,
                &[OP_INGEST_ACTIVITY],
                connector.instance_id(),
            ),
        ))
        .await
        .expect_err("missing conversation should be typed invalid request");
    assert!(matches!(error, FcpError::InvalidRequest { code: 1005, .. }));

    let introspection = connector.introspect();
    let ingest = introspection
        .operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_INGEST_ACTIVITY)
        .expect("ingest activity operation should be advertised");
    assert_eq!(
        ingest.output_schema["properties"]["accepted"]["type"],
        "boolean"
    );
    assert_eq!(
        ingest.output_schema["properties"]["attachments"]["type"],
        "array"
    );
    assert!(!introspection.event_caps.as_ref().unwrap().streaming);

    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("id = \"teams.ingest_activity\""));
    assert!(manifest.contains("forbidden = [\"system.exec\", \"system.privileged\"]"));
    assert!(!manifest.contains("network.listen"));
}
