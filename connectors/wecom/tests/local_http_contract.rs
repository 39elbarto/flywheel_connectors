#![forbid(unsafe_code)]

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, HealthState, InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_sdk::{ChatCoordinationBackend, InMemoryThreadOwnershipChecker, ThreadOwnershipChecker};
use fcp_wecom::{
    WeComConnector,
    client::WeComClient,
    types::{
        DEFAULT_TIMEOUT_MS, WeComConfig, WeComMediaDownloadRequest, WeComMediaUploadRequest,
        WeComMessageKind, WeComMessageRequest,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path, query_param},
};

const OP_SEND_TEXT: &str = "wecom.messages.send_text";
const OP_HEALTH: &str = "wecom.health";
const CAP_MESSAGES_WRITE: &str = "wecom.messages.write";
const CAP_HEALTH_READ: &str = "wecom.health.read";
const WECOM_TOKEN_PROBE: &str = "GET /cgi-bin/gettoken";

fn wecom_manifest_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(include_str!("../manifest.toml").as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn client_config(base_url: &str) -> WeComConfig {
    WeComConfig::from_value(json!({
        "base_url": base_url,
        "corp_id": "corp",
        "agent_id": 1_000_002_u64,
        "agent_secret": "secret",
        "request_timeout_ms": DEFAULT_TIMEOUT_MS,
    }))
    .expect("config should parse")
}

async fn mount_token_response(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path("/cgi-bin/gettoken"))
        .respond_with(response)
        .mount(server)
        .await;
}

async fn mount_successful_token(server: &MockServer) {
    mount_token_response(
        server,
        ResponseTemplate::new(200).set_body_json(json!({
            "errcode": 0,
            "errmsg": "ok",
            "access_token": "token-123",
            "expires_in": 7200
        })),
    )
    .await;
}

fn handshake_request(
    host_public_key: [u8; 32],
    requested_instance_id: Option<InstanceId>,
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [19_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id,
    }
}

fn test_constraints_cbor() -> Vec<u8> {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    cbor
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &'static str,
    operation: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&test_constraints_cbor())
        .expect("test constraints cbor should be valid")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

async fn configured_connector_with_checker(
    server_uri: &str,
    signing_key: &Ed25519SigningKey,
    checker: Arc<dyn ThreadOwnershipChecker>,
) -> (WeComConnector, InstanceId) {
    let requested_instance_id = InstanceId::new();
    let mut connector = WeComConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    connector
        .configure(json!({
            "base_url": server_uri,
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
            "request_timeout_ms": DEFAULT_TIMEOUT_MS,
            "chat_coordination": { "backend": "in_memory" }
        }))
        .await
        .expect("configure should succeed");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            Some(requested_instance_id.clone()),
        ))
        .await
        .expect("handshake should succeed");
    (connector, requested_instance_id)
}

#[fcp_async_core::runtime::test]
async fn client_send_text_posts_expected_message_payload() {
    let server = MockServer::start().await;
    mount_successful_token(&server).await;

    Mock::given(method("POST"))
        .and(path("/cgi-bin/message/send"))
        .and(query_param("access_token", "token-123"))
        .and(body_partial_json(json!({
            "touser": "zhangsan",
            "msgtype": "text",
            "agentid": 1_000_002_u64,
            "text": { "content": "hello from test" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errcode": 0,
            "errmsg": "ok",
            "msgid": "mid-1"
        })))
        .mount(&server)
        .await;

    let client = WeComClient::new(client_config(&server.uri())).expect("client should build");
    let request = WeComMessageRequest::from_value(
        &json!({
            "touser": "zhangsan",
            "content": "hello from test",
        }),
        WeComMessageKind::Text,
    )
    .expect("message request should parse");

    let output = client
        .send_message(&request)
        .await
        .expect("send text should succeed");

    assert_eq!(output["msgid"], "mid-1");
}

#[fcp_async_core::runtime::test]
async fn client_upload_media_posts_multipart_request() {
    let server = MockServer::start().await;
    mount_successful_token(&server).await;

    Mock::given(method("POST"))
        .and(path("/cgi-bin/media/upload"))
        .and(query_param("access_token", "token-123"))
        .and(query_param("type", "image"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errcode": 0,
            "errmsg": "ok",
            "type": "image",
            "media_id": "MEDIA123"
        })))
        .mount(&server)
        .await;

    let client = WeComClient::new(client_config(&server.uri())).expect("client should build");
    let request = WeComMediaUploadRequest::from_value(&json!({
        "media_type": "image",
        "file_name": "test.png",
        "mime_type": "image/png",
        "content_base64": BASE64.encode(b"png"),
    }))
    .expect("upload request should parse");

    let output = client
        .upload_media(&request)
        .await
        .expect("upload should succeed");

    assert_eq!(output["media_id"], "MEDIA123");
}

#[fcp_async_core::runtime::test]
async fn client_send_image_message_posts_media_payload() {
    let server = MockServer::start().await;
    mount_successful_token(&server).await;

    Mock::given(method("POST"))
        .and(path("/cgi-bin/message/send"))
        .and(query_param("access_token", "token-123"))
        .and(body_partial_json(json!({
            "touser": "zhangsan",
            "msgtype": "image",
            "agentid": 1_000_002_u64,
            "image": { "media_id": "MEDIA123" },
            "safe": 1,
            "enable_duplicate_check": 1,
            "duplicate_check_interval": 120
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errcode": 0,
            "errmsg": "ok",
            "msgid": "mid-image-1"
        })))
        .mount(&server)
        .await;

    let client = WeComClient::new(client_config(&server.uri())).expect("client should build");
    let request = WeComMessageRequest::from_value(
        &json!({
            "touser": "zhangsan",
            "media_id": "MEDIA123",
            "safe": true,
            "enable_duplicate_check": true,
            "duplicate_check_interval": 120,
        }),
        WeComMessageKind::Image,
    )
    .expect("image request should parse");

    let output = client
        .send_message(&request)
        .await
        .expect("send image should succeed");

    assert_eq!(output["msgid"], "mid-image-1");
}

#[fcp_async_core::runtime::test]
async fn client_download_media_returns_base64_payload() {
    let server = MockServer::start().await;
    mount_successful_token(&server).await;

    Mock::given(method("GET"))
        .and(path("/cgi-bin/media/get"))
        .and(query_param("access_token", "token-123"))
        .and(query_param("media_id", "MEDIA123"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "image/png")
                .append_header("content-disposition", "attachment; filename=\"test.png\"")
                .set_body_bytes(b"png-data"),
        )
        .mount(&server)
        .await;

    let client = WeComClient::new(client_config(&server.uri())).expect("client should build");
    let download = client
        .download_media(
            &WeComMediaDownloadRequest::from_value(&json!({
                "media_id": "MEDIA123",
            }))
            .expect("request should parse"),
        )
        .await
        .expect("download should succeed");

    assert_eq!(download.media_id, "MEDIA123");
    assert_eq!(download.file_name.as_deref(), Some("test.png"));
    assert_eq!(download.mime_type.as_deref(), Some("image/png"));
    assert_eq!(download.content_base64, BASE64.encode(b"png-data"));
}

#[fcp_async_core::runtime::test]
async fn connector_health_performs_token_probe_and_reports_cached_state() {
    let server = MockServer::start().await;
    mount_successful_token(&server).await;

    let mut connector = WeComConnector::new();
    connector
        .configure(json!({
            "base_url": server.uri(),
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
            "request_timeout_ms": DEFAULT_TIMEOUT_MS
        }))
        .await
        .expect("configure should succeed");

    let health_before = connector.health().await;
    assert!(matches!(health_before.status, HealthState::Ready));
    assert_eq!(
        health_before
            .details
            .as_ref()
            .and_then(|details| details.get("token_cached"))
            .and_then(Value::as_bool),
        Some(true)
    );

    let report = connector
        .self_check()
        .await
        .expect("self_check should return");
    assert_eq!(report.status, fcp_core::SelfCheckStatus::Ok);
    assert_eq!(
        report
            .details
            .as_ref()
            .and_then(|details| details.get("live_probe"))
            .and_then(|probe| probe.get("token_issuance_probe"))
            .and_then(Value::as_str),
        Some(WECOM_TOKEN_PROBE)
    );
    assert!(
        report
            .details
            .as_ref()
            .and_then(|details| details.get("operator_guidance"))
            .is_some(),
        "self_check should attach operator guidance details"
    );

    let health_after = connector.health().await;
    assert!(matches!(health_after.status, HealthState::Ready));
    assert_eq!(
        health_after
            .details
            .as_ref()
            .and_then(|details| details.get("token_cached"))
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[fcp_async_core::runtime::test]
async fn connector_health_degrades_when_token_probe_fails() {
    let server = MockServer::start().await;
    mount_token_response(
        &server,
        ResponseTemplate::new(401).set_body_json(json!({
            "errcode": 40013,
            "errmsg": "invalid corpid"
        })),
    )
    .await;

    let mut connector = WeComConnector::new();
    connector
        .configure(json!({
            "base_url": server.uri(),
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "wrong-secret",
            "request_timeout_ms": DEFAULT_TIMEOUT_MS
        }))
        .await
        .expect("configure should succeed");

    let health = connector.health().await;
    assert!(matches!(health.status, HealthState::Degraded { .. }));
    assert_eq!(
        health
            .details
            .as_ref()
            .and_then(|details| details.get("token_cached"))
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[fcp_async_core::runtime::test]
async fn connector_invoke_health_returns_status_and_state() {
    let server = MockServer::start().await;
    mount_successful_token(&server).await;

    let mut connector = WeComConnector::new();
    connector
        .configure(json!({
            "base_url": server.uri(),
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
            "request_timeout_ms": DEFAULT_TIMEOUT_MS
        }))
        .await
        .expect("configure should succeed");
    let signing_key = Ed25519SigningKey::generate();
    let requested_instance_id = InstanceId::new();
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            Some(requested_instance_id.clone()),
        ))
        .await
        .expect("handshake should succeed");

    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("wecom-health"),
            connector_id: ConnectorId::from_static("fcp.wecom"),
            operation: OperationId::from_static(OP_HEALTH),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: capability_token(
                &signing_key,
                CAP_HEALTH_READ,
                OP_HEALTH,
                &requested_instance_id,
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .expect("health invoke should succeed");

    assert_eq!(response.result.as_ref().expect("result")["status"], "ok");
    assert_eq!(
        response.result.as_ref().expect("result")["details"]["token_cached"],
        json!(true)
    );
    assert_eq!(
        response.result.as_ref().expect("result")["details"]["manifest_hash"],
        json!(wecom_manifest_hash())
    );
}

#[fcp_async_core::runtime::test]
async fn connector_send_text_claims_target_and_denies_duplicate_before_http() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cgi-bin/gettoken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errcode": 0,
            "errmsg": "ok",
            "access_token": "token-123",
            "expires_in": 7200
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/cgi-bin/message/send"))
        .and(query_param("access_token", "token-123"))
        .and(body_partial_json(json!({
            "touser": "zhangsan",
            "agentid": 1_000_002_u64,
            "msgtype": "text",
            "text": { "content": "secret message body" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errcode": 0,
            "errmsg": "ok",
            "msgid": "msg-loopback"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let checker: Arc<dyn ThreadOwnershipChecker> = Arc::new(InMemoryThreadOwnershipChecker::new());
    let (first, first_instance_id) =
        configured_connector_with_checker(&server.uri(), &signing_key, Arc::clone(&checker)).await;
    let (second, second_instance_id) =
        configured_connector_with_checker(&server.uri(), &signing_key, Arc::clone(&checker)).await;

    let first_response = first
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("wecom-send-first"),
            connector_id: ConnectorId::from_static("fcp.wecom"),
            operation: OperationId::from_static(OP_SEND_TEXT),
            zone_id: ZoneId::work(),
            input: json!({
                "touser": "zhangsan",
                "content": "secret message body"
            }),
            capability_token: capability_token(
                &signing_key,
                CAP_MESSAGES_WRITE,
                OP_SEND_TEXT,
                &first_instance_id,
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .expect("first send should claim and reach loopback provider");
    let first_result = first_response.result.as_ref().expect("result");
    assert_eq!(first_result["msgid"], "msg-loopback");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][1]["outcome"], "granted");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");
    assert!(
        !serde_json::to_string(&first_result["coordination"])
            .expect("serialize coordination")
            .contains("zhangsan"),
        "coordination audit must not leak the raw WeCom user ID"
    );

    let duplicate = second
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("wecom-send-duplicate"),
            connector_id: ConnectorId::from_static("fcp.wecom"),
            operation: OperationId::from_static(OP_SEND_TEXT),
            zone_id: ZoneId::work(),
            input: json!({
                "touser": "zhangsan",
                "content": "secret message body"
            }),
            capability_token: capability_token(
                &signing_key,
                CAP_MESSAGES_WRITE,
                OP_SEND_TEXT,
                &second_instance_id,
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .expect_err("duplicate active owner should be denied before provider HTTP");
    assert!(matches!(
        duplicate,
        FcpError::Unauthorized {
            code: 4090,
            ref message
        } if message.starts_with("thread_owned_by_peer:")
            && message.contains(first_instance_id.as_str())
    ));
}
