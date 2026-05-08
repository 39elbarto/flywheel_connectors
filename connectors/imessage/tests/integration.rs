use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_imessage::BlueBubblesConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, HealthState, InstanceId, InvokeRequest, OperationId, RequestId,
    ShutdownRequest, SimulateRequest, ZoneId,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Instant;
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CONNECTOR_ID: &str = "fcp.imessage";
const FIXTURE_AUTH_VALUE: &str = "fixture-auth-redacted";
const INVALID_AUTH_VALUE: &str = "wrong-auth-fixture";
const WEBHOOK_AUTH_QUERY_KEY: &str = concat!("pass", "word");
const CHAT_GUID: &str = "iMessage;-;sender.fixture.invalid";
const MESSAGE_GUID: &str = "fixture-message-guid";
const MESSAGE_TEXT: &str = "fixture message body that must not enter proof logs";
const SENDER_ID: &str = "sender.fixture.invalid";

#[fcp_async_core::runtime::test]
async fn lifecycle_loopback_token_and_shutdown_contract() {
    let server = MockServer::start().await;
    mock_server_info(&server, 200, server_info_body(true)).await;

    let mut connector = configured_connector(&server).await;
    assert!(matches!(
        connector.health().await.status,
        HealthState::Ready
    ));
    assert!(connector.doctor().passed);

    let identity = establish_handshake(&mut connector, ZoneId::work()).await;
    let started = Instant::now();
    let output = invoke_json(
        &mut connector,
        &identity,
        "imessage.get_server_info",
        "imessage.admin",
        ZoneId::work(),
        json!({}),
    )
    .await
    .unwrap();

    assert_eq!(output["private_api"], true);
    assert_eq!(output["server_version"], "1.10.0-test");
    assert_no_secret_leak(&output);

    let simulate = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static("imessage.send_message"),
            ZoneId::work(),
            json!({"chat_guid": CHAT_GUID, "message": MESSAGE_TEXT}),
            valid_token(
                &identity,
                "imessage.send",
                "imessage.send_message",
                ZoneId::work(),
                true,
            ),
        ))
        .await
        .unwrap();
    assert!(simulate.would_succeed, "{simulate:?}");

    let wrong_zone = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static("imessage.get_server_info"),
            ZoneId::work(),
            json!({}),
            valid_token(
                &identity,
                "imessage.admin",
                "imessage.get_server_info",
                ZoneId::private(),
                true,
            ),
        ))
        .await
        .unwrap();
    assert!(!wrong_zone.would_succeed);

    let unbound_instance = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static("imessage.get_server_info"),
            ZoneId::work(),
            json!({}),
            valid_token(
                &identity,
                "imessage.admin",
                "imessage.get_server_info",
                ZoneId::work(),
                false,
            ),
        ))
        .await
        .unwrap();
    assert!(!unbound_instance.would_succeed);

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".to_owned(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("connector-local lifecycle test".to_owned()),
        })
        .await
        .unwrap();

    emit_proof_log(ProofLog::success(
        "imessage.get_server_info",
        "imessage.admin",
        &identity,
        ZoneId::work(),
        started.elapsed().as_millis(),
        "server-info-loopback",
    ));
}

#[fcp_async_core::runtime::test]
async fn local_bridge_send_create_chat_and_media_guards_are_bounded() {
    let server = MockServer::start().await;
    mock_server_info(&server, 200, server_info_body(true)).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/message/text"))
        .and(query_param("password", FIXTURE_AUTH_VALUE))
        .and(body_partial_json(json!({
            "chatGuid": CHAT_GUID,
            "message": MESSAGE_TEXT
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": 200,
            "message": "sent",
            "data": {
                "guid": MESSAGE_GUID
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/chat/new"))
        .and(query_param("password", FIXTURE_AUTH_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": 200,
            "message": "sent",
            "data": {
                "chatGuid": "iMessage;+;fixture-new-dm",
                "guid": "fixture-new-chat-message"
            }
        })))
        .mount(&server)
        .await;

    let mut connector = configured_connector(&server).await;
    let identity = establish_handshake(&mut connector, ZoneId::work()).await;
    let started = Instant::now();

    let send_output = invoke_json(
        &mut connector,
        &identity,
        "imessage.send_message",
        "imessage.send",
        ZoneId::work(),
        json!({
            "chat_guid": CHAT_GUID,
            "message": MESSAGE_TEXT,
            "reply_context": {"message_guid": "fixture-parent-guid"},
            "send_effect": "echo"
        }),
    )
    .await
    .unwrap();
    assert_eq!(send_output["status"], 200);
    assert_eq!(send_output["message"], "sent");
    assert_eq!(send_output["data"]["guid"], MESSAGE_GUID);
    assert_eq!(send_output["send_method"], "private-api");
    assert_no_secret_leak(&send_output);

    let create_output = invoke_json(
        &mut connector,
        &identity,
        "imessage.create_chat",
        "imessage.send",
        ZoneId::work(),
        json!({
            "address": "sender.fixture.invalid",
            "message": "fixture initial message"
        }),
    )
    .await
    .unwrap();
    assert_eq!(create_output["chat_guid"], "iMessage;+;fixture-new-dm");
    assert_no_secret_leak(&create_output);

    let direct_target = invoke_json(
        &mut connector,
        &identity,
        "imessage.resolve_send_target",
        "imessage.read",
        ZoneId::work(),
        json!({"chat_guid": CHAT_GUID}),
    )
    .await
    .unwrap();
    assert_eq!(direct_target["chat_guid"], CHAT_GUID);
    assert_eq!(direct_target["match_kind"], "direct_chat_guid");

    let media_error = invoke_json(
        &mut connector,
        &identity,
        "imessage.send_media",
        "imessage.send",
        ZoneId::work(),
        json!({
            "chat_guid": CHAT_GUID,
            "local_path": "/tmp/fcp-imessage-fixture-do-not-read.png",
            "content_type": "image/png"
        }),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(media_error, FcpError::InvalidRequest { .. }),
        "{media_error:?}"
    );

    emit_proof_log(ProofLog::success(
        "imessage.send_message",
        "imessage.send",
        &identity,
        ZoneId::work(),
        started.elapsed().as_millis(),
        "bridge-fixture-text-send",
    ));
}

#[fcp_async_core::runtime::test]
async fn webhook_request_ingress_maps_auth_policy_malformed_and_timeout() {
    let server = MockServer::start().await;
    mock_server_info(&server, 200, server_info_body(true)).await;

    let mut connector = configured_connector_with_webhook_policy(&server).await;
    let identity = establish_handshake(&mut connector, ZoneId::work()).await;
    let started = Instant::now();

    let accepted = invoke_json(
        &mut connector,
        &identity,
        "imessage.ingest_webhook_request",
        "imessage.read",
        ZoneId::work(),
        webhook_request_input(FIXTURE_AUTH_VALUE, webhook_body(SENDER_ID, CHAT_GUID)),
    )
    .await
    .unwrap();
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["status_code"], 200);
    assert_eq!(accepted["reason_code"], "event_accepted");
    assert_eq!(
        accepted["ingest"]["event_envelopes"][0]["topic"],
        "imessage.message.inbound"
    );
    assert!(
        !accepted["request_region"]["url"]
            .as_str()
            .unwrap()
            .contains(FIXTURE_AUTH_VALUE)
    );

    let invalid_auth = invoke_json(
        &mut connector,
        &identity,
        "imessage.ingest_webhook_request",
        "imessage.read",
        ZoneId::work(),
        webhook_request_input(INVALID_AUTH_VALUE, webhook_body(SENDER_ID, CHAT_GUID)),
    )
    .await
    .unwrap();
    assert_eq!(invalid_auth["accepted"], false);
    assert_eq!(invalid_auth["status_code"], 401);
    assert_eq!(invalid_auth["reason_code"], "invalid_auth");

    let policy_denied = invoke_json(
        &mut connector,
        &identity,
        "imessage.ingest_webhook_request",
        "imessage.read",
        ZoneId::work(),
        webhook_request_input(
            FIXTURE_AUTH_VALUE,
            webhook_body("blocked.fixture.invalid", CHAT_GUID),
        ),
    )
    .await
    .unwrap();
    assert_eq!(policy_denied["accepted"], false);
    assert_eq!(policy_denied["status_code"], 403);
    assert_eq!(policy_denied["reason_code"], "policy_rejected");

    let malformed = invoke_json(
        &mut connector,
        &identity,
        "imessage.ingest_webhook_request",
        "imessage.read",
        ZoneId::work(),
        webhook_request_input(FIXTURE_AUTH_VALUE, json!("not-a-json-object")),
    )
    .await
    .unwrap();
    assert_eq!(malformed["accepted"], false);
    assert_eq!(malformed["status_code"], 400);
    assert_eq!(malformed["reason_code"], "malformed_payload");

    let timeout = invoke_json(
        &mut connector,
        &identity,
        "imessage.ingest_webhook_request",
        "imessage.read",
        ZoneId::work(),
        json!({
            "method": "POST",
            "url": webhook_url(&server, FIXTURE_AUTH_VALUE),
            "headers": {"x-bluebubbles-event": "new-message"},
            "body": webhook_body(SENDER_ID, CHAT_GUID),
            "received_at": "2026-05-08T00:00:00Z",
            "deadline_exceeded": true
        }),
    )
    .await
    .unwrap();
    assert_eq!(timeout["accepted"], false);
    assert_eq!(timeout["status_code"], 408);
    assert_eq!(timeout["reason_code"], "request_timeout");

    let oversized = invoke_json(
        &mut connector,
        &identity,
        "imessage.ingest_webhook_request",
        "imessage.read",
        ZoneId::work(),
        json!({
            "method": "POST",
            "url": webhook_url(&server, FIXTURE_AUTH_VALUE),
            "headers": {"x-bluebubbles-event": "new-message"},
            "body": "x".repeat(70 * 1024),
            "body_size_bytes": 71_680,
            "max_body_bytes": 65_536,
            "received_at": "2026-05-08T00:00:00Z"
        }),
    )
    .await
    .unwrap();
    assert_eq!(oversized["accepted"], false);
    assert_eq!(oversized["status_code"], 413);
    assert_eq!(oversized["reason_code"], "payload_too_large");

    emit_proof_log(ProofLog::success(
        "imessage.ingest_webhook_request",
        "imessage.read",
        &identity,
        ZoneId::work(),
        started.elapsed().as_millis(),
        "webhook-request-fixture",
    ));
}

#[fcp_async_core::runtime::test]
async fn provider_error_mapping_is_stable_for_local_bridge_failures() {
    let unauthorized_server = MockServer::start().await;
    mock_server_info(
        &unauthorized_server,
        401,
        json!({"error": {"message": "unauthorized"}}),
    )
    .await;
    let mut connector = configured_connector(&unauthorized_server).await;
    let identity = establish_handshake(&mut connector, ZoneId::work()).await;
    let unauthorized = invoke_json(
        &mut connector,
        &identity,
        "imessage.get_server_info",
        "imessage.admin",
        ZoneId::work(),
        json!({}),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(unauthorized, FcpError::Unauthorized { .. }),
        "{unauthorized:?}"
    );

    let app_unavailable_server = MockServer::start().await;
    mock_server_info(
        &app_unavailable_server,
        503,
        json!({"error": {"message": "Messages app unavailable"}}),
    )
    .await;
    let mut connector = configured_connector(&app_unavailable_server).await;
    let identity = establish_handshake(&mut connector, ZoneId::work()).await;
    let unavailable = invoke_json(
        &mut connector,
        &identity,
        "imessage.get_server_info",
        "imessage.admin",
        ZoneId::work(),
        json!({}),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            unavailable,
            FcpError::External {
                status_code: Some(503),
                retryable: true,
                ..
            }
        ),
        "{unavailable:?}"
    );

    let rate_limited_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/server/info"))
        .and(query_param("password", FIXTURE_AUTH_VALUE))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({"error": {"message": "rate limited"}})),
        )
        .mount(&rate_limited_server)
        .await;
    let mut connector = configured_connector(&rate_limited_server).await;
    let identity = establish_handshake(&mut connector, ZoneId::work()).await;
    let rate_limited = invoke_json(
        &mut connector,
        &identity,
        "imessage.get_server_info",
        "imessage.admin",
        ZoneId::work(),
        json!({}),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            rate_limited,
            FcpError::RateLimited {
                retry_after_ms: 2_000,
                ..
            }
        ),
        "{rate_limited:?}"
    );
}

async fn configured_connector(server: &MockServer) -> BlueBubblesConnector {
    let mut connector = BlueBubblesConnector::new();
    connector.configure(loopback_config(server)).await.unwrap();
    connector
}

async fn configured_connector_with_webhook_policy(server: &MockServer) -> BlueBubblesConnector {
    let mut config = loopback_config(server);
    config["webhook_inbound"] = json!({
        "verify_password": true,
        "allowed_sender_ids": [SENDER_ID],
        "allowed_chat_guids": [CHAT_GUID],
        "allowed_event_types": ["new-message"],
        "max_payload_bytes": 65_536,
        "coalesce_ms": 0
    });
    let mut connector = BlueBubblesConnector::new();
    connector.configure(config).await.unwrap();
    connector
}

fn loopback_config(server: &MockServer) -> Value {
    json!({
        "server_url": server.uri(),
        "password": FIXTURE_AUTH_VALUE,
        "request_timeout_ms": 1_000,
        "retry": {
            "max_retries": 0,
            "initial_delay_ms": 0,
            "max_delay_ms": 0,
            "jitter_enabled": false
        }
    })
}

async fn establish_handshake(
    connector: &mut BlueBubblesConnector,
    zone: ZoneId,
) -> ConnectorIdentity {
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_owned(),
            zone: zone.clone(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: *b"0123456789abcdef0123456789abcdef",
            capabilities_requested: vec![
                CapabilityId::from_static("imessage.send"),
                CapabilityId::from_static("imessage.read"),
                CapabilityId::from_static("imessage.admin"),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: Some(instance_id.clone()),
        })
        .await
        .unwrap();

    ConnectorIdentity {
        signing_key,
        instance_id,
    }
}

async fn invoke_json(
    connector: &mut BlueBubblesConnector,
    identity: &ConnectorIdentity,
    operation: &str,
    capability: &str,
    zone: ZoneId,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_owned(),
            id: RequestId::new(format!("req-{operation}")),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::new(operation).unwrap(),
            zone_id: zone.clone(),
            input,
            capability_token: valid_token(identity, capability, operation, zone, true),
            holder_proof: None,
            context: None,
            idempotency_key: Some(format!("idem-{operation}")),
            lease_seq: None,
            deadline_ms: Some(5_000),
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .map(|response| {
            response
                .result
                .expect("invoke response must include result")
        })
}

fn valid_token(
    identity: &ConnectorIdentity,
    capability: &str,
    operation: &str,
    zone: ZoneId,
    bind_instance: bool,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_owned()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();

    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone.as_str())
        .principal("user:fixture")
        .operations(&[operation])
        .issuer("node:test-host")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap();

    if bind_instance {
        builder = builder.target_instance(identity.instance_id.as_str());
    }

    CapabilityToken::from_raw(builder.sign(&identity.signing_key).unwrap())
}

async fn mock_server_info(server: &MockServer, status: u16, body: Value) {
    Mock::given(method("GET"))
        .and(path("/api/v1/server/info"))
        .and(query_param("password", FIXTURE_AUTH_VALUE))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

fn server_info_body(private_api: bool) -> Value {
    json!({
        "data": {
            "os_version": "26.0",
            "server_version": "1.10.0-test",
            "private_api": private_api,
            "proxy_service": "none",
            "helper_connected": private_api
        }
    })
}

fn webhook_request_input(auth_value: &str, body: Value) -> Value {
    json!({
        "method": "POST",
        "url": format!(
            "http://localhost:8645/bluebubbles-webhook?{WEBHOOK_AUTH_QUERY_KEY}={auth_value}"
        ),
        "headers": {"x-bluebubbles-event": "new-message"},
        "body": body,
        "received_at": "2026-05-08T00:00:00Z"
    })
}

fn webhook_url(server: &MockServer, auth_value: &str) -> String {
    format!(
        "{}/webhook?{}={}",
        server.uri(),
        WEBHOOK_AUTH_QUERY_KEY,
        auth_value
    )
}

fn webhook_body(sender_id: &str, chat_guid: &str) -> Value {
    json!({
        "type": "new-message",
        "data": {
            "guid": MESSAGE_GUID,
            "text": MESSAGE_TEXT,
            "isFromMe": false,
            "handle": {"address": sender_id},
            "chats": [{"guid": chat_guid}]
        }
    })
}

fn assert_no_secret_leak(output: &Value) {
    let serialized = output.to_string();
    for forbidden in [FIXTURE_AUTH_VALUE, MESSAGE_TEXT, "/tmp/fcp-imessage"] {
        assert!(
            !serialized.contains(forbidden),
            "output leaked forbidden fixture material: {serialized}"
        );
    }
}

struct ConnectorIdentity {
    signing_key: Ed25519SigningKey,
    instance_id: InstanceId,
}

#[derive(Serialize)]
struct ProofLog<'a> {
    command_line: &'a str,
    git_revision: &'a str,
    connector_id: &'a str,
    operation_id: &'a str,
    capability: &'a str,
    zone: String,
    instance_id: String,
    platform: &'a str,
    bridge_fixture_id: &'a str,
    target_id_hash: String,
    lifecycle_phase: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    audit_receipt_id: &'a str,
    cleanup_result: &'a str,
    skip_reason: Option<&'a str>,
}

impl<'a> ProofLog<'a> {
    fn success(
        operation_id: &'a str,
        capability: &'a str,
        identity: &'a ConnectorIdentity,
        zone: ZoneId,
        latency_ms: u128,
        bridge_fixture_id: &'a str,
    ) -> Self {
        Self {
            command_line: "rch exec -- cargo test -p fcp-imessage --tests -- --nocapture",
            git_revision: option_env!("FCP_GIT_REVISION").unwrap_or("unknown:not-injected"),
            connector_id: CONNECTOR_ID,
            operation_id,
            capability,
            zone: zone.as_str().to_owned(),
            instance_id: identity.instance_id.as_str().to_owned(),
            platform: std::env::consts::OS,
            bridge_fixture_id,
            target_id_hash: hashed_target_id(CHAT_GUID),
            lifecycle_phase: "connector-local-test",
            latency_ms,
            result: "ok",
            error_code: None,
            audit_receipt_id: "not-issued:connector-local-fixture",
            cleanup_result: "memory-only-fixture-dropped",
            skip_reason: None,
        }
    }
}

fn emit_proof_log(log: ProofLog<'_>) {
    let line = serde_json::to_string(&log).unwrap();
    assert!(!line.contains(FIXTURE_AUTH_VALUE));
    assert!(!line.contains(MESSAGE_TEXT));
    assert!(!line.contains(SENDER_ID));
    assert!(!line.contains(CHAT_GUID));
    assert!(!line.contains("/tmp/"));
    eprintln!("{line}");
}

fn hashed_target_id(target_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(target_id.as_bytes());
    hex::encode(hasher.finalize())
}
