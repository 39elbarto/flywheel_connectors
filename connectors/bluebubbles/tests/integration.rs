#![allow(
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::unwrap_used
)]

use std::fmt::Write as _;
use std::str::FromStr as _;
use std::time::Instant;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_bluebubbles::{CONNECTOR_ID, SharedBlueBubblesConnector, new_connector};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, HealthState, InstanceId, InvokeRequest, OperationId, RequestId,
    ShutdownRequest, SimulateRequest, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PASSWORD: &str = "test-password-123";
const WEBHOOK_AUTH_QUERY: &str = "password";
const CHAT_GUID: &str = "iMessage;-;+15551234567";
const GROUP_CHAT_GUID: &str = "iMessage;+;chat123";
const MESSAGE_TEXT: &str = "sensitive message body";

const OP_SEND_MESSAGE: &str = "imessage.send_message";
const OP_SEND_MEDIA: &str = "imessage.send_media";
const OP_GET_SERVER_INFO: &str = "imessage.get_server_info";
const OP_INGEST_WEBHOOK_REQUEST: &str = "imessage.ingest_webhook_request";

const CAP_SEND: &str = "imessage.send";
const CAP_READ: &str = "imessage.read";
const CAP_ADMIN: &str = "imessage.admin";

#[fcp_async_core::runtime::test]
async fn lifecycle_loopback_bound_invoke_simulate_health_and_jsonl_logging() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/server/info"))
        .and(query_param("password", PASSWORD))
        .respond_with(ResponseTemplate::new(200).set_body_json(server_info_fixture()))
        .expect(1)
        .mount(&server)
        .await;

    let instance_id = make_instance_id("lifecycle");
    let (mut connector, signing_key) =
        configure_and_handshake(loopback_config(&server.uri()), &instance_id).await;

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert!(matches!(
        connector.health().await.status,
        HealthState::Ready
    ));
    assert!(connector.doctor().passed);

    let started_at = Instant::now();
    let response = connector
        .invoke(invoke_request(
            connector.id(),
            OP_GET_SERVER_INFO,
            &ZoneId::work(),
            json!({}),
            valid_token(
                &signing_key,
                &instance_id,
                OP_GET_SERVER_INFO,
                CAP_ADMIN,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("server-info invoke should succeed against loopback");
    let result = response
        .result
        .expect("server-info invoke should include result payload");
    assert_eq!(result["private_api"], true);
    assert_eq!(result["server_version"], "1.10.0-test");

    let simulation = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({
                "chat_guid": CHAT_GUID,
                "message": MESSAGE_TEXT
            }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEND_MESSAGE,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("send-message simulation should be policy-evaluable");
    assert!(simulation.would_succeed);

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("bluebubbles loopback lifecycle test complete".into()),
        })
        .await
        .expect("shutdown should drain cleanly");

    emit_proof_log(&ProofLog {
        event: "lifecycle_loopback",
        operation: OP_GET_SERVER_INFO,
        capability: CAP_ADMIN,
        zone: ZoneId::work().as_str(),
        instance_id: instance_id.as_str(),
        fixture_id: "bluebubbles-server-info-v1",
        webhook_id_hash: None,
        conversation_id_hash: Some(&hash_pii(CHAT_GUID)),
        attachment_kind: "none",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        lifecycle_phase: "configure-handshake-invoke-simulate-shutdown",
        audit: "health-ready,doctor-passed,bound-token-invoke,simulate-allowed,shutdown-drained",
        audit_receipt_id: "not-issued:connector-local-loopback",
        cleanup: "wiremock-server-dropped",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn send_message_loopback_posts_without_logging_bodies_or_phone_numbers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/server/info"))
        .and(query_param("password", PASSWORD))
        .respond_with(ResponseTemplate::new(200).set_body_json(server_info_fixture()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/message/text"))
        .and(query_param("password", PASSWORD))
        .and(body_partial_json(json!({
            "chatGuid": CHAT_GUID,
            "message": MESSAGE_TEXT
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": 200,
            "message": "queued",
            "data": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let instance_id = make_instance_id("send_message");
    let (connector, signing_key) =
        configure_and_handshake(loopback_config(&server.uri()), &instance_id).await;

    let started_at = Instant::now();
    let output = connector
        .invoke(invoke_request(
            connector.id(),
            OP_SEND_MESSAGE,
            &ZoneId::work(),
            json!({
                "chat_guid": CHAT_GUID,
                "message": MESSAGE_TEXT
            }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEND_MESSAGE,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("send-message invoke should succeed against loopback")
        .result
        .expect("send-message invoke should include result payload");

    assert_eq!(output["status"], 200);
    assert_eq!(output["message"], "queued");
    assert!(output["send_method"].is_string());

    emit_proof_log(&ProofLog {
        event: "send_message_loopback",
        operation: OP_SEND_MESSAGE,
        capability: CAP_SEND,
        zone: ZoneId::work().as_str(),
        instance_id: instance_id.as_str(),
        fixture_id: "bluebubbles-send-message-v1",
        webhook_id_hash: None,
        conversation_id_hash: Some(&hash_pii(CHAT_GUID)),
        attachment_kind: "none",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        lifecycle_phase: "configure-handshake-invoke",
        audit: "loopback-post-observed,password-query-not-logged,message-body-not-logged",
        audit_receipt_id: "not-issued:connector-local-loopback",
        cleanup: "wiremock-server-dropped",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn webhook_ingress_covers_attachment_reply_tapback_binding_and_redaction_edges() {
    let instance_id = make_instance_id("webhook");
    let (connector, signing_key) = configure_and_handshake(webhook_config(), &instance_id).await;

    let started_at = Instant::now();
    let accepted = invoke_webhook_request(
        &connector,
        &signing_key,
        &instance_id,
        json!({
            "type": "new-message",
            "data": {
                "guid": "msg-001",
                "text": MESSAGE_TEXT,
                "isFromMe": false,
                "handle": { "address": "+15551234567", "displayName": "Alice" },
                "dateCreated": 1_700_000_000_123_i64,
                "chats": [{
                    "guid": GROUP_CHAT_GUID,
                    "chatIdentifier": "Family"
                }],
                "attachments": [{
                    "guid": "att-1",
                    "mimeType": "image/png",
                    "uti": "public.png",
                    "transferName": "photo.png",
                    "totalBytes": 123
                }],
                "threadOriginatorGuid": "root-1"
            }
        }),
        PASSWORD,
    )
    .await;
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["status_code"], 200);
    assert_eq!(accepted["reason_code"], "event_accepted");
    assert_eq!(
        accepted["ingest"]["event_envelopes"][0]["topic"],
        "imessage.message.inbound"
    );
    assert_eq!(
        accepted["ingest"]["events"][0]["attachments"][0]["mime_type"],
        "image/png"
    );
    assert_eq!(
        accepted["ingest"]["events"][0]["reply_to_message_guid"],
        "root-1"
    );
    assert!(
        !serde_json::to_string(&accepted)
            .expect("webhook output should serialize")
            .contains(PASSWORD)
    );

    let tapback = invoke_webhook_request(
        &connector,
        &signing_key,
        &instance_id,
        json!({
            "type": "updated-message",
            "data": {
                "guid": "tapback-1",
                "text": "Loved a prior message",
                "isFromMe": false,
                "handle": { "address": "+15551234567" },
                "chats": [{ "guid": CHAT_GUID }],
                "associatedMessageGuid": "msg-root",
                "associatedMessageType": 2000,
                "balloonBundleId": "com.apple.messages.URLBalloonProvider"
            }
        }),
        PASSWORD,
    )
    .await;
    assert_eq!(tapback["accepted"], true);
    assert_eq!(
        tapback["ingest"]["event_envelopes"][0]["topic"],
        "imessage.message.tapback"
    );
    assert_eq!(tapback["ingest"]["events"][0]["is_tapback"], true);

    let unbound_conversation = invoke_webhook_request(
        &connector,
        &signing_key,
        &instance_id,
        json!({
            "type": "new-message",
            "data": {
                "guid": "msg-unbound",
                "text": "body should stay out of proof logs",
                "isFromMe": false,
                "handle": { "address": "+15551234567" },
                "chats": [{ "guid": "iMessage;-;+15550000000" }]
            }
        }),
        PASSWORD,
    )
    .await;
    assert_eq!(unbound_conversation["accepted"], false);
    assert_eq!(unbound_conversation["status_code"], 403);
    assert_eq!(unbound_conversation["reason_code"], "policy_rejected");
    assert_eq!(
        unbound_conversation["ingest"]["acceptance"]["reason"],
        "conversation_not_bound"
    );

    emit_proof_log(&ProofLog {
        event: "webhook_ingress_matrix",
        operation: OP_INGEST_WEBHOOK_REQUEST,
        capability: CAP_READ,
        zone: ZoneId::work().as_str(),
        instance_id: instance_id.as_str(),
        fixture_id: "bluebubbles-webhook-fixture-v1",
        webhook_id_hash: Some(&hash_pii("msg-001")),
        conversation_id_hash: Some(&hash_pii(GROUP_CHAT_GUID)),
        attachment_kind: "image/png",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        lifecycle_phase: "configure-handshake-webhook-ingress",
        audit: "auth-redacted,attachment-normalized,reply-bound,tapback-classified,conversation-binding-denied",
        audit_receipt_id: "not-issued:connector-local-loopback",
        cleanup: "memory-dedupe-only",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn capability_zone_instance_and_missing_instance_denials_are_explicit() {
    let instance_id = make_instance_id("denials");
    let (connector, signing_key) =
        configure_and_handshake(loopback_config("http://127.0.0.1:1234"), &instance_id).await;

    let wrong_zone = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_GET_SERVER_INFO),
            ZoneId::work(),
            json!({}),
            valid_token(
                &signing_key,
                &instance_id,
                OP_GET_SERVER_INFO,
                CAP_ADMIN,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect("wrong-zone token should produce a simulate response");
    assert!(!wrong_zone.would_succeed);
    assert_eq!(wrong_zone.denial_code.as_deref(), Some("FCP-4001"));

    let wrong_instance = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_GET_SERVER_INFO),
            ZoneId::work(),
            json!({}),
            valid_token(
                &signing_key,
                &make_instance_id("other"),
                OP_GET_SERVER_INFO,
                CAP_ADMIN,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("wrong-instance token should produce a simulate response");
    assert!(!wrong_instance.would_succeed);
    assert_eq!(wrong_instance.denial_code.as_deref(), Some("FCP-4001"));
    assert!(
        wrong_instance
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("Token instance mismatch"))
    );

    let missing_instance = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_GET_SERVER_INFO),
            ZoneId::work(),
            json!({}),
            token_without_instance(&signing_key, OP_GET_SERVER_INFO, CAP_ADMIN, &ZoneId::work()),
        ))
        .await
        .expect("missing-instance token should produce a simulate response");
    assert!(!missing_instance.would_succeed);
    assert_eq!(missing_instance.denial_code.as_deref(), Some("FCP-1006"));
}

#[fcp_async_core::runtime::test]
async fn malformed_unauthorized_rate_limited_timeout_and_network_errors_are_mapped() {
    let instance_id = make_instance_id("errors");
    let (connector, signing_key) = configure_and_handshake(webhook_config(), &instance_id).await;

    let malformed = invoke_webhook_raw(
        &connector,
        &signing_key,
        &instance_id,
        json!({
            "method": "POST",
            "url": webhook_url(PASSWORD),
            "body": "not an object"
        }),
    )
    .await;
    assert_eq!(malformed["accepted"], false);
    assert_eq!(malformed["status_code"], 400);
    assert_eq!(malformed["reason_code"], "malformed_payload");

    let unauthorized = invoke_webhook_request(
        &connector,
        &signing_key,
        &instance_id,
        accepted_dm_payload("msg-bad-auth", CHAT_GUID),
        "wrong-password",
    )
    .await;
    assert_eq!(unauthorized["accepted"], false);
    assert_eq!(unauthorized["status_code"], 401);
    assert_eq!(unauthorized["reason_code"], "invalid_auth");

    let timed_out = invoke_webhook_raw(
        &connector,
        &signing_key,
        &instance_id,
        json!({
            "method": "POST",
            "url": webhook_url(PASSWORD),
            "request_region": { "deadline_exceeded": true },
            "body": accepted_dm_payload("msg-timeout", CHAT_GUID)
        }),
    )
    .await;
    assert_eq!(timed_out["accepted"], false);
    assert_eq!(timed_out["status_code"], 408);
    assert_eq!(timed_out["reason_code"], "request_timeout");

    let rate_limited_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/server/info"))
        .and(query_param("password", PASSWORD))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "2"))
        .expect(1)
        .mount(&rate_limited_server)
        .await;
    let (rate_limited_connector, rate_limited_key) = configure_and_handshake(
        loopback_config(&rate_limited_server.uri()),
        &make_instance_id("rate_limited"),
    )
    .await;
    let rate_limited_error = rate_limited_connector
        .invoke(invoke_request(
            rate_limited_connector.id(),
            OP_GET_SERVER_INFO,
            &ZoneId::work(),
            json!({}),
            valid_token(
                &rate_limited_key,
                &make_instance_id("rate_limited"),
                OP_GET_SERVER_INFO,
                CAP_ADMIN,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect_err("429 server-info response should map to rate limit");
    assert!(matches!(
        rate_limited_error,
        FcpError::RateLimited {
            retry_after_ms: 2_000,
            ..
        }
    ));

    let failing_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/server/info"))
        .and(query_param("password", PASSWORD))
        .respond_with(ResponseTemplate::new(503).set_body_string("bridge unavailable"))
        .expect(1)
        .mount(&failing_server)
        .await;
    let failing_instance = make_instance_id("network");
    let (failing_connector, failing_key) =
        configure_and_handshake(loopback_config(&failing_server.uri()), &failing_instance).await;
    let network_error = failing_connector
        .invoke(invoke_request(
            failing_connector.id(),
            OP_GET_SERVER_INFO,
            &ZoneId::work(),
            json!({}),
            valid_token(
                &failing_key,
                &failing_instance,
                OP_GET_SERVER_INFO,
                CAP_ADMIN,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect_err("503 server-info response should map to retryable external error");
    assert!(matches!(
        network_error,
        FcpError::External {
            status_code: Some(503),
            retryable: true,
            ..
        }
    ));
}

#[fcp_async_core::runtime::test]
async fn send_media_rejects_unconfigured_local_roots_before_uploading_attachment_bytes() {
    let instance_id = make_instance_id("media_denial");
    let (connector, signing_key) =
        configure_and_handshake(loopback_config("http://127.0.0.1:1234"), &instance_id).await;

    let error = connector
        .invoke(invoke_request(
            connector.id(),
            OP_SEND_MEDIA,
            &ZoneId::work(),
            json!({
                "chat_guid": CHAT_GUID,
                "local_path": "/tmp/bluebubbles-private-photo.png",
                "content_type": "image/png"
            }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEND_MEDIA,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect_err("media send should fail closed before reading outside configured roots");
    assert!(matches!(error, FcpError::InvalidRequest { .. }));
}

async fn configure_and_handshake(
    config: Value,
    instance_id: &InstanceId,
) -> (SharedBlueBubblesConnector, Ed25519SigningKey) {
    let mut connector = new_connector();
    assert!(
        !matches!(connector.health().await.status, HealthState::Ready),
        "connector must not start ready before configure"
    );
    connector
        .configure(config)
        .await
        .expect("BlueBubbles connector should accept deterministic test config");
    let signing_key = Ed25519SigningKey::generate();
    let response = connector
        .handshake(handshake_request(&signing_key, instance_id))
        .await
        .expect("handshake should accept deterministic requested instance id");
    assert_eq!(response.status, "accepted");
    assert!(
        response
            .capabilities_granted
            .iter()
            .any(|grant| grant.capability.as_str() == CAP_ADMIN)
    );
    (connector, signing_key)
}

fn handshake_request(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: signing_key.verifying_key().to_bytes(),
        nonce: [7; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_SEND),
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_ADMIN),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn invoke_request(
    connector_id: &ConnectorId,
    operation: &'static str,
    zone_id: &ZoneId,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("req_{operation}")),
        connector_id: connector_id.clone(),
        operation: OperationId::from_static(operation),
        zone_id: zone_id.clone(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: Some(format!("idem_{operation}")),
        lease_seq: None,
        deadline_ms: Some(5_000),
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &'static str,
    capability: &'static str,
    zone_id: &ZoneId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize to CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone_id.as_str())
        .principal("user:bluebubbles-test")
        .operations(&[operation])
        .issuer("node:bluebubbles-test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn token_without_instance(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    zone_id: &ZoneId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize to CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone_id.as_str())
        .principal("user:bluebubbles-test")
        .operations(&[operation])
        .issuer("node:bluebubbles-test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn invoke_webhook_request(
    connector: &SharedBlueBubblesConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    body: Value,
    auth: &str,
) -> Value {
    invoke_webhook_raw(
        connector,
        signing_key,
        instance_id,
        json!({
            "method": "POST",
            "url": webhook_url(auth),
            "headers": { "x-bluebubbles-event": "new-message" },
            "request_region": { "source": "loopback_harness" },
            "account_id": "acct-a",
            "observed_at_ms": 1_700_000_000_000_i64,
            "body": body
        }),
    )
    .await
}

async fn invoke_webhook_raw(
    connector: &SharedBlueBubblesConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    input: Value,
) -> Value {
    connector
        .invoke(invoke_request(
            connector.id(),
            OP_INGEST_WEBHOOK_REQUEST,
            &ZoneId::work(),
            input,
            valid_token(
                signing_key,
                instance_id,
                OP_INGEST_WEBHOOK_REQUEST,
                CAP_READ,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("webhook request should return an FCP result payload")
        .result
        .expect("webhook request should include result payload")
}

fn loopback_config(server_url: &str) -> Value {
    json!({
        "server_url": server_url,
        "password": PASSWORD,
        "request_timeout_ms": 2_000,
        "retry": {
            "max_retries": 0,
            "initial_delay_ms": 0,
            "max_delay_ms": 0,
            "jitter_enabled": false
        }
    })
}

fn webhook_config() -> Value {
    let mut config = loopback_config("http://127.0.0.1:1234");
    config["webhook_inbound"] = json!({
        "allowed_sender_ids": ["+15551234567"],
        "allowed_chat_guids": [CHAT_GUID, GROUP_CHAT_GUID],
        "allow_group_chats": true
    });
    config
}

fn server_info_fixture() -> Value {
    json!({
        "data": {
            "os_version": "26.0",
            "server_version": "1.10.0-test",
            "private_api": true,
            "proxy_service": "none"
        }
    })
}

fn accepted_dm_payload(guid: &str, chat_guid: &str) -> Value {
    json!({
        "type": "new-message",
        "data": {
            "guid": guid,
            "text": MESSAGE_TEXT,
            "isFromMe": false,
            "handle": { "address": "+15551234567" },
            "chats": [{ "guid": chat_guid }]
        }
    })
}

fn webhook_url(auth: &str) -> String {
    format!("http://localhost:8645/bluebubbles-webhook?{WEBHOOK_AUTH_QUERY}={auth}")
}

fn make_instance_id(suffix: &str) -> InstanceId {
    InstanceId::from_str(&format!("inst_bluebubbles_{suffix}"))
        .expect("test instance id should be canonical")
}

fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}

fn hash_pii(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::from("sha256:");
    for byte in digest.iter().take(8) {
        write!(&mut out, "{byte:02x}").expect("writing to string should not fail");
    }
    out
}

struct ProofLog<'a> {
    event: &'a str,
    operation: &'a str,
    capability: &'a str,
    zone: &'a str,
    instance_id: &'a str,
    fixture_id: &'a str,
    webhook_id_hash: Option<&'a str>,
    conversation_id_hash: Option<&'a str>,
    attachment_kind: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    lifecycle_phase: &'a str,
    audit: &'a str,
    audit_receipt_id: &'a str,
    cleanup: &'a str,
    skip_reason: Option<&'a str>,
}

fn emit_proof_log(proof: &ProofLog<'_>) {
    let line = serde_json::to_string(&json!({
        "command_line": "cargo test -p fcp-bluebubbles --tests -- --nocapture",
        "git_revision": git_revision(),
        "connector_id": CONNECTOR_ID,
        "event": proof.event,
        "op_id": proof.operation,
        "capability": proof.capability,
        "zone": proof.zone,
        "instance_id": proof.instance_id,
        "fixture_id": proof.fixture_id,
        "webhook_id_hash": proof.webhook_id_hash,
        "conversation_id_hash": proof.conversation_id_hash,
        "attachment_kind": proof.attachment_kind,
        "latency_ms": proof.latency_ms,
        "result": proof.result,
        "error_code": proof.error_code,
        "lifecycle_phase": proof.lifecycle_phase,
        "audit": proof.audit,
        "audit_receipt_id": proof.audit_receipt_id,
        "cleanup": proof.cleanup,
        "skip_reason": proof.skip_reason,
        "pii_redaction": {
            "message_bodies": "omitted",
            "phone_numbers": "hashed_or_omitted",
            "attachment_bytes": "omitted",
            "api_keys": "omitted",
            "local_paths": "omitted"
        }
    }))
    .expect("proof log should serialize");
    assert_redacted(&line);
    println!("BLUEBUBBLES_E2E_JSONL {line}");
}

fn assert_redacted(line: &str) {
    for forbidden in [
        PASSWORD,
        MESSAGE_TEXT,
        "+15551234567",
        "+15550000000",
        CHAT_GUID,
        GROUP_CHAT_GUID,
        "/Users/",
        "/tmp/bluebubbles-private-photo.png",
        "photo.png",
    ] {
        assert!(
            !line.contains(forbidden),
            "proof log leaked forbidden value: {forbidden}"
        );
    }
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |value| value.trim().to_string())
}
