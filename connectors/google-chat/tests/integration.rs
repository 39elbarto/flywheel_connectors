#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    net::TcpListener,
    process::Command,
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_chat::connector::ChatConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityToken, ConnectorId, FcpError, InstanceId, OperationId,
    RequestId, SimulateRequest, ZoneId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path, query_param},
};

const CONNECTOR_ID: &str = "google-chat";
const CONNECTOR_MANIFEST_ID: &str = "fcp.google_chat";
const BEAD_ID: &str = "flywheel_connectors-4kw5f.11.10";
const FIXTURE_ACCESS_TOKEN: &str = "fixture-google-chat-oauth-token";
const FIXTURE_WEBHOOK_TOKEN: &str = "fixture-google-chat-webhook-token";
const LIST_SPACES_OP: &str = "chat.list_spaces";
const SEND_MESSAGE_OP: &str = "chat.send_message";
const REPLY_MESSAGE_OP: &str = "chat.reply_message";
const INGEST_WEBHOOK_OP: &str = "chat.ingest_webhook";
const READ_CAP: &str = "chat.read";
const WRITE_CAP: &str = "chat.write";
const WEBHOOK_CAP: &str = "chat.webhook";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleChatEvidenceLog {
    schema_version: String,
    bead_id: String,
    command_line: String,
    git_revision: String,
    connector_id: String,
    operation_id: String,
    capability: String,
    zone: String,
    instance_id: String,
    fixture_id: String,
    space_id_hash: String,
    thread_id_hash: Option<String>,
    event_id_hash: Option<String>,
    lifecycle_phase: String,
    latency_ms: u64,
    result: String,
    error_code: Option<String>,
    audit_receipt_id: String,
    cleanup_result: String,
    skip_reason: Option<String>,
    redaction: String,
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-git-revision".to_string())
}

fn stable_hash(input: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv64:{hash:016x}")
}

fn elapsed_millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn evidence_log(
    operation_id: &str,
    capability: &str,
    space_id: &str,
    thread_id: Option<&str>,
    event_id: Option<&str>,
    latency_ms: u64,
    result: &str,
    error_code: Option<String>,
    cleanup_result: &str,
    skip_reason: Option<&str>,
) -> GoogleChatEvidenceLog {
    GoogleChatEvidenceLog {
        schema_version: "google_chat_connector_local_evidence.v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        command_line: "cargo test -p fcp-google-chat --test integration".to_string(),
        git_revision: git_revision(),
        connector_id: CONNECTOR_MANIFEST_ID.to_string(),
        operation_id: operation_id.to_string(),
        capability: capability.to_string(),
        zone: "z:work".to_string(),
        instance_id: stable_hash("google-chat-loopback-instance"),
        fixture_id: "google-workspace-chat-loopback-fixture.v1".to_string(),
        space_id_hash: stable_hash(space_id),
        thread_id_hash: thread_id.map(stable_hash),
        event_id_hash: event_id.map(stable_hash),
        lifecycle_phase: "invoke".to_string(),
        latency_ms,
        result: result.to_string(),
        error_code,
        audit_receipt_id: format!("audit:{BEAD_ID}:{operation_id}"),
        cleanup_result: cleanup_result.to_string(),
        skip_reason: skip_reason.map(str::to_string),
        redaction:
            "oauth_token_message_body_user_email_display_name_provider_body_paths_not_logged"
                .to_string(),
    }
}

fn assert_log_shape_and_redaction(logs: &[GoogleChatEvidenceLog]) {
    assert!(!logs.is_empty(), "expected at least one evidence log");
    for entry in logs {
        let value = serde_json::to_value(entry).expect("evidence log JSON");
        for field in [
            "command_line",
            "git_revision",
            "connector_id",
            "operation_id",
            "capability",
            "zone",
            "instance_id",
            "fixture_id",
            "space_id_hash",
            "thread_id_hash",
            "event_id_hash",
            "lifecycle_phase",
            "latency_ms",
            "result",
            "error_code",
            "audit_receipt_id",
            "cleanup_result",
            "skip_reason",
        ] {
            assert!(value.get(field).is_some(), "missing evidence field {field}");
        }
        eprintln!("{}", serde_json::to_string(entry).expect("log JSONL"));
    }

    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        FIXTURE_ACCESS_TOKEN,
        FIXTURE_WEBHOOK_TOKEN,
        "secret message body",
        "provider raw body",
        "alice@example.com",
        "Alice Example",
        "General Room",
        "spaces/AAAA",
        "/Users/",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "evidence logs should not contain sensitive sentinel `{forbidden}`"
        );
    }
}

fn config(base_url: &str, request_timeout_ms: Option<u64>, webhook: bool) -> Value {
    let mut config = json!({
        "access_token": FIXTURE_ACCESS_TOKEN,
        "base_url": base_url,
        "chat_coordination": {
            "enabled": false
        }
    });
    if let Some(timeout) = request_timeout_ms {
        config["request_timeout_ms"] = json!(timeout);
    }
    if webhook {
        config["webhook"] = json!({
            "enabled": true,
            "allowed_bearer_tokens": [FIXTURE_WEBHOOK_TOKEN],
            "body_timeout_ms": 3000,
            "max_body_bytes": 65536,
            "preauth_max_body_bytes": 16384
        });
        config["inbound_policy"] = json!({
            "group_policy": "open",
            "require_mention": true,
            "bot_user": "users/app"
        });
    }
    config
}

async fn configure_and_handshake(
    connector: &mut ChatConnector,
    signing_key: &Ed25519SigningKey,
    base_url: &str,
    request_timeout_ms: Option<u64>,
    webhook: bool,
) {
    connector
        .handle_configure(config(base_url, request_timeout_ms, webhook))
        .await
        .expect("configure should accept loopback base URL");
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": [READ_CAP, WRITE_CAP, WEBHOOK_CAP],
        }))
        .await
        .expect("handshake should complete");
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    zone: &str,
    target_instance: Option<&str>,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone)
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor");
    if let Some(instance) = target_instance {
        builder = builder.target_instance(instance);
    }
    CapabilityToken::from_raw(builder.sign(signing_key).expect("sign token"))
}

fn simulate_request_json(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    zone: &str,
    target_instance: Option<&str>,
) -> Value {
    serde_json::to_value(SimulateRequest {
        r#type: "simulate".into(),
        id: RequestId::new(format!("sim-{operation}")),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::new(operation).expect("valid operation id"),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: capability_token(
            signing_key,
            capability,
            operation,
            zone,
            target_instance,
        ),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    })
    .expect("serialize simulate request")
}

fn unused_loopback_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused loopback port");
    let addr = listener.local_addr().expect("unused loopback address");
    drop(listener);
    format!("http://{addr}/v1")
}

fn google_api_error(code: u16, message: &str) -> Value {
    json!({
        "error": {
            "code": code,
            "message": message
        }
    })
}

async fn configured_connector(
    base_url: &str,
    request_timeout_ms: Option<u64>,
    webhook: bool,
) -> ChatConnector {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = ChatConnector::new();
    configure_and_handshake(
        &mut connector,
        &signing_key,
        base_url,
        request_timeout_ms,
        webhook,
    )
    .await;
    connector
}

#[fcp_async_core::runtime::test]
async fn connector_lifecycle_uses_oauth_fixture_without_leaking_token() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = ChatConnector::new();

    let before = connector
        .handle_health()
        .await
        .expect("health before config");
    assert_eq!(before["status"], "not_configured");

    configure_and_handshake(
        &mut connector,
        &signing_key,
        "http://127.0.0.1:1/v1",
        None,
        true,
    )
    .await;
    let health = connector
        .handle_health()
        .await
        .expect("health after config");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["metrics"]["requests_total"], 0);
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor after config");
    assert_eq!(doctor["status"], "healthy");
    let self_check = connector
        .handle_self_check()
        .await
        .expect("self-check after config");
    assert_eq!(self_check["status"], "pass");

    let shutdown = connector
        .handle_shutdown(json!({ "reason": "connector-local integration test" }))
        .await
        .expect("shutdown should complete");
    assert_eq!(shutdown["status"], "shutdown");

    let wire =
        serde_json::to_string(&json!([health, doctor, self_check, shutdown])).expect("serialize");
    assert!(!wire.contains(FIXTURE_ACCESS_TOKEN));
    assert!(!wire.contains(FIXTURE_WEBHOOK_TOKEN));
}

#[fcp_async_core::runtime::test]
async fn capability_tokens_deny_wrong_zone_or_instance_before_execution() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = ChatConnector::new();
    configure_and_handshake(
        &mut connector,
        &signing_key,
        "http://127.0.0.1:1/v1",
        None,
        false,
    )
    .await;
    let connector_instance_id = connector.instance_id().to_string();

    let allowed = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            READ_CAP,
            LIST_SPACES_OP,
            "z:work",
            Some(&connector_instance_id),
        ))
        .await
        .expect("valid simulate should return policy result");
    assert_eq!(allowed["would_succeed"], true);

    let wrong_instance = InstanceId::new();
    let instance_denied = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            READ_CAP,
            LIST_SPACES_OP,
            "z:work",
            Some(wrong_instance.as_str()),
        ))
        .await
        .expect("simulate wrong instance should return policy result");
    assert_eq!(instance_denied["would_succeed"], false);
    assert!(
        instance_denied["failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("Token instance mismatch"))
    );

    let wrong_zone = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            READ_CAP,
            LIST_SPACES_OP,
            "z:private",
            Some(&connector_instance_id),
        ))
        .await
        .expect("simulate wrong zone should return policy result");
    assert_eq!(wrong_zone["would_succeed"], false);
    assert_eq!(wrong_zone["denial_code"], "FCP-4001");
    assert!(
        wrong_zone["failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("Token audience mismatch"))
    );
}

#[fcp_async_core::runtime::test]
async fn loopback_workspace_rest_and_webhook_emit_redacted_jsonl() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spaces"))
        .and(header(
            "authorization",
            format!("Bearer {FIXTURE_ACCESS_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spaces": [{
                "name": "spaces/AAAA",
                "displayName": "General Room",
                "spaceType": "ROOM",
                "threaded": true
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/spaces/AAAA/messages"))
        .and(header(
            "authorization",
            format!("Bearer {FIXTURE_ACCESS_TOKEN}"),
        ))
        .and(body_partial_json(json!({
            "text": "secret message body"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "spaces/AAAA/messages/msg-outbound",
            "text": "provider raw body",
            "thread": { "name": "spaces/AAAA/threads/thread-one" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/spaces/AAAA/messages"))
        .and(query_param(
            "messageReplyOption",
            "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD",
        ))
        .and(header(
            "authorization",
            format!("Bearer {FIXTURE_ACCESS_TOKEN}"),
        ))
        .and(body_partial_json(json!({
            "text": "secret threaded reply",
            "thread": { "threadKey": "incident-secret-thread" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "spaces/AAAA/messages/msg-reply",
            "thread": { "name": "spaces/AAAA/threads/thread-one" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let mut connector = ChatConnector::new();
    configure_and_handshake(
        &mut connector,
        &signing_key,
        &format!("{}/v1", server.uri()),
        None,
        true,
    )
    .await;
    let mut logs = Vec::new();

    let start = Instant::now();
    let spaces = connector
        .handle_invoke(json!({
            "operation": LIST_SPACES_OP,
            "input": {}
        }))
        .await
        .expect("list spaces through loopback");
    assert_eq!(spaces["spaces"][0]["name"], "spaces/AAAA");
    logs.push(evidence_log(
        LIST_SPACES_OP,
        READ_CAP,
        "spaces/AAAA",
        None,
        None,
        elapsed_millis(start),
        "ok",
        None,
        "listed_spaces",
        None,
    ));

    let start = Instant::now();
    let sent = connector
        .handle_invoke(json!({
            "operation": SEND_MESSAGE_OP,
            "input": {
                "space_name": "spaces/AAAA",
                "text": "secret message body"
            }
        }))
        .await
        .expect("send message through loopback");
    assert_eq!(sent["message"]["name"], "spaces/AAAA/messages/msg-outbound");
    logs.push(evidence_log(
        SEND_MESSAGE_OP,
        WRITE_CAP,
        "spaces/AAAA",
        Some("spaces/AAAA/threads/thread-one"),
        None,
        elapsed_millis(start),
        "ok",
        None,
        "message_sent",
        None,
    ));

    let start = Instant::now();
    let reply = connector
        .handle_invoke(json!({
            "operation": REPLY_MESSAGE_OP,
            "input": {
                "space_name": "spaces/AAAA",
                "text": "secret threaded reply",
                "thread_key": "incident-secret-thread",
                "message_reply_option": "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
            }
        }))
        .await
        .expect("reply message through loopback");
    assert_eq!(reply["message"]["name"], "spaces/AAAA/messages/msg-reply");
    logs.push(evidence_log(
        REPLY_MESSAGE_OP,
        WRITE_CAP,
        "spaces/AAAA",
        Some("incident-secret-thread"),
        None,
        elapsed_millis(start),
        "ok",
        None,
        "reply_sent",
        None,
    ));

    let webhook_body = json!({
        "type": "MESSAGE",
        "space": {
            "name": "spaces/AAAA",
            "displayName": "General Room",
            "spaceType": "ROOM"
        },
        "message": {
            "name": "spaces/AAAA/messages/msg-webhook",
            "text": "@flywheel secret message body",
            "sender": {
                "name": "users/123",
                "displayName": "Alice Example",
                "email": "alice@example.com"
            },
            "thread": {
                "name": "spaces/AAAA/threads/thread-one",
                "threadKey": "incident-secret-thread"
            }
        }
    });
    let start = Instant::now();
    let webhook = connector
        .handle_invoke(json!({
            "operation": INGEST_WEBHOOK_OP,
            "input": {
                "method": "POST",
                "headers": {
                    "authorization": format!("Bearer {FIXTURE_WEBHOOK_TOKEN}"),
                    "content-type": "application/json"
                },
                "body": webhook_body,
                "body_size_bytes": 512,
                "body_read_elapsed_ms": 20,
                "delivery_id": "delivery-secret",
                "source_id": "source-secret",
                "command_authorized": true
            }
        }))
        .await
        .expect("ingest webhook fixture");
    assert_eq!(webhook["accepted"], true);
    assert_eq!(webhook["event_emitted"], true);
    assert_eq!(webhook["event"]["message"]["text_redacted_in_logs"], true);
    assert_eq!(webhook["auth"]["token_redacted"], true);
    assert_eq!(webhook["policy"]["ids_redacted"], true);
    logs.push(evidence_log(
        INGEST_WEBHOOK_OP,
        WEBHOOK_CAP,
        "spaces/AAAA",
        Some("incident-secret-thread"),
        Some("spaces/AAAA/messages/msg-webhook"),
        elapsed_millis(start),
        "ok",
        None,
        "webhook_processed",
        None,
    ));

    assert_log_shape_and_redaction(&logs);
}

#[fcp_async_core::runtime::test]
async fn loopback_errors_cover_auth_rate_provider_network_timeout_and_malformed_shapes() {
    let mut logs = Vec::new();

    let unauthorized_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spaces"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(google_api_error(401, "invalid token")),
        )
        .expect(1)
        .mount(&unauthorized_server)
        .await;
    let mut connector =
        configured_connector(&format!("{}/v1", unauthorized_server.uri()), None, false).await;
    let start = Instant::now();
    let unauthorized = connector
        .handle_invoke(json!({
            "operation": LIST_SPACES_OP,
            "input": {}
        }))
        .await
        .expect_err("unauthorized loopback should fail");
    assert!(matches!(
        unauthorized,
        FcpError::Unauthorized { code: 2001, .. }
    ));
    logs.push(evidence_log(
        LIST_SPACES_OP,
        READ_CAP,
        "spaces/error-auth",
        None,
        None,
        elapsed_millis(start),
        "error",
        Some(unauthorized.error_code()),
        "no_cleanup_needed",
        None,
    ));

    let rate_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spaces"))
        .respond_with(
            ResponseTemplate::new(429).set_body_json(google_api_error(429, "rate limited")),
        )
        .expect(1)
        .mount(&rate_server)
        .await;
    connector = configured_connector(&format!("{}/v1", rate_server.uri()), None, false).await;
    let start = Instant::now();
    let limited = connector
        .handle_invoke(json!({
            "operation": LIST_SPACES_OP,
            "input": {}
        }))
        .await
        .expect_err("rate limited loopback should fail");
    assert!(matches!(limited, FcpError::RateLimited { .. }));
    logs.push(evidence_log(
        LIST_SPACES_OP,
        READ_CAP,
        "spaces/error-rate",
        None,
        None,
        elapsed_millis(start),
        "error",
        Some(limited.error_code()),
        "retry_decision_recorded",
        None,
    ));

    let provider_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spaces"))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(google_api_error(503, "provider unavailable")),
        )
        .expect(1)
        .mount(&provider_server)
        .await;
    connector = configured_connector(&format!("{}/v1", provider_server.uri()), None, false).await;
    let start = Instant::now();
    let provider = connector
        .handle_invoke(json!({
            "operation": LIST_SPACES_OP,
            "input": {}
        }))
        .await
        .expect_err("provider loopback should fail");
    assert!(matches!(
        provider,
        FcpError::External {
            ref service,
            status_code: Some(503),
            retryable: true,
            ..
        } if service == "google_chat"
    ));
    logs.push(evidence_log(
        LIST_SPACES_OP,
        READ_CAP,
        "spaces/error-provider",
        None,
        None,
        elapsed_millis(start),
        "error",
        Some(provider.error_code()),
        "provider_error_mapped",
        None,
    ));

    let malformed_input = connector
        .handle_invoke(json!({
            "operation": SEND_MESSAGE_OP,
            "input": {
                "space_name": "spaces/AAAA"
            }
        }))
        .await
        .expect_err("missing text should fail before provider dispatch");
    assert!(matches!(
        malformed_input,
        FcpError::InvalidRequest { code: 1001, .. }
    ));
    logs.push(evidence_log(
        SEND_MESSAGE_OP,
        WRITE_CAP,
        "spaces/error-input",
        None,
        None,
        0,
        "error",
        Some(malformed_input.error_code()),
        "provider_not_called",
        None,
    ));

    let malformed_response_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spaces"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .expect(1)
        .mount(&malformed_response_server)
        .await;
    connector = configured_connector(
        &format!("{}/v1", malformed_response_server.uri()),
        None,
        false,
    )
    .await;
    let start = Instant::now();
    let malformed_response = connector
        .handle_invoke(json!({
            "operation": LIST_SPACES_OP,
            "input": {}
        }))
        .await
        .expect_err("malformed provider JSON should fail");
    assert!(matches!(
        malformed_response,
        FcpError::External {
            ref service,
            retryable: true,
            ..
        } if service == "google_chat"
    ));
    logs.push(evidence_log(
        LIST_SPACES_OP,
        READ_CAP,
        "spaces/error-malformed-provider",
        None,
        None,
        elapsed_millis(start),
        "error",
        Some(malformed_response.error_code()),
        "malformed_provider_shape_mapped",
        None,
    ));

    connector = configured_connector(&unused_loopback_base_url(), None, false).await;
    let start = Instant::now();
    let network = connector
        .handle_invoke(json!({
            "operation": LIST_SPACES_OP,
            "input": {}
        }))
        .await
        .expect_err("closed loopback port should fail");
    assert!(matches!(
        network,
        FcpError::External {
            ref service,
            status_code: None,
            retryable: true,
            ..
        } if service == "google_chat"
    ));
    logs.push(evidence_log(
        LIST_SPACES_OP,
        READ_CAP,
        "spaces/error-network",
        None,
        None,
        elapsed_millis(start),
        "error",
        Some(network.error_code()),
        "network_error_mapped",
        None,
    ));

    let timeout_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/spaces"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(StdDuration::from_millis(50))
                .set_body_json(json!({ "spaces": [] })),
        )
        .expect(1)
        .mount(&timeout_server)
        .await;
    connector = configured_connector(&format!("{}/v1", timeout_server.uri()), Some(1), false).await;
    let start = Instant::now();
    let timeout = connector
        .handle_invoke(json!({
            "operation": LIST_SPACES_OP,
            "input": {}
        }))
        .await
        .expect_err("delayed loopback should hit request timeout");
    assert!(matches!(
        timeout,
        FcpError::External {
            ref service,
            status_code: None,
            retryable: true,
            ..
        } if service == "google_chat"
    ));
    logs.push(evidence_log(
        LIST_SPACES_OP,
        READ_CAP,
        "spaces/error-timeout",
        None,
        None,
        elapsed_millis(start),
        "error",
        Some(timeout.error_code()),
        "timeout_mapped",
        None,
    ));

    assert_log_shape_and_redaction(&logs);
}

#[test]
fn absent_live_google_credentials_emit_structured_skip_artifact() {
    let has_live_env = ["GOOGLE_CHAT_ACCESS_TOKEN", "GOOGLE_CHAT_SPACE_NAME"]
        .iter()
        .all(|name| std::env::var_os(name).is_some());
    if has_live_env {
        return;
    }

    let log = evidence_log(
        "chat.live_verification",
        READ_CAP,
        "live-google-chat-space-not-configured",
        None,
        None,
        0,
        "skipped",
        None,
        "no_live_resources_allocated",
        Some("GOOGLE_CHAT_ACCESS_TOKEN or GOOGLE_CHAT_SPACE_NAME not set"),
    );
    assert_log_shape_and_redaction(&[log]);
}
