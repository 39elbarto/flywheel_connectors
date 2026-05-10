#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    io::Write,
    net::TcpListener,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::FcpError;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};
use fcp_sdk::{ChatCoordinationBackend, InMemoryThreadOwnershipChecker};
use fcp_tlon::TlonConnector;
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CONNECTOR_ID: &str = "fcp.tlon";
const BEAD_ID: &str = "flywheel_connectors-4kw5f.11.13";
const DM_OPERATION: &str = "tlon.dm.send";
const CHANNEL_OPERATION: &str = "tlon.channel.send";
const RESOLVE_OPERATION: &str = "tlon.target.resolve";
const SHIP_FIXTURE: &str = "~zod";
const CHANNEL_FIXTURE: &str = "/ship/~zod/general";
const MESSAGE_FIXTURE: &str = "body text that must stay out of evidence";
const SESSION_COOKIE: &str = "urbauth-ship=fixture-session";
const CREDENTIAL_ID: &str = "fixture-credential-id";
const EYRE_CHANNEL_PATH: &str = "/~/channel/fcp-tlon";

#[derive(Clone, Copy)]
struct Evidence<'a> {
    test: &'a str,
    operation_id: &'a str,
    capability: &'a str,
    fixture_id: &'a str,
    lifecycle_phase: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    cleanup_result: &'a str,
    skip_reason: Option<&'a str>,
}

fn stable_hash(kind: &str, raw: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in kind.bytes().chain(*b":").chain(raw.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{kind}:{hash:016x}")
}

fn test_command_line() -> String {
    std::env::var("FCP_TEST_COMMAND_LINE")
        .unwrap_or_else(|_| "cargo test -p fcp-tlon --tests -- --nocapture".to_owned())
}

fn git_revision() -> String {
    std::env::var("FCP_TEST_GIT_REVISION").unwrap_or_else(|_| "unknown".to_owned())
}

fn evidence_json(evidence: Evidence<'_>) -> Value {
    json!({
        "schema_version": "1",
        "bead_id": BEAD_ID,
        "test": evidence.test,
        "command_line": test_command_line(),
        "git_revision": git_revision(),
        "connector_id": CONNECTOR_ID,
        "operation_id": evidence.operation_id,
        "capability": evidence.capability,
        "zone": "z:community",
        "instance_id": "loopback-fixture",
        "fixture_id": evidence.fixture_id,
        "ship_hash": stable_hash("ship", SHIP_FIXTURE),
        "group_channel_id_hash": stable_hash("channel", CHANNEL_FIXTURE),
        "lifecycle_phase": evidence.lifecycle_phase,
        "latency_ms": evidence.latency_ms,
        "result": evidence.result,
        "error_code": evidence.error_code,
        "audit_receipt_id": stable_hash("audit", evidence.fixture_id),
        "cleanup_result": evidence.cleanup_result,
        "skip_reason": evidence.skip_reason,
    })
}

fn assert_redacted(serialized: &str) {
    for forbidden in [
        SHIP_FIXTURE,
        CHANNEL_FIXTURE,
        MESSAGE_FIXTURE,
        SESSION_COOKIE,
        CREDENTIAL_ID,
        "/Users/",
        "/private/",
        "provider response body",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "sensitive fixture value leaked in Tlon evidence: {forbidden}"
        );
    }
}

fn emit_redacted_evidence(evidence: Evidence<'_>) {
    let serialized = evidence_json(evidence).to_string();
    assert_redacted(&serialized);
    eprintln!("{serialized}");
}

async fn configured_cookie_connector(base_url: &str) -> TlonConnector {
    let mut connector = TlonConnector::new();
    connector
        .handle_configure(json!({
            "base_url": base_url,
            "session_cookie": SESSION_COOKIE,
            "allow_private_network": true,
            "ship": SHIP_FIXTURE
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:community"
        }))
        .await
        .expect("handshake should succeed");
    connector
}

async fn configured_credential_connector(base_url: &str) -> TlonConnector {
    let mut connector = TlonConnector::new();
    connector
        .handle_configure(json!({
            "base_url": base_url,
            "credential_id": CREDENTIAL_ID,
            "allow_private_network": true,
            "ship": SHIP_FIXTURE
        }))
        .await
        .expect("configure with credential id should succeed");
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:community"
        }))
        .await
        .expect("handshake should succeed");
    connector
}

async fn configured_bound_connector(
    base_url: &str,
    signing_key: &Ed25519SigningKey,
) -> TlonConnector {
    let mut connector = TlonConnector::new();
    connector
        .handle_configure(json!({
            "base_url": base_url,
            "session_cookie": SESSION_COOKIE,
            "allow_private_network": true,
            "ship": SHIP_FIXTURE
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:community",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["tlon.dm", "tlon.channel"],
        }))
        .await
        .expect("bound handshake should succeed");
    connector
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
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor");
    if let Some(instance) = target_instance {
        builder = builder.target_instance(instance);
    }
    CapabilityToken::from_raw(builder.sign(signing_key).expect("sign token"))
}

fn unused_loopback_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused loopback port");
    let addr = listener.local_addr().expect("read unused loopback address");
    drop(listener);
    format!("http://{addr}")
}

fn assert_invalid_request(error: FcpError, expected_code: u16, expected_text: &str) {
    assert!(
        matches!(&error, FcpError::InvalidRequest { .. }),
        "expected InvalidRequest, got {error:?}"
    );
    let FcpError::InvalidRequest { code, message } = error else {
        return;
    };
    assert_eq!(code, expected_code);
    assert!(
        message.contains(expected_text),
        "expected `{message}` to contain `{expected_text}`"
    );
}

fn assert_operation_not_granted(error: &FcpError, operation_id: &str) {
    assert!(
        matches!(&error, FcpError::OperationNotGranted { operation } if operation == operation_id),
        "expected OperationNotGranted for {operation_id}, got {error:?}"
    );
}

fn assert_rate_limited(error: &FcpError, retry_after_ms: u64) {
    assert!(
        matches!(
            &error,
            FcpError::RateLimited {
                retry_after_ms: actual,
                ..
            } if *actual == retry_after_ms
        ),
        "expected RateLimited retry_after_ms={retry_after_ms}, got {error:?}"
    );
}

fn assert_external_status(error: FcpError, status_code: u16) {
    assert!(
        matches!(
            &error,
            FcpError::External {
                service,
                status_code: Some(actual),
                ..
            } if service == "tlon" && *actual == status_code
        ),
        "expected External status {status_code}, got {error:?}"
    );
    let FcpError::External { message, .. } = error else {
        return;
    };
    assert!(
        !message.contains("secret")
            && !message.contains("token")
            && !message.contains(MESSAGE_FIXTURE),
        "provider error message leaked sensitive data: {message}"
    );
}

fn assert_transport_error(error: &FcpError, retryable: bool) {
    assert!(
        matches!(
            &error,
            FcpError::External {
                service,
                status_code: None,
                retryable: actual,
                ..
            } if service == "tlon" && *actual == retryable
        ),
        "expected Tlon transport error retryable={retryable}, got {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_and_shutdown_emit_redacted_jsonl() {
    let started = Instant::now();
    let server = MockServer::start().await;
    let mut connector = TlonConnector::new();

    let health = connector
        .handle_health()
        .await
        .expect("health before configure should succeed");
    assert_eq!(health["status"], "unconfigured");

    connector
        .handle_configure(json!({
            "base_url": server.uri(),
            "session_cookie": SESSION_COOKIE,
            "allow_private_network": true,
            "ship": SHIP_FIXTURE
        }))
        .await
        .expect("configure should succeed");
    let handshake = connector
        .handle_handshake(json!({"protocol_version": "2.0", "zone": "z:community"}))
        .await
        .expect("handshake should succeed");
    assert_eq!(handshake["surface_status"], "implemented");
    assert_eq!(
        handshake["capabilities"],
        json!(["tlon.dm", "tlon.channel"])
    );

    let health = connector
        .handle_health()
        .await
        .expect("health after handshake should succeed");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["live_requests_supported"], true);

    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");
    assert_eq!(doctor["status"], "healthy");
    assert_eq!(doctor["checks"][4]["passed"], true);

    let self_check = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed");
    assert_eq!(self_check["status"], "ok");
    assert_eq!(self_check["reason_code"], "ready");

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    let health = connector
        .handle_health()
        .await
        .expect("health after shutdown should succeed");
    assert_eq!(health["status"], "unconfigured");

    emit_redacted_evidence(Evidence {
        test: "lifecycle_and_shutdown_emit_redacted_jsonl",
        operation_id: "lifecycle",
        capability: "tlon.lifecycle",
        fixture_id: "tlon-loopback-lifecycle",
        lifecycle_phase: "shutdown",
        latency_ms: started.elapsed().as_millis(),
        result: "pass",
        error_code: None,
        cleanup_result: "shutdown_accepted",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn loopback_dm_and_channel_send_emit_redacted_jsonl() {
    let started = Instant::now();
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(EYRE_CHANNEL_PATH))
        .and(header("cookie", SESSION_COOKIE))
        .respond_with(ResponseTemplate::new(204))
        .expect(2)
        .mount(&server)
        .await;

    let connector = configured_cookie_connector(&server.uri()).await;

    let dm_result = connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE}
        }))
        .await
        .expect("DM send should hit loopback Eyre channel");
    assert_eq!(dm_result["ok"], true);
    assert_eq!(dm_result["provider_status"], "accepted");

    let channel_result = connector
        .handle_invoke(json!({
            "operation_id": CHANNEL_OPERATION,
            "input": {"channel": CHANNEL_FIXTURE, "message": MESSAGE_FIXTURE}
        }))
        .await
        .expect("channel send should hit loopback Eyre channel");
    assert_eq!(channel_result["ok"], true);

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 2);
    let dm_body: Value = serde_json::from_slice(&requests[0].body).expect("DM request body JSON");
    let channel_body: Value =
        serde_json::from_slice(&requests[1].body).expect("channel request body JSON");
    assert_eq!(dm_body[0]["id"], 1);
    assert_eq!(dm_body[0]["action"], "poke");
    assert_eq!(dm_body[0]["ship"], "zod");
    assert_eq!(dm_body[0]["mark"], "tlon-dm-action");
    assert_eq!(dm_body[0]["json"]["kind"], "dm.send");
    assert_eq!(dm_body[0]["json"]["ship"], SHIP_FIXTURE);
    assert_eq!(dm_body[0]["json"]["message"], MESSAGE_FIXTURE);
    assert_eq!(channel_body[0]["id"], 2);
    assert_eq!(channel_body[0]["ship"], "zod");
    assert_eq!(channel_body[0]["mark"], "tlon-channel-action");
    assert_eq!(channel_body[0]["json"]["kind"], "channel.send");
    assert_eq!(channel_body[0]["json"]["channel"], CHANNEL_FIXTURE);

    emit_redacted_evidence(Evidence {
        test: "loopback_dm_and_channel_send_emit_redacted_jsonl",
        operation_id: "tlon.send.loopback",
        capability: "tlon.dm+tlon.channel",
        fixture_id: "tlon-loopback-eyre-channel",
        lifecycle_phase: "invoke",
        latency_ms: started.elapsed().as_millis(),
        result: "pass",
        error_code: None,
        cleanup_result: "mock_server_dropped",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn dm_send_claims_conversation_and_denies_duplicate_before_http() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(EYRE_CHANNEL_PATH))
        .and(header("cookie", SESSION_COOKIE))
        .and(body_partial_json(json!([{
            "json": {
                "kind": "dm.send",
                "ship": SHIP_FIXTURE,
                "message": "agent A reply"
            }
        }])))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let config = json!({
        "base_url": server.uri(),
        "session_cookie": SESSION_COOKIE,
        "allow_private_network": true,
        "ship": SHIP_FIXTURE,
        "chat_coordination": { "backend": "in_memory" }
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = TlonConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = TlonConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    first
        .handle_configure(config.clone())
        .await
        .expect("first configure should succeed");
    second
        .handle_configure(config)
        .await
        .expect("second configure should succeed");
    first
        .handle_handshake(json!({"protocol_version": "2.0", "zone": "z:community"}))
        .await
        .expect("first handshake should succeed");
    second
        .handle_handshake(json!({"protocol_version": "2.0", "zone": "z:community"}))
        .await
        .expect("second handshake should succeed");
    let first_instance = first.instance_id().as_str().to_owned();

    let first_result = first
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": "agent A reply"}
        }))
        .await
        .expect("first send should succeed");
    assert_eq!(first_result["ok"], true);
    let coordination = first_result["coordination"]
        .as_array()
        .expect("coordination audit records should be present");
    assert_eq!(coordination[0]["event"], "claim_attempt");
    assert_eq!(coordination[1]["outcome"], "granted");
    assert_eq!(coordination[2]["event"], "send_executed");
    let coordination_text = Value::Array(coordination.clone()).to_string();
    assert!(!coordination_text.contains(SHIP_FIXTURE));
    assert!(!coordination_text.contains("agent A reply"));
    assert!(!coordination_text.contains(&first_instance));

    let second_error = second
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": "agent B reply"}
        }))
        .await
        .expect_err("second send should be denied by duplicate claim");
    match second_error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 4090);
            assert!(message.starts_with("thread_owned_by_peer:"));
            assert!(message.contains(&first_instance));
        }
        other => panic!("expected duplicate claim denial, got {other:?}"),
    }

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(
        requests.len(),
        1,
        "duplicate Tlon claim must not reach the Eyre channel"
    );
}

#[fcp_async_core::runtime::test]
async fn target_resolve_and_validation_denials_are_local() {
    let started = Instant::now();
    let server = MockServer::start().await;
    let connector = configured_cookie_connector(&server.uri()).await;

    for target in [SHIP_FIXTURE, CHANNEL_FIXTURE] {
        let resolved = connector
            .handle_invoke(json!({
                "operation_id": RESOLVE_OPERATION,
                "input": {"target": target}
            }))
            .await
            .expect("target resolution should validate locally");
        assert_eq!(resolved["resolved"], true);
    }

    let bad_channel = connector
        .handle_invoke(json!({
            "operation_id": RESOLVE_OPERATION,
            "input": {"target": "/ship/~zod/../secret"}
        }))
        .await
        .expect_err("path traversal should be denied before provider work");
    assert_invalid_request(bad_channel, 1005, "channel must be an absolute");

    let bad_message = connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": "bad\u{0}message"}
        }))
        .await
        .expect_err("NUL message should be denied before provider work");
    assert_invalid_request(bad_message, 1005, "NUL");

    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        0
    );
    emit_redacted_evidence(Evidence {
        test: "target_resolve_and_validation_denials_are_local",
        operation_id: RESOLVE_OPERATION,
        capability: "tlon.channel",
        fixture_id: "tlon-local-validation",
        lifecycle_phase: "invoke",
        latency_ms: started.elapsed().as_millis(),
        result: "pass",
        error_code: None,
        cleanup_result: "no_provider_socket_opened",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn credential_id_mode_reports_injection_requirement_and_sends_header() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(EYRE_CHANNEL_PATH))
        .and(header("x-fcp-credential-id", CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_credential_connector(&server.uri()).await;
    let self_check = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed");
    assert_eq!(self_check["status"], "degraded");
    assert_eq!(self_check["reason_code"], "credential_injection_required");

    let result = connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE}
        }))
        .await
        .expect("credential id mode should pass the host credential reference header");
    assert_eq!(result["ok"], true);
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        1
    );
}

#[fcp_async_core::runtime::test]
async fn provider_error_mapping_is_redacted_and_retry_aware() {
    let retry_server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(EYRE_CHANNEL_PATH))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_string("secret token message body"),
        )
        .expect(1)
        .mount(&retry_server)
        .await;
    let retry_connector = configured_cookie_connector(&retry_server.uri()).await;
    let retry_error = retry_connector
        .handle_invoke(json!({
            "operation_id": CHANNEL_OPERATION,
            "input": {"channel": CHANNEL_FIXTURE, "message": MESSAGE_FIXTURE}
        }))
        .await
        .expect_err("429 should map to FCP rate limit");
    assert_rate_limited(&retry_error, 2_000);

    let auth_server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(EYRE_CHANNEL_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_string("secret token message body"))
        .expect(1)
        .mount(&auth_server)
        .await;
    let auth_connector = configured_cookie_connector(&auth_server.uri()).await;
    let auth_error = auth_connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE}
        }))
        .await
        .expect_err("401 should map to a redacted external auth error");
    assert_external_status(auth_error, 401);

    let network_connector = configured_cookie_connector(&unused_loopback_base_url()).await;
    let network_error = network_connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE}
        }))
        .await
        .expect_err("closed loopback port should map to retryable transport error");
    assert_transport_error(&network_error, true);

    let timeout_server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(EYRE_CHANNEL_PATH))
        .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_millis(1_200)))
        .expect(1)
        .mount(&timeout_server)
        .await;
    let mut timeout_connector = TlonConnector::new();
    timeout_connector
        .handle_configure(json!({
            "base_url": timeout_server.uri(),
            "session_cookie": SESSION_COOKIE,
            "allow_private_network": true,
            "ship": SHIP_FIXTURE,
            "timeout_ms": 1000
        }))
        .await
        .expect("timeout configure should succeed");
    timeout_connector
        .handle_handshake(json!({"protocol_version": "2.0", "zone": "z:community"}))
        .await
        .expect("timeout handshake should succeed");
    let timeout_error = timeout_connector
        .handle_invoke(json!({
            "operation_id": CHANNEL_OPERATION,
            "input": {"channel": CHANNEL_FIXTURE, "message": MESSAGE_FIXTURE}
        }))
        .await
        .expect_err("slow provider should map to retryable timeout transport error");
    assert_transport_error(&timeout_error, true);
}

#[fcp_async_core::runtime::test]
async fn malformed_unknown_and_pre_handshake_requests_are_denied() {
    let unready = TlonConnector::new();
    let not_configured = unready
        .handle_invoke(json!({"operation_id": DM_OPERATION}))
        .await
        .expect_err("invoke before configure should fail readiness");
    assert!(matches!(not_configured, FcpError::NotConfigured));

    let mut unhandshaken = TlonConnector::new();
    unhandshaken
        .handle_configure(json!({
            "base_url": "https://fixture.tlon.example",
            "session_cookie": SESSION_COOKIE,
            "ship": SHIP_FIXTURE
        }))
        .await
        .expect("configure should succeed");
    let not_handshaken = unhandshaken
        .handle_invoke(json!({"operation_id": DM_OPERATION}))
        .await
        .expect_err("invoke before handshake should fail readiness");
    assert!(matches!(not_handshaken, FcpError::NotHandshaken));

    let server = MockServer::start().await;
    let connector = configured_cookie_connector(&server.uri()).await;

    let missing_operation = connector
        .handle_invoke(json!({"input": {"ship": SHIP_FIXTURE}}))
        .await
        .expect_err("missing operation id should be rejected");
    assert_invalid_request(missing_operation, 1003, "Missing operation_id");

    let unknown_operation = connector
        .handle_invoke(json!({"operation_id": "tlon.unexpected.operation"}))
        .await
        .expect_err("unknown operation should be rejected");
    assert_operation_not_granted(&unknown_operation, "tlon.unexpected.operation");

    let simulate = connector
        .handle_simulate(json!({"operation_id": "tlon.unexpected.operation"}))
        .await
        .expect("simulate should succeed");
    assert_eq!(simulate["allowed"], false);
    assert_eq!(simulate["reason"], "Unknown operation.");

    emit_redacted_evidence(Evidence {
        test: "malformed_unknown_and_pre_handshake_requests_are_denied",
        operation_id: "tlon.unexpected.operation",
        capability: "tlon.none",
        fixture_id: "tlon-denial-fixture",
        lifecycle_phase: "invoke",
        latency_ms: 0,
        result: "denied",
        error_code: Some("invalid_request"),
        cleanup_result: "no_provider_socket_opened",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn bound_handshake_requires_valid_zone_and_instance_capability_tokens() {
    let started = Instant::now();
    let server = MockServer::start().await;
    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_bound_connector(&server.uri(), &signing_key).await;

    let missing_token = connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE}
        }))
        .await
        .expect_err("bound handshakes must require capability_token");
    assert_invalid_request(missing_token, 1003, "Missing capability_token");

    let wrong_zone_token = capability_token(
        &signing_key,
        "tlon.dm",
        DM_OPERATION,
        "z:work",
        Some("wrong-instance"),
    );
    let wrong_zone = connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE},
            "capability_token": wrong_zone_token
        }))
        .await
        .expect_err("token for the wrong zone should fail before provider I/O");
    assert!(
        matches!(wrong_zone, FcpError::ZoneViolation { .. }),
        "expected wrong-zone capability denial, got {wrong_zone:?}"
    );

    let wrong_instance_token = capability_token(
        &signing_key,
        "tlon.dm",
        DM_OPERATION,
        "z:community",
        Some("wrong-instance"),
    );
    let wrong_instance = connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": {"ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE},
            "capability_token": wrong_instance_token
        }))
        .await
        .expect_err("token for the wrong connector instance should fail before provider I/O");
    assert!(
        matches!(
            &wrong_instance,
            FcpError::ZoneViolation { message, .. } if message.contains("Token instance mismatch")
        ),
        "expected wrong-instance capability denial, got {wrong_instance:?}"
    );

    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        0,
        "capability denials must not reach the Tlon provider"
    );
    emit_redacted_evidence(Evidence {
        test: "bound_handshake_requires_valid_zone_and_instance_capability_tokens",
        operation_id: DM_OPERATION,
        capability: "tlon.dm",
        fixture_id: "tlon-capability-denial-fixture",
        lifecycle_phase: "capability_check",
        latency_ms: started.elapsed().as_millis(),
        result: "denied",
        error_code: Some("capability_token_denied"),
        cleanup_result: "no_provider_socket_opened",
        skip_reason: None,
    });
}

#[test]
fn jsonrpc_process_handles_invalid_json_lifecycle_and_shutdown() {
    let executable =
        std::env::var("CARGO_BIN_EXE_fcp-tlon").expect("cargo should expose fcp-tlon test binary");
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fcp-tlon process");

    {
        let mut stdin = child.stdin.take().expect("child stdin should be piped");
        writeln!(stdin, "{{not-json").expect("write invalid JSON request");
        writeln!(
            stdin,
            "{}",
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "configure",
                "params": {
                    "base_url": "https://fixture.tlon.example",
                    "session_cookie": SESSION_COOKIE,
                    "ship": SHIP_FIXTURE
                }
            })
        )
        .expect("write configure request");
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 2, "method": "handshake", "params": {}})
        )
        .expect("write handshake request");
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}})
        )
        .expect("write shutdown request");
    }

    let output = child
        .wait_with_output()
        .expect("fcp-tlon process should exit after stdin closes");
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert_redacted(&stdout);
    let responses = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("response should be JSON"))
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 4);
    assert_eq!(responses[0]["error"]["code"], "FCP-1001");
    assert_eq!(responses[1]["id"], 1);
    assert_eq!(responses[1]["result"]["configured"], true);
    assert_eq!(responses[2]["id"], 2);
    assert_eq!(responses[2]["result"]["surface_status"], "implemented");
    assert_eq!(responses[3]["id"], 3);
    assert_eq!(responses[3]["result"], json!({}));

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert_redacted(&stderr);
}
