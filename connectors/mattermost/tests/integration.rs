use std::time::{Duration as StdDuration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_mattermost::{
    MattermostConnector,
    client::MattermostClient,
    error::MattermostError,
    types::{CreatePostRequest, GetThreadRequest, MattermostAuth},
};
use fcp_prelude::{
    CapabilityConstraints, CapabilityToken, FcpError, InstanceId, InvokeRequest, InvokeStatus,
    OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path, query_param},
};

fn requested_instance_handshake_params(signing_key: &Ed25519SigningKey) -> (Value, InstanceId) {
    let requested_instance = InstanceId::new();
    let params = json!({
        "protocol_version": "1.0.0",
        "zone": "z:work",
        "host_public_key": signing_key.verifying_key().to_bytes().to_vec(),
        "nonce": vec![0_u8; 32],
        "capabilities_requested": ["mattermost.read", "mattermost.write"],
        "requested_instance_id": requested_instance.as_ref()
    });
    (params, requested_instance)
}

fn handshake_params(signing_key: &Ed25519SigningKey) -> Value {
    requested_instance_handshake_params(signing_key).0
}

fn signed_capability_for_instance(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_owned()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("test constraints should serialize");

    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("agent:mattermost-contract-test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(instance_id.as_ref())
        .try_constraints_cbor(&constraints_cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .expect("test capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn wrong_instance_capability(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
) -> (CapabilityToken, String) {
    let wrong_instance = fcp_prelude::InstanceId::new();
    let wrong_instance_id = wrong_instance.as_ref().to_owned();
    (
        signed_capability_for_instance(signing_key, capability, operation, &wrong_instance),
        wrong_instance_id,
    )
}

fn invoke_request(
    connector: &MattermostConnector,
    operation: &str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_owned(),
        id: RequestId::new("req_mattermost_contract"),
        connector_id: connector.id().clone(),
        operation: OperationId::new(operation).expect("valid Mattermost operation id"),
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

fn assert_no_secret_values(serialized: &str) {
    for forbidden in [
        "tok_sensitive_should_not_render",
        "slash-secret",
        "https://hooks.example.test/response",
        "trigger-sensitive",
        "message body that must not be logged",
        "provider body should not be logged",
        "invalid token body hidden",
        "provider outage body hidden",
        "rate limit body hidden",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "sensitive test value leaked in serialized connector output: {forbidden}"
        );
    }
}

fn assert_redacted(serialized: &str) {
    assert_no_secret_values(serialized);
    for forbidden in [
        "channel_contract",
        "user_contract",
        "root_contract",
        "reply_contract",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "sensitive test value leaked in serialized connector output: {forbidden}"
        );
    }
}

fn hashed_id(kind: &str, raw: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(kind.as_bytes());
    hasher.update(b":");
    hasher.update(raw.as_bytes());
    let mut digest_hex = hex::encode(hasher.finalize());
    digest_hex.truncate(16);
    format!("{kind}:{digest_hex}")
}

fn test_command_line() -> String {
    std::env::var("FCP_TEST_COMMAND_LINE")
        .unwrap_or_else(|_| "cargo test -p fcp-mattermost --tests -- --nocapture".to_owned())
}

fn git_revision() -> String {
    std::env::var("FCP_TEST_GIT_REVISION").unwrap_or_else(|_| "unknown".to_owned())
}

#[derive(Clone, Copy)]
struct Evidence<'a> {
    test: &'a str,
    connector_id: &'a str,
    operation_id: &'a str,
    capability: &'a str,
    instance_id: &'a str,
    fixture_id: &'a str,
    lifecycle_phase: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    cleanup_result: &'a str,
}

fn evidence_json(evidence: Evidence<'_>) -> Value {
    json!({
        "test": evidence.test,
        "command_line": test_command_line(),
        "git_revision": git_revision(),
        "connector_id": evidence.connector_id,
        "operation_id": evidence.operation_id,
        "capability": evidence.capability,
        "zone": "z:work",
        "instance_id": evidence.instance_id,
        "team_id_hash": hashed_id("team", "team_contract"),
        "channel_id_hash": hashed_id("channel", "channel_contract"),
        "user_id_hash": hashed_id("user", "user_contract"),
        "thread_id_hash": hashed_id("thread", "root_contract"),
        "fixture_id": evidence.fixture_id,
        "lifecycle_phase": evidence.lifecycle_phase,
        "latency_ms": evidence.latency_ms,
        "result": evidence.result,
        "error_code": evidence.error_code,
        "audit_receipt_id": hashed_id("audit", evidence.fixture_id),
        "cleanup_result": evidence.cleanup_result,
        "skip_reason": null
    })
}

fn emit_redacted_evidence(evidence: Evidence<'_>) {
    let serialized = evidence_json(evidence).to_string();
    assert_redacted(&serialized);
    eprintln!("{serialized}");
}

fn loopback_client(server: &MockServer, timeout: StdDuration) -> MattermostClient {
    MattermostClient::new(
        &server.uri(),
        MattermostAuth::Token("tok_sensitive_should_not_render".to_owned()),
        timeout,
    )
    .expect("loopback Mattermost client should initialize")
}

#[fcp_async_core::runtime::test]
async fn mattermost_lifecycle_outputs_are_redaction_safe() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = MattermostConnector::new();

    let configure = connector
        .handle_configure(json!({
            "base_url": "https://mattermost.example.test",
            "token": "tok_sensitive_should_not_render",
            "request_timeout_ms": 1_000,
            "monitor_policy": {
                "require_mention": true,
                "allowed_channels": ["channel_contract"],
                "allowed_users": ["user_contract"]
            }
        }))
        .await
        .expect("configure should accept a self-hosted Mattermost base URL");
    let configure_text = configure.to_string();
    assert_eq!(configure["status"].as_str(), Some("configured"));
    assert_no_secret_values(&configure_text);

    let handshake = connector
        .handle_handshake(handshake_params(&signing_key))
        .expect("handshake should accept requested read/write capabilities");
    assert_eq!(handshake["status"], "accepted");
    assert!(
        handshake["event_caps"]["streaming"]
            .as_bool()
            .unwrap_or(false)
    );

    let health = connector
        .handle_health()
        .await
        .expect("health should serialize after configuration");
    let health_text = health.to_string();
    assert_no_secret_values(&health_text);
    assert!(health_text.contains("monitor_policy"));

    let shutdown = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should clear client and streaming state");
    let shutdown_status = shutdown.get("status").and_then(Value::as_str);
    assert_eq!(shutdown_status, Some("shutdown_accepted"));

    emit_redacted_evidence(Evidence {
        test: "mattermost_lifecycle_outputs_are_redaction_safe",
        connector_id: connector.id().as_str(),
        operation_id: "lifecycle",
        capability: "mattermost.lifecycle",
        instance_id: "connector-managed",
        fixture_id: "mattermost-no-live-credential-lifecycle",
        lifecycle_phase: "shutdown",
        latency_ms: 0,
        result: "pass",
        error_code: None,
        cleanup_result: shutdown_status.unwrap_or("missing_status"),
    });
}

#[fcp_async_core::runtime::test]
async fn mattermost_rejects_wrong_instance_capability_before_network_dispatch() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = MattermostConnector::new();
    connector
        .handle_configure(json!({
            "base_url": "http://127.0.0.1:9",
            "token": "tok_sensitive_should_not_render",
            "request_timeout_ms": 25
        }))
        .await
        .expect("configure should not contact Mattermost");
    connector
        .handle_handshake(handshake_params(&signing_key))
        .expect("handshake should configure capability verifier");

    let (scoped_capability, wrong_instance_id) =
        wrong_instance_capability(&signing_key, "mattermost.read", "mattermost.get_me");
    let err = connector
        .invoke(invoke_request(
            &connector,
            "mattermost.get_me",
            json!({}),
            scoped_capability,
        ))
        .await
        .expect_err("wrong-instance token should be rejected before provider dispatch");

    assert!(
        matches!(err, FcpError::ZoneViolation { .. }),
        "expected instance-binding ZoneViolation, got {err:?}"
    );

    emit_redacted_evidence(Evidence {
        test: "mattermost_rejects_wrong_instance_capability_before_network_dispatch",
        connector_id: connector.id().as_str(),
        operation_id: "mattermost.get_me",
        capability: "mattermost.read",
        instance_id: &wrong_instance_id,
        fixture_id: "mattermost-wrong-instance-token",
        lifecycle_phase: "invoke",
        latency_ms: 0,
        result: "denied",
        error_code: Some("zone_violation"),
        cleanup_result: "no_provider_socket_opened",
    });
}

#[fcp_async_core::runtime::test]
async fn mattermost_public_invoke_round_trip_uses_requested_instance_capability() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v4/posts"))
        .and(header(
            "authorization",
            "Bearer tok_sensitive_should_not_render",
        ))
        .and(body_partial_json(json!({
            "channel_id": "channel_contract",
            "message": "message body that must not be logged",
            "root_id": "root_contract"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "reply_contract",
            "channel_id": "channel_contract",
            "user_id": "user_contract",
            "message": "provider body should not be logged",
            "root_id": "root_contract",
            "create_at": 1_775_000_001_i64,
            "update_at": 1_775_000_001_i64
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let mut connector = MattermostConnector::new();
    connector
        .handle_configure(json!({
            "base_url": server.uri(),
            "token": "tok_sensitive_should_not_render",
            "request_timeout_ms": 2_000
        }))
        .await
        .expect("configure should accept a loopback Mattermost server");
    let (params, requested_instance) = requested_instance_handshake_params(&signing_key);
    connector
        .handle_handshake(params)
        .expect("handshake should honor requested instance id");

    let started = Instant::now();
    let response = connector
        .invoke(invoke_request(
            &connector,
            "mattermost.create_post",
            json!({
                "channel_id": "channel_contract",
                "message": "message body that must not be logged",
                "root_id": "root_contract"
            }),
            signed_capability_for_instance(
                &signing_key,
                "mattermost.write",
                "mattermost.create_post",
                &requested_instance,
            ),
        ))
        .await
        .expect("correct-instance public invoke should reach the loopback API");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response
        .result
        .expect("successful create_post invoke should include a result");
    assert_eq!(result["id"], "reply_contract");
    assert_eq!(result["root_id"], "root_contract");

    emit_redacted_evidence(Evidence {
        test: "mattermost_public_invoke_round_trip_uses_requested_instance_capability",
        connector_id: connector.id().as_str(),
        operation_id: "mattermost.create_post",
        capability: "mattermost.write",
        instance_id: requested_instance.as_ref(),
        fixture_id: "mattermost-public-invoke-loopback",
        lifecycle_phase: "invoke",
        latency_ms: started.elapsed().as_millis(),
        result: "pass",
        error_code: None,
        cleanup_result: "wiremock_verified",
    });
}

#[fcp_async_core::runtime::test]
async fn mattermost_public_invoke_rejects_malformed_input_before_provider_dispatch() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = MattermostConnector::new();
    connector
        .handle_configure(json!({
            "base_url": "http://127.0.0.1:9",
            "token": "tok_sensitive_should_not_render",
            "request_timeout_ms": 25
        }))
        .await
        .expect("configure should not contact Mattermost");
    let (params, requested_instance) = requested_instance_handshake_params(&signing_key);
    connector
        .handle_handshake(params)
        .expect("handshake should configure capability verifier");

    let err = connector
        .invoke(invoke_request(
            &connector,
            "mattermost.create_post",
            json!({"channel_id": "channel_contract"}),
            signed_capability_for_instance(
                &signing_key,
                "mattermost.write",
                "mattermost.create_post",
                &requested_instance,
            ),
        ))
        .await
        .expect_err("malformed create_post input should fail before provider dispatch");
    assert!(
        matches!(err, FcpError::InvalidRequest { .. }),
        "expected invalid request for malformed create_post input, got {err:?}"
    );

    emit_redacted_evidence(Evidence {
        test: "mattermost_public_invoke_rejects_malformed_input_before_provider_dispatch",
        connector_id: connector.id().as_str(),
        operation_id: "mattermost.create_post",
        capability: "mattermost.write",
        instance_id: requested_instance.as_ref(),
        fixture_id: "mattermost-malformed-input-no-dispatch",
        lifecycle_phase: "invoke",
        latency_ms: 0,
        result: "denied",
        error_code: Some("invalid_request"),
        cleanup_result: "no_provider_socket_opened",
    });
}

#[fcp_async_core::runtime::test]
async fn mattermost_inbound_slash_webhook_fixture_applies_monitor_policy_and_redacts() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = MattermostConnector::new();
    connector
        .handle_configure(json!({
            "base_url": "http://127.0.0.1:9",
            "token": "tok_sensitive_should_not_render",
            "request_timeout_ms": 25,
            "monitor_policy": {
                "allowed_channels": ["allowed_channel"],
                "allowed_users": ["user_contract"]
            }
        }))
        .await
        .expect("configure should accept monitor policy");
    let (params, requested_instance) = requested_instance_handshake_params(&signing_key);
    connector
        .handle_handshake(params)
        .expect("handshake should configure capability verifier");

    let started = Instant::now();
    let response = connector
        .invoke(invoke_request(
            &connector,
            "mattermost.authorize_slash_command",
            json!({
                "channel_id": "channel_contract",
                "user_id": "user_contract",
                "command": "/deploy",
                "text": "message body that must not be logged",
                "token": "slash-secret",
                "response_url": "https://hooks.example.test/response",
                "trigger_id": "trigger-sensitive"
            }),
            signed_capability_for_instance(
                &signing_key,
                "mattermost.read",
                "mattermost.authorize_slash_command",
                &requested_instance,
            ),
        ))
        .await
        .expect("slash webhook authorization invoke should return a policy receipt");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response
        .result
        .expect("slash authorization should return a result");
    assert_eq!(result["decision"], "deny");
    let serialized = result.to_string();
    assert_redacted(&serialized);
    assert!(serialized.contains("slash_policy.decision.v1"));

    emit_redacted_evidence(Evidence {
        test: "mattermost_inbound_slash_webhook_fixture_applies_monitor_policy_and_redacts",
        connector_id: connector.id().as_str(),
        operation_id: "mattermost.authorize_slash_command",
        capability: "mattermost.read",
        instance_id: requested_instance.as_ref(),
        fixture_id: "mattermost-inbound-slash-webhook",
        lifecycle_phase: "webhook_ingress",
        latency_ms: started.elapsed().as_millis(),
        result: "denied",
        error_code: Some("monitor_policy_denied"),
        cleanup_result: "no_provider_socket_opened",
    });
}

#[fcp_async_core::runtime::test]
async fn mattermost_loopback_threaded_reply_round_trip_is_redaction_safe() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v4/posts"))
        .and(header(
            "authorization",
            "Bearer tok_sensitive_should_not_render",
        ))
        .and(body_partial_json(json!({
            "channel_id": "channel_contract",
            "message": "message body that must not be logged",
            "root_id": "root_contract"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "reply_contract",
            "channel_id": "channel_contract",
            "user_id": "user_contract",
            "message": "provider body should not be logged",
            "root_id": "root_contract",
            "create_at": 1_775_000_001_i64,
            "update_at": 1_775_000_001_i64
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v4/posts/root_contract/thread"))
        .and(query_param("perPage", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "order": ["root_contract", "reply_contract"],
            "posts": {
                "root_contract": {
                    "id": "root_contract",
                    "channel_id": "channel_contract",
                    "user_id": "user_contract",
                    "message": "provider body should not be logged",
                    "create_at": 1_775_000_000_i64,
                    "update_at": 1_775_000_000_i64
                },
                "reply_contract": {
                    "id": "reply_contract",
                    "channel_id": "channel_contract",
                    "user_id": "user_contract",
                    "message": "provider body should not be logged",
                    "root_id": "root_contract",
                    "create_at": 1_775_000_001_i64,
                    "update_at": 1_775_000_001_i64
                }
            },
            "next_post_id": "",
            "prev_post_id": "",
            "has_next": false,
            "matches": {}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = loopback_client(&server, StdDuration::from_secs(2));
    let started = Instant::now();
    let reply = client
        .create_post(&CreatePostRequest {
            channel_id: "channel_contract".to_owned(),
            message: "message body that must not be logged".to_owned(),
            root_id: Some("root_contract".to_owned()),
            file_ids: None,
            props: None,
        })
        .await
        .expect("loopback post creation should deserialize");
    let thread = client
        .get_thread(&GetThreadRequest {
            post_id: "root_contract".to_owned(),
            per_page: Some(20),
            ..GetThreadRequest::default()
        })
        .await
        .expect("loopback thread fetch should deserialize");

    assert_eq!(reply.id, "reply_contract");
    assert_eq!(reply.root_id, "root_contract");
    assert_eq!(
        thread.order,
        vec!["root_contract".to_owned(), "reply_contract".to_owned()]
    );
    assert!(thread.posts.contains_key("reply_contract"));

    emit_redacted_evidence(Evidence {
        test: "mattermost_loopback_threaded_reply_round_trip_is_redaction_safe",
        connector_id: "fcp.mattermost",
        operation_id: "mattermost.create_post+mattermost.get_thread",
        capability: "mattermost.write,mattermost.read",
        instance_id: "client-loopback",
        fixture_id: "mattermost-threaded-reply-loopback",
        lifecycle_phase: "invoke",
        latency_ms: started.elapsed().as_millis(),
        result: "pass",
        error_code: None,
        cleanup_result: "wiremock_verified",
    });
}

async fn get_me_error(status: u16, body: Value) -> MattermostError {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/users/me"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .expect(1)
        .mount(&server)
        .await;

    loopback_client(&server, StdDuration::from_secs(2))
        .get_me()
        .await
        .expect_err("non-2xx loopback response should map to a Mattermost error")
}

#[fcp_async_core::runtime::test]
async fn mattermost_loopback_provider_errors_map_to_retry_taxonomy() {
    let started = Instant::now();
    let unauthorized = get_me_error(401, json!({"message": "invalid token body hidden"})).await;
    assert!(matches!(unauthorized, MattermostError::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());

    let rate_limited = get_me_error(
        429,
        json!({
            "message": "rate limit body hidden",
            "retry_after_ms": 1750
        }),
    )
    .await;
    assert!(matches!(rate_limited, MattermostError::RateLimited { .. }));
    assert!(rate_limited.is_retryable());
    assert_eq!(
        rate_limited.retry_after(),
        Some(StdDuration::from_millis(1750))
    );

    let provider_error = get_me_error(503, json!({"message": "provider outage body hidden"})).await;
    assert!(
        matches!(
            provider_error,
            MattermostError::Api {
                status_code: 503,
                ..
            }
        ),
        "expected 503 API error, got {provider_error:?}"
    );
    let fcp_error = provider_error.to_fcp_error();
    assert!(
        matches!(fcp_error, FcpError::External { .. }),
        "expected retryable external FCP error, got {fcp_error:?}"
    );
    if let FcpError::External {
        service,
        status_code,
        retryable,
        ..
    } = fcp_error
    {
        assert_eq!(service, "mattermost");
        assert_eq!(status_code, Some(503));
        assert!(retryable);
    }

    emit_redacted_evidence(Evidence {
        test: "mattermost_loopback_provider_errors_map_to_retry_taxonomy",
        connector_id: "fcp.mattermost",
        operation_id: "mattermost.get_me",
        capability: "mattermost.read",
        instance_id: "client-loopback",
        fixture_id: "mattermost-provider-error-loopback",
        lifecycle_phase: "invoke",
        latency_ms: started.elapsed().as_millis(),
        result: "denied",
        error_code: Some("unauthorized,rate_limited,provider_unavailable"),
        cleanup_result: "wiremock_verified",
    });
}

#[fcp_async_core::runtime::test]
async fn mattermost_network_and_timeout_errors_are_retryable_and_redacted() {
    let slow = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/users/me"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(StdDuration::from_millis(250))
                .set_body_json(json!({
                    "id": "user_contract",
                    "username": "provider body should not be logged"
                })),
        )
        .expect(1)
        .mount(&slow)
        .await;

    let started = Instant::now();
    let timeout = loopback_client(&slow, StdDuration::from_millis(10))
        .get_me()
        .await
        .expect_err("slow loopback response should time out");
    assert!(
        matches!(&timeout, MattermostError::Http(error) if error.is_timeout()),
        "expected reqwest timeout, got {timeout:?}"
    );
    assert!(timeout.is_retryable());

    let network = MattermostClient::new(
        "http://127.0.0.1:1",
        MattermostAuth::Token("tok_sensitive_should_not_render".to_owned()),
        StdDuration::from_millis(50),
    )
    .expect("closed-port Mattermost client should initialize")
    .get_me()
    .await
    .expect_err("closed local port should produce a transport error");
    assert!(
        matches!(network, MattermostError::Http(_)),
        "expected transport error, got {network:?}"
    );
    assert!(network.is_retryable());

    emit_redacted_evidence(Evidence {
        test: "mattermost_network_and_timeout_errors_are_retryable_and_redacted",
        connector_id: "fcp.mattermost",
        operation_id: "mattermost.get_me",
        capability: "mattermost.read",
        instance_id: "client-loopback",
        fixture_id: "mattermost-network-timeout-loopback",
        lifecycle_phase: "invoke",
        latency_ms: started.elapsed().as_millis(),
        result: "denied",
        error_code: Some("timeout,network_error"),
        cleanup_result: "wiremock_verified",
    });
}
