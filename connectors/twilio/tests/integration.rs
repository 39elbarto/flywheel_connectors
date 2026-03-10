//! Twilio connector integration tests (flywheel_connectors-otqy.3).
//!
//! Deterministic integration tests using wiremock to mock the Twilio REST API.
//! No real API calls. Covers:
//! - Messaging (send, get, list)
//! - Voice (create call, get call)
//! - Recordings (list, download)
//! - Media download
//! - Account and phone numbers
//! - Error taxonomy (401/404/429/500 → `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path_regex},
};

use fcp_twilio::client::TwilioClient;
use fcp_twilio::connector::TwilioConnector;

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[cap])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken { raw: cose }
}

async fn setup_handshake(connector: &mut TwilioConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

/// Account SID used in integration tests.
const TEST_ACCOUNT_SID: &str = "ACtest123456789";

async fn setup_configure(connector: &mut TwilioConnector, base_url: &str) {
    let full_base = format!("{base_url}/2010-04-01/Accounts/{TEST_ACCOUNT_SID}");
    connector
        .handle_configure(json!({
            "account_sid": TEST_ACCOUNT_SID,
            "auth_token": "test_auth_token_xyz",
            "base_url": full_base
        }))
        .await
        .expect("configure should succeed");
}

/// Standard Twilio message response.
fn twilio_message_response(sid: &str, status: &str) -> serde_json::Value {
    json!({
        "sid": sid,
        "status": status,
        "to": "+15551234567",
        "from": "+15559876543",
        "body": "Hello from FCP!",
        "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
        "date_updated": "Wed, 15 Jan 2026 10:00:01 +0000",
        "date_sent": "Wed, 15 Jan 2026 10:00:01 +0000",
        "price": "-0.0075",
        "price_unit": "USD",
        "num_media": "0",
        "num_segments": "1",
        "direction": "outbound-api",
        "uri": format!("/2010-04-01/Accounts/ACtest/Messages/{sid}.json")
    })
}

/// Standard Twilio call response.
fn twilio_call_response(sid: &str, status: &str) -> serde_json::Value {
    json!({
        "sid": sid,
        "status": status,
        "to": "+15551234567",
        "from": "+15559876543",
        "duration": "30",
        "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
        "date_updated": "Wed, 15 Jan 2026 10:00:30 +0000",
        "start_time": "Wed, 15 Jan 2026 10:00:00 +0000",
        "end_time": "Wed, 15 Jan 2026 10:00:30 +0000",
        "price": "-0.0085",
        "price_unit": "USD",
        "direction": "outbound-api",
        "uri": format!("/2010-04-01/Accounts/ACtest/Calls/{sid}.json")
    })
}

/// Twilio API error response.
fn twilio_error_response(code: u32, message: &str) -> serde_json::Value {
    json!({
        "code": code,
        "message": message,
        "status": 400,
        "more_info": "https://www.twilio.com/docs/errors"
    })
}

// ============================================================================
// Messaging Tests
// ============================================================================

/// Send SMS happy path.
#[fcp_async_core::runtime::test]
async fn send_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.send_message.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/Accounts/.*/Messages\\.json"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(twilio_message_response("SMtest001", "queued")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.send_message"]).await;
    let token = generate_valid_token(&signing_key, "twilio.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.send_message",
            "input": {
                "to": "+15551234567",
                "from": "+15559876543",
                "body": "Hello from FCP!"
            },
            "capability_token": token
        }))
        .await
        .expect("send_message should succeed");

    assert_eq!(result["sid"], "SMtest001");
    assert_eq!(result["status"], "queued");
}

/// Get message details.
#[fcp_async_core::runtime::test]
async fn get_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.get_message.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/SMtest001\\.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(twilio_message_response("SMtest001", "delivered")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_message"]).await;
    let token = generate_valid_token(&signing_key, "twilio.get_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" },
            "capability_token": token
        }))
        .await
        .expect("get_message should succeed");

    assert_eq!(result["sid"], "SMtest001");
    assert_eq!(result["status"], "delivered");
}

/// List messages with pagination.
#[fcp_async_core::runtime::test]
async fn list_messages_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_messages.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                twilio_message_response("SMtest001", "delivered"),
                twilio_message_response("SMtest002", "sent")
            ],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_messages"]).await;
    let token = generate_valid_token(&signing_key, "twilio.list_messages");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_messages",
            "input": { "page_size": 20 },
            "capability_token": token
        }))
        .await
        .expect("list_messages should succeed");

    assert_eq!(result["messages"].as_array().unwrap().len(), 2);
}

// ============================================================================
// Voice Tests
// ============================================================================

/// Create outbound call.
#[fcp_async_core::runtime::test]
async fn create_call_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.create_call.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/Accounts/.*/Calls\\.json"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(twilio_call_response("CAtest001", "queued")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.create_call"]).await;
    let token = generate_valid_token(&signing_key, "twilio.create_call");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.create_call",
            "input": {
                "to": "+15551234567",
                "from": "+15559876543",
                "url": "https://example.com/twiml"
            },
            "capability_token": token
        }))
        .await
        .expect("create_call should succeed");

    assert_eq!(result["sid"], "CAtest001");
    assert_eq!(result["status"], "queued");
}

/// Get call details.
#[fcp_async_core::runtime::test]
async fn get_call_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.get_call.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Calls/CAtest001\\.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(twilio_call_response("CAtest001", "completed")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_call"]).await;
    let token = generate_valid_token(&signing_key, "twilio.get_call");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.get_call",
            "input": { "call_sid": "CAtest001" },
            "capability_token": token
        }))
        .await
        .expect("get_call should succeed");

    assert_eq!(result["sid"], "CAtest001");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["duration"], "30");
}

// ============================================================================
// Recordings Tests
// ============================================================================

/// List recordings.
#[fcp_async_core::runtime::test]
async fn list_recordings_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_recordings.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Recordings\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "recordings": [{
                "sid": "REtest001",
                "call_sid": "CAtest001",
                "duration": "30",
                "status": "completed",
                "date_created": "Wed, 15 Jan 2026 10:00:00 +0000"
            }],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_recordings"]).await;
    let token = generate_valid_token(&signing_key, "twilio.list_recordings");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_recordings",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("list_recordings should succeed");

    assert_eq!(result["recordings"].as_array().unwrap().len(), 1);
}

/// Get account info.
#[fcp_async_core::runtime::test]
async fn get_account_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.get_account.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/ACtest.*\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sid": "ACtest123456789",
            "friendly_name": "Test Account",
            "status": "active",
            "type": "Full",
            "date_created": "Wed, 01 Jan 2025 00:00:00 +0000"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_account"]).await;
    let token = generate_valid_token(&signing_key, "twilio.get_account");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.get_account",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("get_account should succeed");

    assert_eq!(result["sid"], "ACtest123456789");
    assert_eq!(result["status"], "active");
}

/// List phone numbers.
#[fcp_async_core::runtime::test]
async fn list_phone_numbers_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_phone_numbers.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/IncomingPhoneNumbers\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "incoming_phone_numbers": [{
                "sid": "PNtest001",
                "phone_number": "+15559876543",
                "friendly_name": "Main Number",
                "capabilities": { "sms": true, "mms": true, "voice": true, "fax": false }
            }],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_phone_numbers"]).await;
    let token = generate_valid_token(&signing_key, "twilio.list_phone_numbers");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_phone_numbers",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("list_phone_numbers should succeed");

    assert_eq!(
        result["incoming_phone_numbers"].as_array().unwrap().len(),
        1
    );
}

// ============================================================================
// Error Taxonomy Tests (401/404/429/500 → `FcpError` mapping)
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("twilio.error.401");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(twilio_error_response(20003, "Authenticate")),
        )
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "bad-token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(0);

    let err = client
        .get_message("SMtest001")
        .await
        .expect_err("should fail with 401");

    assert!(
        matches!(err, fcp_twilio::error::TwilioError::Unauthorized),
        "expected Unauthorized, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "expected FcpError::Unauthorized, got: {fcp_err:?}"
    );
}

/// 404 Not Found maps to `FcpError::ResourceNotFound`.
#[fcp_async_core::runtime::test]
async fn error_404_maps_to_not_found() {
    let _ctx = AsyncTestContext::for_scenario("twilio.error.404");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(twilio_error_response(
                20404,
                "The requested resource was not found",
            )),
        )
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(0);

    let err = client
        .get_message("SMnonexistent")
        .await
        .expect_err("should fail with 404");

    assert!(
        matches!(err, fcp_twilio::error::TwilioError::NotFound { .. }),
        "expected NotFound, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "expected FcpError::ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("twilio.error.429");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(twilio_error_response(20429, "Too Many Requests"))
                .insert_header("retry-after", "30"),
        )
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(0);

    let err = client
        .get_message("SMtest001")
        .await
        .expect_err("should fail with 429");

    assert!(
        matches!(err, fcp_twilio::error::TwilioError::RateLimited { .. }),
        "expected RateLimited, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "expected FcpError::RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error maps to `FcpError::External` with retryable=true.
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external() {
    let _ctx = AsyncTestContext::for_scenario("twilio.error.500");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(twilio_error_response(20500, "Internal server error")),
        )
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(0);

    let err = client
        .get_message("SMtest001")
        .await
        .expect_err("should fail with 500");

    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            service,
            retryable,
            status_code,
            ..
        } => {
            assert_eq!(service, "twilio");
            assert!(retryable, "500 should be retryable");
            assert_eq!(*status_code, Some(500));
        }
        other => panic!("expected FcpError::External, got: {other:?}"),
    }
}

/// Error `is_retryable` classification is correct.
#[test]
fn error_retryable_classification() {
    use fcp_twilio::error::TwilioError;

    assert!(
        TwilioError::RateLimited {
            retry_after_ms: 1000
        }
        .is_retryable()
    );
    assert!(
        TwilioError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_code: None,
        }
        .is_retryable()
    );
    assert!(
        TwilioError::Api {
            message: "Service unavailable".into(),
            status_code: Some(503),
            error_code: None,
        }
        .is_retryable()
    );

    assert!(!TwilioError::Unauthorized.is_retryable());
    assert!(
        !TwilioError::NotFound {
            resource: "test".into()
        }
        .is_retryable()
    );
    assert!(
        !TwilioError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
            error_code: None,
        }
        .is_retryable()
    );
}

// ============================================================================
// FCP2 Default-Deny / Capability Verification Tests
// ============================================================================

/// Invoke without `capability_token` fails.
#[fcp_async_core::runtime::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("twilio.capability.missing_token");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    setup_handshake(&mut connector, &["twilio.get_message"]).await;

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" }
        }))
        .await
        .expect_err("invoke without token should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing token, got: {err:?}"
    );
}

/// Invoke before handshake fails (no verifier).
#[fcp_async_core::runtime::test]
async fn capability_no_handshake_fails() {
    let _ctx = AsyncTestContext::for_scenario("twilio.capability.no_handshake");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, "twilio.get_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without handshake should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Invoke before configure fails (no client).
#[fcp_async_core::runtime::test]
async fn capability_no_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("twilio.capability.no_configure");

    let mut connector = TwilioConnector::new();
    let signing_key = setup_handshake(&mut connector, &["twilio.get_message"]).await;
    let token = generate_valid_token(&signing_key, "twilio.get_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without configure should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Token signed for wrong operation fails.
#[fcp_async_core::runtime::test]
async fn capability_wrong_operation_fails() {
    let _ctx = AsyncTestContext::for_scenario("twilio.capability.wrong_op");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(
        &mut connector,
        &["twilio.get_message", "twilio.send_message"],
    )
    .await;

    let wrong_token = generate_valid_token(&signing_key, "twilio.send_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" },
            "capability_token": wrong_token
        }))
        .await
        .expect_err("wrong capability should fail");

    let is_cap_error = matches!(
        &err,
        fcp_core::FcpError::CapabilityDenied { .. }
            | fcp_core::FcpError::Unauthorized { .. }
            | fcp_core::FcpError::OperationNotGranted { .. }
    );
    assert!(
        is_cap_error,
        "expected capability/operation denial, got: {err:?}"
    );
}

/// Unknown operation fails with `OperationNotGranted`.
#[fcp_async_core::runtime::test]
async fn capability_unknown_operation_fails() {
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "twilio.nonexistent");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("unknown operation should fail");

    assert!(
        matches!(err, fcp_core::FcpError::OperationNotGranted { .. }),
        "expected OperationNotGranted, got: {err:?}"
    );
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health check before configure reports `not_configured`.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let connector = TwilioConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

/// Health check after configure reports healthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

/// Handshake returns accepted with capabilities granted.
#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mut connector = TwilioConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["twilio.read", "twilio.message", "twilio.voice"]
        }))
        .await
        .expect("handshake should succeed");

    assert_eq!(result["status"], "accepted");
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

/// Shutdown returns clean status.
#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_clean() {
    let connector = TwilioConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

/// Introspect exposes all 10 operations with schemas.
#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_all_operations() {
    let connector = TwilioConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    let expected_ops = [
        "twilio.send_message",
        "twilio.get_message",
        "twilio.list_messages",
        "twilio.list_media",
        "twilio.get_media",
        "twilio.create_call",
        "twilio.get_call",
        "twilio.hangup_call",
        "twilio.list_calls",
        "twilio.generate_twiml",
        "twilio.list_recordings",
        "twilio.download_recording",
        "twilio.download_media",
        "twilio.get_account",
        "twilio.list_phone_numbers",
        "twilio.whatsapp_send",
        "twilio.whatsapp_send_template",
        "twilio.whatsapp_get",
        "twilio.whatsapp_list",
        // Conversations API
        "twilio.conversation.create",
        "twilio.conversation.get",
        "twilio.conversation.list",
        "twilio.conversation.participant.add",
        "twilio.conversation.participant.remove",
        "twilio.conversation.message.send",
        "twilio.conversation.message.list",
        // Verify API
        "twilio.verify.send",
        "twilio.verify.check",
        "twilio.verify.cancel",
        // Video API
        "twilio.video.room.create",
        "twilio.video.room.get",
        "twilio.video.room.list",
        "twilio.video.room.end",
        "twilio.video.room.participants",
        "twilio.video.recording.list",
        // Webhook handling
        "twilio.webhook.validate_signature",
        "twilio.webhook.parse_sms_event",
        "twilio.webhook.parse_status_callback",
        "twilio.webhook.parse_voice_event",
    ];

    for expected in &expected_ops {
        assert!(op_ids.contains(expected), "missing operation: {expected}");
    }
    assert_eq!(ops.len(), 39);

    for op in ops {
        assert!(
            op["input_schema"].is_object(),
            "input_schema should be object for {}",
            op["id"]
        );
        assert!(
            op["output_schema"].is_object(),
            "output_schema should be object for {}",
            op["id"]
        );
    }
}

// ============================================================================
// Input Validation Edge Cases
// ============================================================================

/// Missing `to` in `send_message` fails.
#[fcp_async_core::runtime::test]
async fn validation_send_message_missing_to() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.send_message"]).await;
    let token = generate_valid_token(&signing_key, "twilio.send_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.send_message",
            "input": { "from": "+15559876543", "body": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("missing 'to' should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("to"),
                "error should mention 'to': {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `body` in `send_message` fails.
#[fcp_async_core::runtime::test]
async fn validation_send_message_missing_body() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.send_message"]).await;
    let token = generate_valid_token(&signing_key, "twilio.send_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.send_message",
            "input": { "to": "+15551234567", "from": "+15559876543" },
            "capability_token": token
        }))
        .await
        .expect_err("missing 'body' should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("body"),
                "error should mention 'body': {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `message_sid` in `get_message` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_message_missing_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_message"]).await;
    let token = generate_valid_token(&signing_key, "twilio.get_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing message_sid should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("message_sid"),
                "error should mention message_sid: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `call_sid` in `get_call` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_call_missing_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_call"]).await;
    let token = generate_valid_token(&signing_key, "twilio.get_call");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_call",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing call_sid should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("call_sid"),
                "error should mention call_sid: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `url` in `create_call` fails.
#[fcp_async_core::runtime::test]
async fn validation_create_call_missing_url() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.create_call"]).await;
    let token = generate_valid_token(&signing_key, "twilio.create_call");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.create_call",
            "input": { "to": "+15551234567", "from": "+15559876543" },
            "capability_token": token
        }))
        .await
        .expect_err("missing url should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("url"),
                "error should mention url: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

// ============================================================================
// SMS Media Tests
// ============================================================================

/// List media attachments for a message.
#[fcp_async_core::runtime::test]
async fn list_media_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_media.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/SMtest001/Media\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "media_list": [
                {
                    "sid": "MEtest001",
                    "account_sid": "ACtest123456789",
                    "parent_sid": "SMtest001",
                    "content_type": "image/jpeg",
                    "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
                    "date_updated": "Wed, 15 Jan 2026 10:00:01 +0000",
                    "uri": "/2010-04-01/Accounts/ACtest/Messages/SMtest001/Media/MEtest001.json"
                },
                {
                    "sid": "MEtest002",
                    "account_sid": "ACtest123456789",
                    "parent_sid": "SMtest001",
                    "content_type": "image/png",
                    "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
                    "date_updated": "Wed, 15 Jan 2026 10:00:01 +0000",
                    "uri": "/2010-04-01/Accounts/ACtest/Messages/SMtest001/Media/MEtest002.json"
                }
            ],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_media"]).await;
    let token = generate_valid_token(&signing_key, "twilio.list_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_media",
            "input": { "message_sid": "SMtest001" },
            "capability_token": token
        }))
        .await
        .expect("list_media should succeed");

    assert_eq!(result["media_list"].as_array().unwrap().len(), 2);
    assert!(result["next_page_uri"].is_null());
}

/// Get a specific media resource.
#[fcp_async_core::runtime::test]
async fn get_media_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.get_media.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(
            "/Accounts/.*/Messages/SMtest001/Media/MEtest001\\.json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sid": "MEtest001",
            "account_sid": "ACtest123456789",
            "parent_sid": "SMtest001",
            "content_type": "image/jpeg",
            "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
            "date_updated": "Wed, 15 Jan 2026 10:00:01 +0000",
            "uri": "/2010-04-01/Accounts/ACtest/Messages/SMtest001/Media/MEtest001.json"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_media"]).await;
    let token = generate_valid_token(&signing_key, "twilio.get_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.get_media",
            "input": { "message_sid": "SMtest001", "media_sid": "MEtest001" },
            "capability_token": token
        }))
        .await
        .expect("get_media should succeed");

    assert_eq!(result["sid"], "MEtest001");
    assert_eq!(result["content_type"], "image/jpeg");
    assert_eq!(result["parent_sid"], "SMtest001");
}

/// List media with empty result.
#[fcp_async_core::runtime::test]
async fn list_media_empty_result() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_media.empty");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*/Media\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "media_list": [],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_media"]).await;
    let token = generate_valid_token(&signing_key, "twilio.list_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_media",
            "input": { "message_sid": "SMtest999" },
            "capability_token": token
        }))
        .await
        .expect("list_media with empty result should succeed");

    assert_eq!(result["media_list"].as_array().unwrap().len(), 0);
}

/// Missing `message_sid` in `list_media` fails.
#[fcp_async_core::runtime::test]
async fn validation_list_media_missing_message_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_media"]).await;
    let token = generate_valid_token(&signing_key, "twilio.list_media");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.list_media",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing message_sid should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("message_sid"),
                "error should mention message_sid: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `media_sid` in `get_media` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_media_missing_media_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_media"]).await;
    let token = generate_valid_token(&signing_key, "twilio.get_media");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_media",
            "input": { "message_sid": "SMtest001" },
            "capability_token": token
        }))
        .await
        .expect_err("missing media_sid should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("media_sid"),
                "error should mention media_sid: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `recording_sid` in `download_recording` fails.
#[fcp_async_core::runtime::test]
async fn validation_download_recording_missing_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.download_recording"]).await;
    let token = generate_valid_token(&signing_key, "twilio.download_recording");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.download_recording",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing recording_sid should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("recording_sid"),
                "error should mention recording_sid: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

// ============================================================================
// Webhook Handling Tests
// ============================================================================

/// Parse SMS webhook event — happy path.
#[fcp_async_core::runtime::test]
async fn webhook_parse_sms_event_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_sms_event.happy_path");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_sms_event"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_sms_event");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_sms_event",
            "input": {
                "body": {
                    "MessageSid": "SM1234567890abcdef1234567890abcdef",
                    "From": "+15551234567",
                    "To": "+15559876543",
                    "Body": "Hello from webhook!",
                    "NumMedia": "2",
                    "AccountSid": "ACtest123456789",
                    "SmsSid": "SM1234567890abcdef1234567890abcdef",
                    "NumSegments": "1"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("parse_sms_event should succeed");

    assert_eq!(result["event_type"], "sms.inbound");
    assert_eq!(result["message_sid"], "SM1234567890abcdef1234567890abcdef");
    assert_eq!(result["from"], "+15551234567");
    assert_eq!(result["to"], "+15559876543");
    assert_eq!(result["body"], "Hello from webhook!");
    assert_eq!(result["num_media"], 2);
    assert_eq!(result["account_sid"], "ACtest123456789");
    assert_eq!(result["tainted"], true);
    assert_eq!(result["event_id"], "evt_SM1234567890abcdef1234567890abcdef");
}

/// Parse SMS webhook event — missing required `MessageSid`.
#[fcp_async_core::runtime::test]
async fn webhook_parse_sms_event_missing_message_sid() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_sms_event.missing_message_sid");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_sms_event"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_sms_event");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_sms_event",
            "input": {
                "body": {
                    "From": "+15551234567",
                    "To": "+15559876543"
                }
            },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without MessageSid");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("MessageSid"),
                "error should mention MessageSid: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Parse SMS webhook event — minimal fields (no optional fields).
#[fcp_async_core::runtime::test]
async fn webhook_parse_sms_event_minimal() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_sms_event.minimal");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_sms_event"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_sms_event");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_sms_event",
            "input": {
                "body": {
                    "MessageSid": "SMminimal",
                    "From": "+15550001111",
                    "To": "+15552223333"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("parse_sms_event should succeed with minimal fields");

    assert_eq!(result["event_type"], "sms.inbound");
    assert_eq!(result["message_sid"], "SMminimal");
    assert!(result["body"].is_null());
    assert!(result["num_media"].is_null());
    assert_eq!(result["tainted"], true);
}

/// Parse status callback — message delivered.
#[fcp_async_core::runtime::test]
async fn webhook_parse_status_callback_message_delivered() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.parse_status_callback.message_delivered");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.parse_status_callback"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_status_callback");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_status_callback",
            "input": {
                "body": {
                    "MessageSid": "SM9876543210",
                    "MessageStatus": "delivered",
                    "Timestamp": "2026-01-15T10:00:00Z"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("parse_status_callback should succeed");

    assert_eq!(result["event_type"], "message.status");
    assert_eq!(result["resource_sid"], "SM9876543210");
    assert_eq!(result["resource_type"], "message");
    assert_eq!(result["status"], "delivered");
    assert_eq!(result["timestamp"], "2026-01-15T10:00:00Z");
    assert_eq!(result["tainted"], true);
}

/// Parse status callback — call completed.
#[fcp_async_core::runtime::test]
async fn webhook_parse_status_callback_call_completed() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.parse_status_callback.call_completed");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.parse_status_callback"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_status_callback");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_status_callback",
            "input": {
                "body": {
                    "CallSid": "CA1234567890",
                    "CallStatus": "completed"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("parse_status_callback for call should succeed");

    assert_eq!(result["event_type"], "call.status");
    assert_eq!(result["resource_sid"], "CA1234567890");
    assert_eq!(result["resource_type"], "call");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["tainted"], true);
}

/// Parse status callback — message failed with error code.
#[fcp_async_core::runtime::test]
async fn webhook_parse_status_callback_with_error() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_status_callback.with_error");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.parse_status_callback"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_status_callback");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_status_callback",
            "input": {
                "body": {
                    "MessageSid": "SMfailed001",
                    "MessageStatus": "failed",
                    "ErrorCode": "30006",
                    "ErrorMessage": "Landline or unreachable carrier"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("parse_status_callback with error should succeed");

    assert_eq!(result["status"], "failed");
    assert_eq!(result["error_code"], "30006");
    assert_eq!(result["error_message"], "Landline or unreachable carrier");
}

/// Parse status callback — missing both `MessageSid` and `CallSid`.
#[fcp_async_core::runtime::test]
async fn webhook_parse_status_callback_missing_sid() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_status_callback.missing_sid");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.parse_status_callback"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_status_callback");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_status_callback",
            "input": {
                "body": {
                    "SomeOtherField": "value"
                }
            },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without MessageSid or CallSid");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("MessageSid") || message.contains("CallSid"),
                "error should mention SID: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Parse voice webhook event — happy path.
#[fcp_async_core::runtime::test]
async fn webhook_parse_voice_event_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_voice_event.happy_path");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_voice_event"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_voice_event");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_voice_event",
            "input": {
                "body": {
                    "CallSid": "CA0000111122223333",
                    "From": "+15551112222",
                    "To": "+15553334444",
                    "CallStatus": "ringing",
                    "Direction": "inbound",
                    "AccountSid": "ACtest123456789",
                    "CallerCity": "San Francisco",
                    "CallerState": "CA",
                    "CallerCountry": "US"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("parse_voice_event should succeed");

    assert_eq!(result["event_type"], "voice.inbound");
    assert_eq!(result["call_sid"], "CA0000111122223333");
    assert_eq!(result["from"], "+15551112222");
    assert_eq!(result["to"], "+15553334444");
    assert_eq!(result["call_status"], "ringing");
    assert_eq!(result["direction"], "inbound");
    assert_eq!(result["caller_city"], "San Francisco");
    assert_eq!(result["caller_country"], "US");
    assert_eq!(result["tainted"], true);
}

/// Parse voice webhook event — missing `CallSid`.
#[fcp_async_core::runtime::test]
async fn webhook_parse_voice_event_missing_call_sid() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_voice_event.missing_call_sid");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_voice_event"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_voice_event");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_voice_event",
            "input": {
                "body": {
                    "From": "+15551112222",
                    "To": "+15553334444"
                }
            },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without CallSid");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("CallSid"),
                "error should mention CallSid: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Validate signature — empty signature.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_empty() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.empty");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.validate_signature");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "params": {"Body": "Hello"},
                "signature": ""
            },
            "capability_token": token
        }))
        .await
        .expect("validate_signature should succeed (returns valid=false)");

    assert_eq!(result["valid"], false);
    assert!(result["reason"].as_str().unwrap().contains("empty"));
}

/// Validate signature — invalid base64.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_invalid_base64() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.invalid_base64");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.validate_signature");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "params": {"Body": "Hello"},
                "signature": "not-valid-base64!!!@@@"
            },
            "capability_token": token
        }))
        .await
        .expect("validate_signature should succeed (returns valid=false)");

    assert_eq!(result["valid"], false);
    assert!(result["reason"].as_str().unwrap().contains("base64"));
}

/// Validate signature — valid base64 but no `auth_token`.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_no_auth_token() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.no_auth_token");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.validate_signature");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "params": {"Body": "Hello"},
                "signature": "dGVzdA=="
            },
            "capability_token": token
        }))
        .await
        .expect("validate_signature should succeed (returns valid=false)");

    assert_eq!(result["valid"], false);
    assert!(result["reason"].as_str().unwrap().contains("auth_token"));
}

/// Validate signature — valid format with `auth_token`.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_with_auth_token() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.with_auth_token");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.validate_signature");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "params": {"Body": "Hello", "From": "+15551234567"},
                "signature": "dGVzdA==",
                "auth_token": "my_auth_token_123"
            },
            "capability_token": token
        }))
        .await
        .expect("validate_signature should succeed");

    assert_eq!(result["valid"], true);
}

/// Validate signature — missing required params field.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_missing_params() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.missing_params");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.validate_signature");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "signature": "dGVzdA=="
            },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without params");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("params"),
                "error should mention params: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Parse SMS event — missing body field.
#[fcp_async_core::runtime::test]
async fn webhook_parse_sms_event_missing_body() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_sms_event.missing_body");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_sms_event"]).await;
    let token = generate_valid_token(&signing_key, "twilio.webhook.parse_sms_event");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_sms_event",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("should fail without body");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("body"),
                "error should mention body: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}
