//! WhatsApp connector integration tests (flywheel_connectors-j05nu.1.5).
//!
//! Deterministic integration tests using wiremock to exercise the real
//! `FcpConnector` surface against mock WhatsApp Business API responses.
//! No real API calls. Covers lifecycle and self-check behavior, outbound sends
//! and profile fetches, webhook verification and replay filtering, and FCP2
//! capability verification.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, HandshakeRequest,
    HealthState, InvokeRequest, OperationId, RequestId, SelfCheckStatus, ShutdownRequest, ZoneId,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

use fcp_whatsapp::connector::WhatsAppConnector;

const PHONE_NUMBER_ID: &str = "123456789";
const ACCESS_TOKEN: &str = "test_access_token_xyz";
const APP_SECRET: &str = "test_app_secret_12345";
const VERIFY_TOKEN: &str = "test_verify_token_xyz";

const OP_SEND_TEXT: &str = "whatsapp.send_text";
const OP_SEND_TEMPLATE: &str = "whatsapp.send_template";
const OP_GET_PROFILE: &str = "whatsapp.get_profile";
const OP_WEBHOOK_VERIFY: &str = "whatsapp.webhook_verify";
const OP_WEBHOOK_RECEIVE: &str = "whatsapp.webhook_receive";

const CAP_SEND: &str = "whatsapp.send";
const CAP_READ: &str = "whatsapp.read";
const CAP_WEBHOOK: &str = "whatsapp.webhook";

type HmacSha256 = Hmac<Sha256>;

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .constraints_cbor(&cbor)
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(cose)
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| CapabilityId::new(*cap).expect("capability id"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

async fn setup_handshake(
    connector: &mut WhatsAppConnector,
    capabilities: &[&str],
) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            capabilities,
        ))
        .await
        .expect("handshake should succeed");
    signing_key
}

async fn configure_connector(
    connector: &mut WhatsAppConnector,
    base_url: &str,
    webhook_enabled: bool,
) {
    let mut config = json!({
        "base_url": base_url,
        "phone_number_id": PHONE_NUMBER_ID,
        "access_token": ACCESS_TOKEN,
        "retry": {
            "max_retries": 0,
        },
    });
    if webhook_enabled {
        config["app_secret"] = json!(APP_SECRET);
        config["webhook_verify_token"] = json!(VERIFY_TOKEN);
    }
    connector
        .configure(config)
        .await
        .expect("configure should succeed");
}

async fn setup_connector(
    base_url: &str,
    capabilities: &[&str],
    webhook_enabled: bool,
) -> (WhatsAppConnector, Ed25519SigningKey) {
    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, base_url, webhook_enabled).await;
    let signing_key = setup_handshake(&mut connector, capabilities).await;
    (connector, signing_key)
}

fn invoke_request(
    connector: &WhatsAppConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("req_1"),
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

async fn invoke(
    connector: &WhatsAppConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(invoke_request(
            connector,
            operation,
            input,
            capability_token,
        ))
        .await?;
    Ok(response
        .result
        .expect("successful invoke should return result"))
}

fn send_message_response(message_id: &str, wa_id: &str) -> Value {
    json!({
        "messaging_product": "whatsapp",
        "contacts": [{ "input": wa_id, "wa_id": wa_id }],
        "messages": [{ "id": message_id }],
    })
}

fn sample_text_notification() -> Value {
    json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": {
                        "display_phone_number": "15551234567",
                        "phone_number_id": PHONE_NUMBER_ID,
                    },
                    "messages": [{
                        "from": "15559876543",
                        "id": "wamid.HBgLMTU1NTk4NzY1NDMVAgASGBQzQUY5MTcxMkFCRTY1RTM5REI0MAA=",
                        "timestamp": "1677000000",
                        "type": "text",
                        "text": { "body": "Hello from WhatsApp!", "preview_url": false },
                    }],
                },
                "field": "messages",
            }],
        }],
    })
}

fn sample_status_notification() -> Value {
    json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": {
                        "display_phone_number": "15551234567",
                        "phone_number_id": PHONE_NUMBER_ID,
                    },
                    "statuses": [{
                        "id": "wamid.STATUS123",
                        "status": "delivered",
                        "timestamp": "1677000100",
                        "recipient_id": "15559876543",
                    }],
                },
                "field": "messages",
            }],
        }],
    })
}

fn sign_payload(body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(APP_SECRET.as_bytes()).expect("hmac key");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let connector = WhatsAppConnector::new();
    let health = connector.health().await;
    assert!(matches!(health.status, HealthState::Degraded { .. }));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_accepts_requested_capabilities() {
    let mut connector = WhatsAppConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let response = connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &[CAP_SEND, CAP_READ, CAP_WEBHOOK],
        ))
        .await
        .expect("handshake should succeed");

    assert_eq!(response.status, "accepted");
    assert_eq!(response.capabilities_granted.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_passes_after_configure() {
    let server = MockServer::start().await;
    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let report = connector.doctor();
    assert!(report.passed);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure_is_ready() {
    let server = MockServer::start().await;
    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let health = connector.health().await;
    assert!(matches!(health.status, HealthState::Ready));
}

#[fcp_async_core::runtime::test]
async fn self_check_before_configure_is_degraded() {
    let connector = WhatsAppConnector::new();
    let report = connector.self_check().await.expect("self-check should run");
    assert_eq!(report.status, SelfCheckStatus::Degraded);
    assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
}

#[fcp_async_core::runtime::test]
async fn self_check_reports_ok_when_api_is_reachable() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.self_check.ok");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{PHONE_NUMBER_ID}")))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let report = connector.self_check().await.expect("self-check should run");
    assert_eq!(report.status, SelfCheckStatus::Ok);
}

#[fcp_async_core::runtime::test]
async fn self_check_unauthorized_is_failed() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.self_check.unauthorized");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{PHONE_NUMBER_ID}")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let report = connector.self_check().await.expect("self-check should run");
    assert_eq!(report.status, SelfCheckStatus::Failed);
    assert_eq!(report.reason_code.as_deref(), Some("self_check_failed"));
}

#[fcp_async_core::runtime::test]
async fn self_check_rate_limited_is_degraded() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.self_check.rate_limited");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{PHONE_NUMBER_ID}")))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "2"))
        .mount(&server)
        .await;

    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let report = connector.self_check().await.expect("self-check should run");
    assert_eq!(report.status, SelfCheckStatus::Degraded);
    assert_eq!(report.reason_code.as_deref(), Some("self_check_retryable"));
}

#[fcp_async_core::runtime::test]
async fn send_text_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.send_text.happy_path");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .and(body_json(json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": "15551234567",
            "type": "text",
            "text": {
                "body": "Hello from FCP!",
                "preview_url": true,
            },
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(send_message_response("wamid.MSG1", "15551234567")),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(&signing_key, CAP_SEND, &[OP_SEND_TEXT]);
    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
            "preview_url": true,
        }),
        token,
    )
    .await
    .expect("send_text should succeed");

    assert_eq!(result["message_id"], "wamid.MSG1");
    assert_eq!(result["wa_id"], "15551234567");
}

#[fcp_async_core::runtime::test]
async fn send_text_unauthorized_maps_to_fcp_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(&signing_key, CAP_SEND, &[OP_SEND_TEXT]);
    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::Unauthorized { .. })));
}

#[fcp_async_core::runtime::test]
async fn send_text_rate_limited_maps_to_fcp_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "5"))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(&signing_key, CAP_SEND, &[OP_SEND_TEXT]);
    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(
        result,
        Err(FcpError::RateLimited {
            retry_after_ms: 5000,
            ..
        })
    ));
}

#[fcp_async_core::runtime::test]
async fn send_text_invalid_preview_url_is_rejected() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(&signing_key, CAP_SEND, &[OP_SEND_TEXT]);
    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
            "preview_url": "yes",
        }),
        token,
    )
    .await;

    assert!(matches!(
        result,
        Err(FcpError::InvalidRequest { ref message, .. })
            if message.contains("preview_url")
    ));
}

#[fcp_async_core::runtime::test]
async fn send_template_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.send_template.happy_path");
    let server = MockServer::start().await;
    let components = json!([{
        "type": "body",
        "parameters": [{
            "type": "text",
            "text": "Ada",
        }],
    }]);

    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .and(body_json(json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": "15551234567",
            "type": "template",
            "template": {
                "name": "welcome_message",
                "language": { "code": "en_US" },
                "components": components.clone(),
            },
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(send_message_response("wamid.TEMPLATE1", "15551234567")),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(&signing_key, CAP_SEND, &[OP_SEND_TEMPLATE]);
    let result = invoke(
        &connector,
        OP_SEND_TEMPLATE,
        json!({
            "to": "15551234567",
            "template_name": "welcome_message",
            "language_code": "en_US",
            "components": components,
        }),
        token,
    )
    .await
    .expect("send_template should succeed");

    assert_eq!(result["message_id"], "wamid.TEMPLATE1");
}

#[fcp_async_core::runtime::test]
async fn send_template_invalid_components_is_rejected() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(&signing_key, CAP_SEND, &[OP_SEND_TEMPLATE]);
    let result = invoke(
        &connector,
        OP_SEND_TEMPLATE,
        json!({
            "to": "15551234567",
            "template_name": "welcome_message",
            "components": { "type": "body" },
        }),
        token,
    )
    .await;

    assert!(matches!(
        result,
        Err(FcpError::InvalidRequest { ref message, .. })
            if message.contains("components")
    ));
}

#[fcp_async_core::runtime::test]
async fn get_profile_happy_path_returns_flat_profile() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.get_profile.happy_path");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/{PHONE_NUMBER_ID}/whatsapp_business_profile"
        )))
        .and(query_param("fields", "about,address,description,vertical"))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "about": "Hello there",
                "address": "1 Main Street",
                "description": "Test business profile",
                "vertical": "SERVICES",
            }],
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_READ], false).await;
    let token = generate_valid_token(&signing_key, CAP_READ, &[OP_GET_PROFILE]);
    let result = invoke(&connector, OP_GET_PROFILE, json!({}), token)
        .await
        .expect("get_profile should succeed");

    assert_eq!(result["about"], "Hello there");
    assert_eq!(result["address"], "1 Main Street");
    assert_eq!(result["description"], "Test business profile");
    assert_eq!(result["vertical"], "SERVICES");
    assert!(result.get("data").is_none());
}

#[fcp_async_core::runtime::test]
async fn get_profile_rate_limited_maps_to_fcp_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/{PHONE_NUMBER_ID}/whatsapp_business_profile"
        )))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "3"))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_READ], false).await;
    let token = generate_valid_token(&signing_key, CAP_READ, &[OP_GET_PROFILE]);
    let result = invoke(&connector, OP_GET_PROFILE, json!({}), token).await;

    assert!(matches!(
        result,
        Err(FcpError::RateLimited {
            retry_after_ms: 3000,
            ..
        })
    ));
}

#[fcp_async_core::runtime::test]
async fn get_profile_empty_response_returns_empty_object() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/{PHONE_NUMBER_ID}/whatsapp_business_profile"
        )))
        .and(query_param("fields", "about,address,description,vertical"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_READ], false).await;
    let token = generate_valid_token(&signing_key, CAP_READ, &[OP_GET_PROFILE]);
    let result = invoke(&connector, OP_GET_PROFILE, json!({}), token)
        .await
        .expect("get_profile should succeed");

    assert_eq!(result, json!({}));
}

#[fcp_async_core::runtime::test]
async fn invoke_not_configured_is_rejected() {
    let mut connector = WhatsAppConnector::new();
    let signing_key = setup_handshake(&mut connector, &[CAP_SEND]).await;
    let token = generate_valid_token(&signing_key, CAP_SEND, &[OP_SEND_TEXT]);

    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::NotConfigured)));
}

#[fcp_async_core::runtime::test]
async fn webhook_verify_via_invoke() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.webhook_verify.happy_path");
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let token = generate_valid_token(&signing_key, CAP_WEBHOOK, &[OP_WEBHOOK_VERIFY]);

    let result = invoke(
        &connector,
        OP_WEBHOOK_VERIFY,
        json!({
            "hub_mode": "subscribe",
            "hub_verify_token": VERIFY_TOKEN,
            "hub_challenge": "challenge_123",
        }),
        token,
    )
    .await
    .expect("webhook verify should succeed");

    assert_eq!(result["challenge"], "challenge_123");
}

#[fcp_async_core::runtime::test]
async fn webhook_verify_wrong_token_is_unauthorized() {
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let token = generate_valid_token(&signing_key, CAP_WEBHOOK, &[OP_WEBHOOK_VERIFY]);

    let result = invoke(
        &connector,
        OP_WEBHOOK_VERIFY,
        json!({
            "hub_mode": "subscribe",
            "hub_verify_token": "wrong",
            "hub_challenge": "challenge_123",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::Unauthorized { .. })));
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_via_invoke_parses_events() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.webhook_receive.happy_path");
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let token = generate_valid_token(&signing_key, CAP_WEBHOOK, &[OP_WEBHOOK_RECEIVE]);

    let body = serde_json::to_vec(&sample_text_notification()).expect("body json");
    let result = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        token,
    )
    .await
    .expect("webhook receive should succeed");

    assert_eq!(result["event_count"], 1);
    assert_eq!(result["events"][0]["event_type"], "message.text");
    assert_eq!(
        result["events"][0]["id"],
        "wamid.HBgLMTU1NTk4NzY1NDMVAgASGBQzQUY5MTcxMkFCRTY1RTM5REI0MAA="
    );
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_filters_replayed_events() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.webhook_receive.replay_filter");
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let body = serde_json::to_vec(&sample_status_notification()).expect("body json");

    let first = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body.clone()).expect("utf8 body"),
        }),
        generate_valid_token(&signing_key, CAP_WEBHOOK, &[OP_WEBHOOK_RECEIVE]),
    )
    .await
    .expect("first webhook receive should succeed");

    let second = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        generate_valid_token(&signing_key, CAP_WEBHOOK, &[OP_WEBHOOK_RECEIVE]),
    )
    .await
    .expect("second webhook receive should succeed");

    assert_eq!(first["event_count"], 1);
    assert_eq!(second["event_count"], 0);
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_invalid_signature_is_rejected() {
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let token = generate_valid_token(&signing_key, CAP_WEBHOOK, &[OP_WEBHOOK_RECEIVE]);
    let body = serde_json::to_vec(&sample_text_notification()).expect("body json");

    let result = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": "sha256=deadbeef" },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        token,
    )
    .await;

    assert!(matches!(
        result,
        Err(FcpError::InvalidRequest { ref message, .. })
            if message.contains("Webhook verification failed")
    ));
}

#[fcp_async_core::runtime::test]
async fn capability_mismatch_rejects_send_text() {
    let server = MockServer::start().await;
    let (connector, signing_key) =
        setup_connector(&server.uri(), &[CAP_SEND, CAP_READ], false).await;
    let token = generate_valid_token(&signing_key, CAP_READ, &[OP_SEND_TEXT]);

    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspection_exposes_expected_operations() {
    let connector = WhatsAppConnector::new();
    let introspection = connector.introspect();
    let operation_ids: Vec<&str> = introspection
        .operations
        .iter()
        .map(|op| op.id.as_str())
        .collect();

    assert_eq!(operation_ids.len(), 5);
    assert!(operation_ids.contains(&OP_SEND_TEXT));
    assert!(operation_ids.contains(&OP_SEND_TEMPLATE));
    assert!(operation_ids.contains(&OP_GET_PROFILE));
    assert!(operation_ids.contains(&OP_WEBHOOK_VERIFY));
    assert!(operation_ids.contains(&OP_WEBHOOK_RECEIVE));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_succeeds() {
    let mut connector = WhatsAppConnector::new();
    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 10_000,
            drain: false,
            reason: None,
        })
        .await
        .expect("shutdown should succeed");
}

#[fcp_async_core::runtime::test]
async fn operation_mismatch_rejects_send_text() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(&signing_key, CAP_SEND, &[OP_GET_PROFILE]);

    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
}
