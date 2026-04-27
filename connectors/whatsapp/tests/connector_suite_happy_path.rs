use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_whatsapp::connector::WhatsAppConnector;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

const OP_WEBHOOK_RECEIVE: &str = "whatsapp.webhook_receive";
const CAP_WEBHOOK: &str = "whatsapp.webhook";
const APP_SECRET: &str = "test_app_secret_12345";
const VERIFY_TOKEN: &str = "test_verify_token_xyz";

type HmacSha256 = Hmac<Sha256>;

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [11u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_WEBHOOK)],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn build_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_WEBHOOK)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_WEBHOOK_RECEIVE])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn signed_webhook_body() -> (String, String) {
    let body = json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": {
                        "display_phone_number": "15551234567",
                        "phone_number_id": "123456789"
                    },
                    "messages": [{
                        "from": "15559876543",
                        "id": "wamid.connector_suite_signature",
                        "timestamp": "1677000000",
                        "type": "text",
                        "text": {
                            "body": "hello from connector suite",
                            "preview_url": false
                        }
                    }]
                },
                "field": "messages"
            }]
        }]
    })
    .to_string();

    let mut mac =
        HmacSha256::new_from_slice(APP_SECRET.as_bytes()).expect("HMAC accepts app secret bytes");
    mac.update(body.as_bytes());
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    (body, signature)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_verifies_webhook_signature() {
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let (body, signature) = signed_webhook_body();

    let invoke = InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("whatsapp-connector-suite"),
        connector_id: ConnectorId::from_static("fcp.whatsapp"),
        operation: OperationId::from_static(OP_WEBHOOK_RECEIVE),
        zone_id: ZoneId::work(),
        input: json!({
            "headers": {
                "X-Hub-Signature-256": signature
            },
            "body": body
        }),
        capability_token: build_token(&signing_key),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    };

    let suite = ConnectorSuite {
        test_name: "whatsapp_webhook_signature_happy_path".to_string(),
        config: json!({
            "phone_number_id": "123456789",
            "access_token": "test_access_token_xyz",
            "app_secret": APP_SECRET,
            "webhook_verify_token": VERIFY_TOKEN,
            "retry": { "max_retries": 0 },
            "request_timeout_ms": 5_000
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = WhatsAppConnector::new();
    let mut runner = E2eRunner::new("fcp-whatsapp");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    for entry in &report.logs {
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
    }

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
