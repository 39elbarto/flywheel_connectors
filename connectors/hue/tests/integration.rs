//! Integration tests for the Hue connector.

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_hue::HueConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, HandshakeRequest,
    InvokeRequest, OperationId, RequestId, SelfCheckStatus, ZoneId,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

const CAP_READ: &str = "hue.read";
const CAP_WRITE: &str = "hue.write";
const OP_HEALTH: &str = "hue.health";
const OP_SET_LIGHT_STATE: &str = "hue.set_light_state";
const OP_RECALL_SCENE: &str = "hue.recall_scene";

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [13u8; 32],
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
) -> CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
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
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

fn invoke_request(
    connector: &HueConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("hue-integration"),
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
    bridge_url: &str,
    allow_insecure_ssl: bool,
    capabilities: &[&str],
) -> (HueConnector, Ed25519SigningKey) {
    let mut connector = HueConnector::new();
    connector
        .configure(json!({
            "bridge_url": bridge_url,
            "app_key": "app-key",
            "allow_insecure_ssl": allow_insecure_ssl
        }))
        .await
        .expect("configure should succeed");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            capabilities,
        ))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn invoke_ok(
    connector: &HueConnector,
    operation: &'static str,
    input: Value,
    capability: &str,
    signing_key: &Ed25519SigningKey,
) -> Value {
    connector
        .invoke(invoke_request(
            connector,
            operation,
            input,
            capability_token(signing_key, capability, &[operation]),
        ))
        .await
        .expect("invoke should succeed")
        .result
        .expect("successful invoke should carry a result")
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_non_loopback_http_bridge_url() {
    let mut connector = HueConnector::new();
    let error = connector
        .configure(json!({
            "bridge_url": "http://bridge.local",
            "app_key": "app-key"
        }))
        .await
        .expect_err("non-loopback http should fail");

    assert!(
        matches!(error, FcpError::InvalidRequest { .. }),
        "unexpected error: {error:?}"
    );
    let FcpError::InvalidRequest { code, message } = error else {
        return;
    };
    assert_eq!(code, 1003);
    assert!(message.contains("https"));
}

#[fcp_async_core::runtime::test]
async fn health_reports_local_transport_and_app_key_state() {
    let mut connector = HueConnector::new();
    connector
        .configure(json!({
            "bridge_url": "http://127.0.0.1:18080",
            "app_key": "app-key"
        }))
        .await
        .expect("configure should succeed");

    let health = connector.health().await;
    assert!(health.is_ready());
    let details = health.details.expect("health details should exist");
    assert_eq!(details["configured"], true);
    assert_eq!(details["transport"], "http-loopback");
    assert_eq!(details["app_key_configured"], true);
    assert_eq!(details["allow_insecure_ssl"], false);
}

#[fcp_async_core::runtime::test]
async fn self_check_reports_bridge_metadata_and_health() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/clip/v2/resource/bridge"))
        .and(header("hue-application-key", "app-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{ "id": "bridge-1" }]
        })))
        .mount(&server)
        .await;

    let mut connector = HueConnector::new();
    connector
        .configure(json!({
            "bridge_url": server.uri(),
            "app_key": "app-key",
            "allow_insecure_ssl": true
        }))
        .await
        .expect("configure should succeed");

    let report = connector
        .self_check()
        .await
        .expect("self check should succeed");
    assert_eq!(report.status, SelfCheckStatus::Ok);
    let details = report.details.expect("self check details should exist");
    assert_eq!(details["transport"], "http-loopback");
    assert_eq!(details["allow_insecure_ssl"], true);
    assert_eq!(details["app_key_configured"], true);
    assert_eq!(details["bridge_health"]["data"][0]["id"], "bridge-1");
}

#[fcp_async_core::runtime::test]
async fn invoke_set_light_state_rejects_out_of_range_brightness() {
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:18080", false, &[CAP_WRITE]).await;
    let error = connector
        .invoke(invoke_request(
            &connector,
            OP_SET_LIGHT_STATE,
            json!({
                "light_id": "light-1",
                "on": true,
                "brightness": 150.0
            }),
            capability_token(&signing_key, CAP_WRITE, &[OP_SET_LIGHT_STATE]),
        ))
        .await
        .expect_err("out-of-range brightness must fail");

    assert!(
        matches!(error, FcpError::InvalidRequest { .. }),
        "unexpected error: {error:?}"
    );
    let FcpError::InvalidRequest { code, message } = error else {
        return;
    };
    assert_eq!(code, 1005);
    assert!(message.contains("between 0 and 100"));
}

#[fcp_async_core::runtime::test]
async fn invoke_recall_scene_hits_expected_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/clip/v2/resource/scene/scene-1"))
        .and(header("hue-application-key", "app-key"))
        .and(body_json(json!({
            "recall": { "action": "active" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{ "rid": "scene-1" }]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), false, &[CAP_WRITE]).await;
    let result = invoke_ok(
        &connector,
        OP_RECALL_SCENE,
        json!({ "scene_id": "scene-1" }),
        CAP_WRITE,
        &signing_key,
    )
    .await;

    assert_eq!(result["data"][0]["rid"], "scene-1");
}

#[fcp_async_core::runtime::test]
async fn invoke_health_reports_transport_metadata() {
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:18080", false, &[CAP_READ]).await;
    let result = invoke_ok(&connector, OP_HEALTH, json!({}), CAP_READ, &signing_key).await;

    assert_eq!(result["status"], "ok");
    assert_eq!(result["transport"], "http-loopback");
    assert_eq!(result["app_key_configured"], true);
}
