//! Deterministic loopback acceptance tests; no Google network access.

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_drive_activity::connector::DriveActivityConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, HandshakeRequest, InstanceId, ZoneId,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

const OPERATION: &str = "drive_activity.query";
const CAPABILITY: &str = "drive.activity.readonly";

fn loopback_auth_value() -> String {
    ["loopback", "auth", "value"].join("-")
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    target: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!("google-drive-activity:{target}")],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:loopback")
        .operations(&[OPERATION])
        .issuer("node:loopback")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(raw)
}

async fn setup(server: &MockServer) -> (DriveActivityConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = DriveActivityConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .handle_configure(json!({
            "access_token": loopback_auth_value(),
            "base_url": format!("{}/v2", server.uri())
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(
            serde_json::to_value(HandshakeRequest {
                protocol_version: "1.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [19_u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAPABILITY)],
                host: None,
                transport_caps: None,
                requested_instance_id: Some(instance_id.clone()),
            })
            .unwrap(),
        )
        .await
        .unwrap();
    (connector, signing_key, instance_id)
}

fn invoke_params(input: &Value, token: &CapabilityToken) -> Value {
    json!({"operation": OPERATION, "input": input, "capability_token": token})
}

#[fcp_async_core::test]
async fn exact_rpc_contract_and_two_page_cursor_continuity() {
    let server = MockServer::start().await;
    let first_body = json!({
        "itemName": "items/file-a", "pageSize": 2,
        "consolidationStrategy": {"none": {}}
    });
    Mock::given(method("POST"))
        .and(path("/v2/activity:query"))
        .and(header(
            "authorization",
            format!("Bearer {}", loopback_auth_value()),
        ))
        .and(header("content-type", "application/json"))
        .and(body_json(first_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "activities": [{
                "primaryActionDetail": {"create": {}},
                "actors": [{"user":{"knownUser":{"personName":"people/1","isCurrentUser":true}}}],
                "targets": [{"driveItem":{"name":"items/file-a","title":"A","file":{}}}],
                "timestamp": "2026-08-04T00:00:00Z", "actions": [{}]
            }],
            "nextPageToken": "opaque-page-2"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let second_body = json!({
        "itemName": "items/file-a", "pageSize": 2, "pageToken": "opaque-page-2",
        "consolidationStrategy": {"none": {}}
    });
    Mock::given(method("POST"))
        .and(path("/v2/activity:query"))
        .and(body_json(second_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "activities": [{
                "primaryActionDetail": {"rename": {}},
                "targets": [{"driveItem":{"name":"items/file-b","title":"B","file":{}}}],
                "timestamp": "2026-08-04T00:01:00Z", "actions": [{}]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (mut connector, signing_key, instance_id) = setup(&server).await;
    let first_input = json!({"item_name":"items/file-a","consolidation":"none","page_size":2});
    let first = connector
        .handle_invoke(invoke_params(
            &first_input,
            &capability_token(&signing_key, &instance_id, CAPABILITY, "items/file-a"),
        ))
        .await
        .unwrap();
    assert_eq!(first["activities"][0]["action"], "create");
    let second_input = json!({
        "item_name":"items/file-a", "consolidation":"none", "page_size":2,
        "page_token": first["next_page"]["page_token"],
        "cursor_binding_sha256": first["next_page"]["cursor_binding_sha256"]
    });
    let second = connector
        .handle_invoke(invoke_params(
            &second_input,
            &capability_token(&signing_key, &instance_id, CAPABILITY, "items/file-a"),
        ))
        .await
        .unwrap();
    assert_eq!(second["activities"][0]["action"], "rename");
    assert!(second["next_page"].is_null());
    assert_ne!(
        first["activities"][0]["targets"][0]["name"],
        second["activities"][0]["targets"][0]["name"]
    );
    server.verify().await;
}

#[fcp_async_core::test]
async fn wrong_capability_is_rejected_before_egress() {
    let server = MockServer::start().await;
    let (mut connector, signing_key, instance_id) = setup(&server).await;
    let result = connector
        .handle_invoke(invoke_params(
            &json!({"ancestor_name":"items/folder-a","consolidation":"legacy"}),
            &capability_token(&signing_key, &instance_id, "drive.read", "items/folder-a"),
        ))
        .await;
    assert!(result.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::test]
async fn provider_unauthorized_is_redacted() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/activity:query"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {"code":401,"message":"provider-private-secret","status":"UNAUTHENTICATED"}
        })))
        .mount(&server)
        .await;
    let (mut connector, signing_key, instance_id) = setup(&server).await;
    let error = connector
        .handle_invoke(invoke_params(
            &json!({"item_name":"items/file-a","consolidation":"none"}),
            &capability_token(&signing_key, &instance_id, CAPABILITY, "items/file-a"),
        ))
        .await
        .unwrap_err();
    let rendered = error.to_string();
    assert!(rendered.contains("authorization"));
    assert!(!rendered.contains("provider-private-secret"));
    assert!(!rendered.contains(&loopback_auth_value()));
}

#[fcp_async_core::test]
async fn oversized_provider_page_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "activities": [{"primaryActionDetail":{"edit":{}},"padding":"x".repeat(61_000)}]
        })))
        .mount(&server)
        .await;
    let (mut connector, signing_key, instance_id) = setup(&server).await;
    let error = connector
        .handle_invoke(invoke_params(
            &json!({"item_name":"items/file-a","consolidation":"none"}),
            &capability_token(&signing_key, &instance_id, CAPABILITY, "items/file-a"),
        ))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("smaller page"));
}
