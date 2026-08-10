//! Integration tests for the FCP n8n connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityConstraints, CapabilityToken, ExecutionScope,
    FcpResult, InputConstraint, ZoneId,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_n8n::connector::N8nConnector;

const TEST_SERVER_ID: &str = "eec";
const TEST_INSTANCE_ID: &str = "inst_n8n_test";

fn test_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[42_u8; 32]).expect("fixed test key should parse")
}

fn resource_uri(operation: &str, input: &Value) -> String {
    match operation {
        "n8n.workflows.list" | "n8n.executions.list" => {
            format!("fwc-n8n://{TEST_SERVER_ID}")
        }
        "n8n.workflows.get" | "n8n.workflows.activate" => {
            let id = input["id"].as_str().expect("workflow id for test token");
            let id = utf8_percent_encode(id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/workflows/{id}")
        }
        "n8n.executions.get" => {
            let workflow_id = input["workflow_id"]
                .as_str()
                .expect("workflow id for execution test token");
            let execution_id = input["id"].as_str().expect("execution id for test token");
            let workflow_id = utf8_percent_encode(workflow_id, NON_ALPHANUMERIC);
            let execution_id = utf8_percent_encode(execution_id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/workflows/{workflow_id}/executions/{execution_id}")
        }
        _ => panic!("unknown operation in test token: {operation}"),
    }
}

fn capability_token(operation: &str, input: &Value) -> CapabilityToken {
    let now = chrono::Utc::now();
    capability_token_with_options(
        operation,
        &test_signing_key(),
        TEST_INSTANCE_ID,
        resource_uri(operation, input),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::hours(1),
    )
}

fn capability_token_with_options(
    operation: &str,
    key: &Ed25519SigningKey,
    target_instance: &str,
    resource_allow: String,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> CapabilityToken {
    let capability = match operation {
        "n8n.workflows.activate" => "n8n.workflows.write",
        "n8n.workflows.list" | "n8n.workflows.get" => "n8n.workflows.read",
        "n8n.executions.list" | "n8n.executions.get" => "n8n.executions.read",
        _ => panic!("unknown operation in test token: {operation}"),
    };
    let constraints = CapabilityConstraints {
        resource_allow: vec![resource_allow],
        ..CapabilityConstraints::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("capability constraints should encode");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(target_instance)
        .validity(issued_at, expires_at)
        .try_constraints_cbor(&constraints_cbor)
        .expect("capability constraints should validate")
        .sign(key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn approval_token(input: &Value) -> ApprovalToken {
    let workflow_id = input["id"].as_str().expect("workflow id for approval");
    let active = input["active"].as_bool().expect("active for approval");
    let resource_uri = resource_uri("n8n.workflows.activate", input);
    let constraints = [
        ("/server_id", json!(TEST_SERVER_ID)),
        ("/resource_uri", json!(resource_uri)),
        ("/workflow_id", json!(workflow_id)),
        ("/active", json!(active)),
        ("/provider", json!("rest")),
    ]
    .into_iter()
    .map(|(pointer, expected)| InputConstraint {
        pointer: pointer.into(),
        expected,
    })
    .collect();
    let now = u64::try_from(chrono::Utc::now().timestamp_millis())
        .expect("current timestamp should fit in u64");
    ApprovalToken::approved(
        "approval-test",
        now.saturating_sub(1_000),
        now.saturating_add(60_000),
        "operator:test",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.n8n".into(),
            method_pattern: "n8n.workflows.activate".into(),
            request_object_id: None,
            input_hash: None,
            input_constraints: constraints,
        }),
        ZoneId::work(),
        Some(vec![1_u8]),
    )
}

fn unrelated_approval_token(input: &Value) -> ApprovalToken {
    let mut token = approval_token(input);
    if let ApprovalScope::Execution(scope) = &mut token.scope {
        scope.connector_id = "fcp.other".into();
    }
    token
}

fn host_bound_input_hash_approval_token(input: &Value) -> ApprovalToken {
    let mut token = approval_token(input);
    if let ApprovalScope::Execution(scope) = &mut token.scope {
        scope.input_hash = Some([7_u8; 32]);
    }
    token
}

fn authorized_params(operation: &str, input: &Value) -> Value {
    let mut params = json!({
        "operation": operation,
        "input": input,
        "capability_token": capability_token(operation, input),
    });
    if operation == "n8n.workflows.activate" {
        params["approval_tokens"] = json!([approval_token(input)]);
    }
    params
}

async fn invoke(connector: &N8nConnector, operation: &str, input: Value) -> FcpResult<Value> {
    connector
        .handle_invoke(authorized_params(operation, &input))
        .await
}

async fn setup_connector(mock_url: &str) -> N8nConnector {
    setup_connector_with_config(json!({
        "api_key": "test-n8n-api-key-123",
        "server_id": TEST_SERVER_ID,
        "base_url": format!("{mock_url}/api/v1")
    }))
    .await
}

async fn setup_connector_with_config(config: Value) -> N8nConnector {
    let mut c = N8nConnector::new();
    let key = test_signing_key();
    c.handle_configure(config).await.unwrap();
    c.handle_handshake(json!({
        "protocol_version": "1.0.0",
        "zone": "z:work",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![0_u8; 32],
        "capabilities_requested": [
            "n8n.workflows.read",
            "n8n.workflows.write",
            "n8n.executions.read"
        ],
        "requested_instance_id": TEST_INSTANCE_ID
    }))
    .await
    .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = N8nConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
    assert_eq!(h["configured"], false);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configured_but_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = N8nConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "server_id": TEST_SERVER_ID,
        "base_url": format!("{}/api/v1", server.uri())
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = N8nConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
    assert_eq!(health["handshaken"], false);
    assert!(
        c.handle_invoke(json!({"operation": "n8n.workflows.list"}))
            .await
            .is_err()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_configured() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
    assert!(check["details"]["provisioning"].is_object());
    assert_eq!(check["details"]["provisioning"]["auth_mode"], "api_key");
    assert_eq!(check["details"]["provisioning"]["network_ok"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = N8nConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_healthy() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "healthy");
    assert_eq!(d["checks"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = N8nConnector::new();
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert!(!ops.is_empty(), "introspect should list operations");
    assert!(ops[0]["id"].is_string());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_response() {
    let server = MockServer::start().await;
    let mut c = N8nConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "server_id": TEST_SERVER_ID,
        "base_url": format!("{}/api/v1", server.uri())
    }))
    .await
    .unwrap();
    let key = test_signing_key();
    let h = c
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["n8n.workflows.read"],
            "requested_instance_id": TEST_INSTANCE_ID
        }))
        .await
        .unwrap();
    assert_eq!(h["status"], "accepted");
    assert!(h["manifest_hash"].as_str().unwrap().starts_with("sha256:"));
    let caps = h["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 1);
}

// -- Workflows List --

#[fcp_async_core::runtime::test]
async fn workflows_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "1001", "name": "Daily Report", "active": true},
                {"id": "1002", "name": "Sync Contacts", "active": false},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn workflows_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

// -- Workflows Get --

#[fcp_async_core::runtime::test]
async fn workflows_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1001",
            "name": "Daily Report",
            "active": true,
            "createdAt": "2025-01-15T10:00:00.000Z",
            "updatedAt": "2025-02-20T14:30:00.000Z",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.get", json!({"id": "1001"}))
        .await
        .unwrap();
    assert_eq!(result["id"], "1001");
    assert_eq!(result["name"], "Daily Report");
    assert_eq!(result["active"], true);
}

#[fcp_async_core::runtime::test]
async fn workflows_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.workflows.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn capability_gate_denials_do_not_egress() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({});
    let now = chrono::Utc::now();

    let mut missing = authorized_params("n8n.workflows.list", &input);
    missing
        .as_object_mut()
        .expect("invoke params should be an object")
        .remove("capability_token");

    let mut invalid_signature = authorized_params("n8n.workflows.list", &input);
    invalid_signature["capability_token"] = json!(capability_token_with_options(
        "n8n.workflows.list",
        &Ed25519SigningKey::from_bytes(&[43_u8; 32]).expect("wrong test key should parse"),
        TEST_INSTANCE_ID,
        resource_uri("n8n.workflows.list", &input),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::hours(1),
    ));

    let mut expired = authorized_params("n8n.workflows.list", &input);
    expired["capability_token"] = json!(capability_token_with_options(
        "n8n.workflows.list",
        &test_signing_key(),
        TEST_INSTANCE_ID,
        resource_uri("n8n.workflows.list", &input),
        now - chrono::Duration::hours(2),
        now - chrono::Duration::hours(1),
    ));

    let mut wrong_instance = authorized_params("n8n.workflows.list", &input);
    wrong_instance["capability_token"] = json!(capability_token_with_options(
        "n8n.workflows.list",
        &test_signing_key(),
        "other-instance",
        resource_uri("n8n.workflows.list", &input),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::hours(1),
    ));

    let mut wrong_resource = authorized_params("n8n.workflows.list", &input);
    wrong_resource["capability_token"] = json!(capability_token_with_options(
        "n8n.workflows.list",
        &test_signing_key(),
        TEST_INSTANCE_ID,
        "fwc-n8n://hetzner".into(),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::hours(1),
    ));

    for (label, params) in [
        ("missing", missing),
        ("invalid signature", invalid_signature),
        ("expired", expired),
        ("wrong instance", wrong_instance),
        ("wrong resource", wrong_resource),
    ] {
        assert!(
            c.handle_invoke(params).await.is_err(),
            "capability denial should fail for {label}"
        );
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "capability denials must not reach provider"
    );
}

// -- Workflows Activate --

#[fcp_async_core::runtime::test]
async fn workflows_activate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let err = invoke(
        &c,
        "n8n.workflows.activate",
        json!({"id": "1001", "active": true}),
    )
    .await
    .expect_err("activation must fail closed until mediated lifecycle support exists");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_ignores_unrelated_approval_tokens() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});
    let mut params = authorized_params("n8n.workflows.activate", &input);
    params["approval_tokens"] = json!([unrelated_approval_token(&input), approval_token(&input),]);
    let err = c
        .handle_invoke(params)
        .await
        .expect_err("valid approval must still stop at the deferred lifecycle boundary");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_rejects_multiple_matching_approval_tokens() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});
    let mut params = authorized_params("n8n.workflows.activate", &input);
    params["approval_tokens"] = json!([approval_token(&input), approval_token(&input)]);
    let err = c
        .handle_invoke(params)
        .await
        .expect_err("duplicate matching approvals must fail closed");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { .. }
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_allows_host_bound_input_hash_for_semantic_gate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});
    let mut params = authorized_params("n8n.workflows.activate", &input);
    params["approval_tokens"] = json!([host_bound_input_hash_approval_token(&input)]);
    let err = c
        .handle_invoke(params)
        .await
        .expect_err("host-bound input_hash approval must not enable direct lifecycle I/O");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_rejects_malformed_approval_entry() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});
    let mut params = authorized_params("n8n.workflows.activate", &input);
    params["approval_tokens"] = json!([
        {"malformed": true},
        approval_token(&input),
    ]);
    let err = c
        .handle_invoke(params)
        .await
        .expect_err("malformed approval entries must fail closed");
    assert!(matches!(err, fcp_prelude::FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn approval_gate_denials_do_not_egress_provider() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});

    let mut missing = authorized_params("n8n.workflows.activate", &input);
    missing
        .as_object_mut()
        .expect("invoke params should be an object")
        .remove("approval_tokens");

    let mut expired = authorized_params("n8n.workflows.activate", &input);
    let mut expired_token = approval_token(&input);
    expired_token.expires_at_ms = 0;
    expired["approval_tokens"] = json!([expired_token]);

    let mut wrong_zone = authorized_params("n8n.workflows.activate", &input);
    let mut wrong_zone_token = approval_token(&input);
    wrong_zone_token.zone_id = ZoneId::private();
    wrong_zone["approval_tokens"] = json!([wrong_zone_token]);

    let mut wrong_target = authorized_params("n8n.workflows.activate", &input);
    wrong_target["approval_tokens"] = json!([approval_token(&json!({
        "id": "1001",
        "active": false
    }))]);

    for (label, params) in [
        ("missing", missing),
        ("expired", expired),
        ("wrong zone", wrong_zone),
        ("wrong target", wrong_target),
    ] {
        assert!(
            c.handle_invoke(params).await.is_err(),
            "approval denial should fail for {label}"
        );
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "approval denials must not reach the provider"
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_deactivate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let err = invoke(
        &c,
        "n8n.workflows.activate",
        json!({"id": "1002", "active": false}),
    )
    .await
    .expect_err("deactivation must fail closed until mediated lifecycle support exists");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.workflows.activate",
            "input": {"active": true}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_missing_active() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.workflows.activate",
            "input": {"id": "1001"}
        }))
        .await
        .is_err()
    );
}

// -- Executions List --

#[fcp_async_core::runtime::test]
async fn executions_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "50001", "finished": true, "status": "success", "workflowId": "1001"},
                {"id": "50002", "finished": true, "status": "error", "workflowId": "1002"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.executions.list", json!({})).await.unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn executions_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.executions.list", json!({})).await.unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

// -- Executions Get --

#[fcp_async_core::runtime::test]
async fn executions_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions/50001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "50001",
            "finished": true,
            "mode": "trigger",
            "startedAt": "2025-03-01T08:00:00.000Z",
            "stoppedAt": "2025-03-01T08:00:05.000Z",
            "workflowId": "1001",
            "status": "success",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(
        &c,
        "n8n.executions.get",
        json!({"workflow_id": "1001", "id": "50001"}),
    )
    .await
    .unwrap();
    assert_eq!(result["id"], "50001");
    assert_eq!(result["finished"], true);
    assert_eq!(result["status"], "success");
}

#[fcp_async_core::runtime::test]
async fn executions_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.executions.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"message": "Invalid API key"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_403_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Insufficient permissions"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_404_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/99999"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "Workflow not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        invoke(&c, "n8n.workflows.get", json!({"id": "99999"}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Rate limit exceeded"}))
                .insert_header("retry-after", "30"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn error_500_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.executions.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_502_bad_gateway() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.workflows.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.workflows.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_activate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.workflows.activate"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_executions_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.executions.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_executions_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.executions.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({"operation": "n8n.nope"}))
        .await
        .unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
    assert_eq!(result["reason"], "Unknown operation");
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment_on_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_increment_on_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = invoke(&c, "n8n.workflows.list", json!({})).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Configuration --

#[fcp_async_core::runtime::test]
async fn configure_rejects_missing_base_url() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "api_key": "test-key",
            "server_id": TEST_SERVER_ID,
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_base_url() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "api_key": "test-key",
            "server_id": TEST_SERVER_ID,
            "base_url": "",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_no_auth() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "server_id": TEST_SERVER_ID,
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "server_id": TEST_SERVER_ID,
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn credential_id_provider_egress_fails_closed_before_request() {
    let server = MockServer::start().await;
    let c = setup_connector_with_config(json!({
        "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        "server_id": TEST_SERVER_ID,
        "base_url": format!("{}/api/v1", server.uri()),
    }))
    .await;

    let err = invoke(&c, "n8n.workflows.list", json!({}))
        .await
        .expect_err("CredentialId must not use direct provider HTTP");
    assert!(err.to_string().contains("host-mediated secret injection"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn production_provider_egress_fails_closed_before_network() {
    let c = setup_connector_with_config(json!({
        "api_key": "test-n8n-api-key-123",
        "server_id": TEST_SERVER_ID,
        "base_url": "https://n8n.example.com/api/v1",
    }))
    .await;

    let err = invoke(&c, "n8n.workflows.list", json!({}))
        .await
        .expect_err("production direct provider HTTP must be unavailable");
    assert!(
        err.to_string()
            .contains("host-mediated network enforcement")
    );

    let check = c
        .handle_self_check()
        .await
        .expect("self-check should report the unavailable provider path");
    assert_eq!(check["status"], "failed");
    assert_eq!(check["reason_code"], "provider_probe_failed");
}

// -- Invoke without configure --

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = N8nConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Empty response body handling --

#[fcp_async_core::runtime::test]
async fn valid_activation_fails_closed_before_provider() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let err = invoke(
        &c,
        "n8n.workflows.activate",
        json!({"id": "1001", "active": true}),
    )
    .await
    .expect_err("valid activation must fail closed before provider I/O");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

// -- Auth header verification --

#[fcp_async_core::runtime::test]
async fn auth_header_sent_correctly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1001",
            "name": "Test Workflow"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.get", json!({"id": "1001"}))
        .await
        .unwrap();
    assert_eq!(result["id"], "1001");
}

// -- Invoke with missing operation --

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Reconfigure --

#[fcp_async_core::runtime::test]
async fn reconfigure_succeeds() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    // Reconfigure with new key
    let result = c
        .handle_configure(json!({
            "api_key": "new-api-key",
            "server_id": TEST_SERVER_ID,
            "base_url": format!("{}/api/v1", server.uri())
        }))
        .await;
    assert!(result.is_ok());
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["configured"], true);
    assert_eq!(health["handshaken"], false);
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}
