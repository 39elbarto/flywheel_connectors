//! Integration tests for the FCP `Pulumi` connector.

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

use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_pulumi::connector::PulumiConnector;

async fn setup_connector(mock_url: &str) -> PulumiConnector {
    let mut c = PulumiConnector::new();
    c.handle_configure(json!({ "access_token": "pul-test-token", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = PulumiConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = PulumiConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 6);
}

// -- Stacks List --

#[fcp_async_core::runtime::test]
async fn stacks_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks.*"))
        .and(header("Authorization", "Bearer pul-test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "stacks": [
                {"orgName": "myorg", "projectName": "proj1", "stackName": "dev"},
                {"orgName": "myorg", "projectName": "proj1", "stackName": "prod"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {"organization": "myorg", "project": "proj1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["stacks"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn stacks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "stacks": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["stacks"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn stacks_list_no_params() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stacks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "stacks": [{"orgName": "o", "projectName": "p", "stackName": "s"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["stacks"].as_array().unwrap().len(), 1);
}

// -- Stacks Get --

#[fcp_async_core::runtime::test]
async fn stacks_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stacks/myorg/myproject/production"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "orgName": "myorg",
            "projectName": "myproject",
            "stackName": "production",
            "activeUpdate": "upd-123",
            "version": 7,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.get",
            "input": {"organization": "myorg", "project": "myproject", "stack": "production"}
        }))
        .await
        .unwrap();
    assert_eq!(result["orgName"], "myorg");
    assert_eq!(result["stackName"], "production");
}

#[fcp_async_core::runtime::test]
async fn stacks_get_missing_organization() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.get",
            "input": {"project": "p", "stack": "s"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn stacks_get_missing_project() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.get",
            "input": {"organization": "o", "stack": "s"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn stacks_get_missing_stack() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.get",
            "input": {"organization": "o", "project": "p"}
        }))
        .await
        .is_err()
    );
}

// -- Stacks Create --

#[fcp_async_core::runtime::test]
async fn stacks_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/stacks/myorg/myproject"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "orgName": "myorg",
            "projectName": "myproject",
            "stackName": "staging",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.create",
            "input": {"organization": "myorg", "project": "myproject", "stack": "staging"}
        }))
        .await
        .unwrap();
    assert_eq!(result["stackName"], "staging");
}

#[fcp_async_core::runtime::test]
async fn stacks_create_missing_organization() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.create",
            "input": {"project": "p", "stack": "s"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn stacks_create_missing_stack() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.create",
            "input": {"organization": "o", "project": "p"}
        }))
        .await
        .is_err()
    );
}

// -- Stacks Delete --

#[fcp_async_core::runtime::test]
async fn stacks_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/stacks/myorg/myproject/staging"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.delete",
            "input": {"organization": "myorg", "project": "myproject", "stack": "staging"}
        }))
        .await
        .unwrap();
    // Empty body on 204 returns {}
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn stacks_delete_missing_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.delete",
            "input": {"organization": "o"}
        }))
        .await
        .is_err()
    );
}

// -- Stacks Export --

#[fcp_async_core::runtime::test]
async fn stacks_export() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stacks/myorg/myproject/production/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": 3,
            "deployment": {
                "manifest": {"time": "2026-03-05T00:00:00Z"},
                "resources": [{"urn": "urn:pulumi:prod::proj::pkg:mod:Type::name"}],
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.export",
            "input": {"organization": "myorg", "project": "myproject", "stack": "production"}
        }))
        .await
        .unwrap();
    assert!(result["deployment"].is_object());
}

#[fcp_async_core::runtime::test]
async fn stacks_export_missing_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.export",
            "input": {"organization": "o", "project": "p"}
        }))
        .await
        .is_err()
    );
}

// -- Deployments List --

#[fcp_async_core::runtime::test]
async fn deployments_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stacks/myorg/myproject/production/updates"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "updates": [
                {"version": 1, "result": "succeeded", "kind": "update"},
                {"version": 2, "result": "succeeded", "kind": "update"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.deployments.list",
            "input": {"organization": "myorg", "project": "myproject", "stack": "production"}
        }))
        .await
        .unwrap();
    assert_eq!(result["updates"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn deployments_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stacks/myorg/myproject/dev/updates"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "updates": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pulumi.deployments.list",
            "input": {"organization": "myorg", "project": "myproject", "stack": "dev"}
        }))
        .await
        .unwrap();
    assert!(result["updates"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn deployments_list_missing_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.deployments.list",
            "input": {"organization": "o"}
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks.*"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"code": 401, "message": "Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks.*"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"code": 403, "message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks/.*"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"code": 404, "message": "not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.get",
            "input": {"organization": "o", "project": "p", "stack": "missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"code": 429, "message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks.*"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"code": 500, "message": "Internal server error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pulumi.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "pulumi.stacks.list"}))
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
    assert!(
        !c.handle_simulate(json!({"operation_id": "pulumi.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "stacks": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "pulumi.stacks.list",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/stacks.*"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"code": 500, "message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "pulumi.stacks.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
