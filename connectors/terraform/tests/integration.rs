//! Integration tests for the FCP Terraform Cloud connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::len_zero,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_terraform::connector::TerraformConnector;

/// Helper: JSON:API single-object response.
fn jsonapi_data(type_name: &str, id: &str, attrs: serde_json::Value) -> serde_json::Value {
    json!({
        "data": {
            "id": id,
            "type": type_name,
            "attributes": attrs,
        }
    })
}

/// Helper: JSON:API list response.
fn jsonapi_list(items: Vec<serde_json::Value>) -> serde_json::Value {
    json!({ "data": items })
}

/// Helper: single JSON:API item for embedding in lists.
fn jsonapi_item(type_name: &str, id: &str, attrs: serde_json::Value) -> serde_json::Value {
    json!({
        "id": id,
        "type": type_name,
        "attributes": attrs,
    })
}

async fn setup_connector(mock_url: &str) -> TerraformConnector {
    let mut c = TerraformConnector::new();
    c.handle_configure(json!({
        "api_token": "test-terraform-token",
        "organization": "test-org",
        "base_url": mock_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test-session"}))
        .await
        .unwrap();
    c
}

fn workspace_mock(id: &str, name: &str, version: &str) -> serde_json::Value {
    jsonapi_data(
        "workspaces",
        id,
        json!({
            "name": name,
            "terraform-version": version,
            "auto-apply": false,
            "resource-count": 10,
        }),
    )
}

// ==========================================================================
// Lifecycle tests
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = TerraformConnector::new();
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
async fn lifecycle_handshake_before_configure() {
    let mut c = TerraformConnector::new();
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
    assert_eq!(check["status"], "ready");
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 12);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configured_not_handshaken() {
    let mut c = TerraformConnector::new();
    c.handle_configure(json!({
        "api_token": "tok",
        "organization": "org",
    }))
    .await
    .unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "degraded");
}

// ==========================================================================
// terraform.init
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn init_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/myproject"))
        .and(header("Authorization", "Bearer test-terraform-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-1", "myproject", "1.7.0")),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {"working_dir": "/home/user/myproject"}
        }))
        .await
        .unwrap();
    assert_eq!(r["initialized"], true);
    assert_eq!(r["workspace_id"], "ws-1");
}

#[fcp_async_core::runtime::test]
async fn init_missing_working_dir() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.validate
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn validate_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/infra"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-v", "infra", "1.6.0")),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.validate",
            "input": {"working_dir": "/code/infra"}
        }))
        .await
        .unwrap();
    assert_eq!(r["valid"], true);
}

// ==========================================================================
// terraform.plan
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn plan_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/prod"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-p", "prod", "1.7.0")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(jsonapi_data(
            "runs",
            "run-plan1",
            json!({"status": "pending", "message": "Plan via FCP"}),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.plan",
            "input": {"working_dir": "/code/prod"}
        }))
        .await
        .unwrap();
    assert!(r["plan_hash"].as_str().unwrap().starts_with("blake3:"));
    assert_eq!(r["plan_file"], "run-plan1");
}

#[fcp_async_core::runtime::test]
async fn plan_missing_working_dir() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.plan",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.show_plan
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn show_plan_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/runs/run-sp1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_data(
            "runs",
            "run-sp1",
            json!({"status": "planned", "message": "All good", "resource-additions": 2, "resource-changes": 1, "resource-destructions": 0}),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.show_plan",
            "input": {"plan_file": "run-sp1"}
        }))
        .await
        .unwrap();
    // When no relationships.plan.data.id, falls back to data.attributes
    assert!(r.get("plan_detail").is_some());
    assert_eq!(r["plan_detail"]["status"], "planned");
}

#[fcp_async_core::runtime::test]
async fn show_plan_missing_plan_file() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.show_plan",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.apply
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn apply_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/runs/run-a1/actions/apply"))
        .and(header("Authorization", "Bearer test-terraform-token"))
        .respond_with(ResponseTemplate::new(202).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.apply",
            "input": {"working_dir": "/code/prod", "plan_hash": "blake3:run-a1"}
        }))
        .await
        .unwrap();
    assert_eq!(r["applied"], true);
}

#[fcp_async_core::runtime::test]
async fn apply_with_comment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/runs/run-a2/actions/apply"))
        .respond_with(ResponseTemplate::new(202).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.apply",
            "input": {"working_dir": "/code/prod", "plan_hash": "blake3:run-a2", "comment": "LGTM"}
        }))
        .await
        .unwrap();
    assert_eq!(r["applied"], true);
}

#[fcp_async_core::runtime::test]
async fn apply_missing_working_dir() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.apply",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.destroy
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn destroy_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/runs/run-destroy1/actions/apply"))
        .respond_with(ResponseTemplate::new(202).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.destroy",
            "input": {"working_dir": "/code/staging", "plan_hash": "blake3:run-destroy1"}
        }))
        .await
        .unwrap();
    assert_eq!(r["destroyed"], true);
}

#[fcp_async_core::runtime::test]
async fn destroy_missing_working_dir() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.destroy",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.state_list
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn state_list_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/infra"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-sl", "infra", "1.7.0")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws-sl/current-state-version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_data(
            "state-versions",
            "sv-1",
            json!({"serial": 5}),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/state-versions/sv-1/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_list(vec![
            jsonapi_item(
                "resources",
                "r-1",
                json!({"address": "aws_instance.web", "name": "web", "type": "aws_instance"}),
            ),
            jsonapi_item(
                "resources",
                "r-2",
                json!({"address": "aws_s3_bucket.data", "name": "data", "type": "aws_s3_bucket"}),
            ),
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.state_list",
            "input": {"working_dir": "/code/infra"}
        }))
        .await
        .unwrap();
    assert_eq!(r["resources"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn state_list_with_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/infra"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-sf", "infra", "1.7.0")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws-sf/current-state-version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_data(
            "state-versions",
            "sv-f",
            json!({"serial": 3}),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/state-versions/sv-f/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_list(vec![
            jsonapi_item(
                "resources",
                "r-1",
                json!({"address": "aws_instance.web", "name": "web", "type": "aws_instance"}),
            ),
            jsonapi_item(
                "resources",
                "r-2",
                json!({"address": "aws_s3_bucket.data", "name": "data", "type": "aws_s3_bucket"}),
            ),
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.state_list",
            "input": {"working_dir": "/code/infra", "filter": "aws_instance"}
        }))
        .await
        .unwrap();
    let resources = r["resources"].as_array().unwrap();
    assert!(resources.len() >= 1);
}

// ==========================================================================
// terraform.state_show
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn state_show_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/infra"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-ss", "infra", "1.7.0")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws-ss/current-state-version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_data(
            "state-versions",
            "sv-ss",
            json!({"serial": 7}),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/state-versions/sv-ss/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_list(vec![
            jsonapi_item(
                "resources",
                "r-match",
                json!({"address": "aws_instance.web", "name": "web", "type": "aws_instance", "provider": "aws"}),
            ),
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.state_show",
            "input": {"working_dir": "/code/infra", "address": "aws_instance.web"}
        }))
        .await
        .unwrap();
    assert!(r.get("resource").is_some());
}

#[fcp_async_core::runtime::test]
async fn state_show_missing_address() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.state_show",
            "input": {"working_dir": "/code/infra"}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.output
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn output_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/infra"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-out", "infra", "1.7.0")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws-out/current-state-version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_data(
            "state-versions",
            "sv-out",
            json!({"serial": 4}),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/state-versions/sv-out/outputs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_list(vec![
            jsonapi_item(
                "state-version-outputs",
                "svo-1",
                json!({"name": "vpc_id", "value": "vpc-abc123", "sensitive": false, "type": "string"}),
            ),
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.output",
            "input": {"working_dir": "/code/infra"}
        }))
        .await
        .unwrap();
    assert!(r.get("outputs").is_some());
}

#[fcp_async_core::runtime::test]
async fn output_missing_working_dir() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.output",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.import
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn import_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/infra"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-imp", "infra", "1.7.0")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(jsonapi_data(
            "runs",
            "run-import1",
            json!({"status": "pending", "message": "Import run"}),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.import",
            "input": {
                "working_dir": "/code/infra",
                "address": "aws_instance.web",
                "id": "i-1234567890abcdef0"
            }
        }))
        .await
        .unwrap();
    assert_eq!(r["imported"], true);
    assert_eq!(r["address"], "aws_instance.web");
}

#[fcp_async_core::runtime::test]
async fn import_missing_address() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.import",
            "input": {"working_dir": "/code/infra", "resource_id": "i-abc"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn import_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.import",
            "input": {"working_dir": "/code/infra", "address": "aws_instance.web"}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.detect_drift
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn detect_drift_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/prod"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-drift", "prod", "1.7.0")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(jsonapi_data(
            "runs",
            "run-drift1",
            json!({"status": "pending", "message": "Drift detection"}),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.detect_drift",
            "input": {"working_dir": "/code/prod"}
        }))
        .await
        .unwrap();
    assert!(r.get("drifted").is_some());
    assert!(r.get("checkpoint_ts").is_some());
}

#[fcp_async_core::runtime::test]
async fn detect_drift_missing_working_dir() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.detect_drift",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// terraform.list_modules
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn list_modules_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/infra"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-mod", "infra", "1.7.0")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws-mod/configuration-versions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonapi_list(vec![
            jsonapi_item(
                "configuration-versions",
                "cv-1",
                json!({"source": "terraform+cloud", "status": "uploaded"}),
            ),
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.list_modules",
            "input": {"working_dir": "/code/infra"}
        }))
        .await
        .unwrap();
    assert!(r.get("modules").is_some());
}

// ==========================================================================
// Error handling
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn error_401_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/prod"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "errors": [{"status": "401", "title": "Unauthorized"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {"working_dir": "/code/prod"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/prod"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "errors": [{"status": "403", "title": "Forbidden"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {"working_dir": "/code/prod"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/gone"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "errors": [{"status": "404", "title": "Not found", "detail": "Workspace not found"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {"working_dir": "/code/gone"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_409_conflict() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/runs/run-locked/actions/apply"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "errors": [{"status": "409", "title": "Conflict", "detail": "Workspace locked"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.apply",
            "input": {"plan_file": "run-locked"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/prod"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "errors": [{"status": "429", "title": "Too many requests"}]
                }))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {"working_dir": "/code/prod"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/prod"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {"working_dir": "/code/prod"}
        }))
        .await
        .is_err()
    );
}

// ==========================================================================
// Unknown op / Simulate
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "terraform.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_op() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "terraform.init"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown_op() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "terraform.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_all_ops() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let ops = [
        "terraform.init", "terraform.validate", "terraform.plan",
        "terraform.show_plan", "terraform.apply", "terraform.destroy",
        "terraform.state_list", "terraform.state_show", "terraform.output",
        "terraform.import", "terraform.detect_drift", "terraform.list_modules",
    ];
    for op in &ops {
        let r = c
            .handle_simulate(json!({"operation_id": op}))
            .await
            .unwrap();
        assert!(r["allowed"].as_bool().unwrap(), "simulate should allow {op}");
    }
}

// ==========================================================================
// Counters
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn counters_increment_on_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/proj"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-c", "proj", "1.7.0")),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "terraform.init",
        "input": {"working_dir": "/code/proj"}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_increment_on_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/test-org/workspaces/proj"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {"working_dir": "/code/proj"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// ==========================================================================
// Custom organization override
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn init_with_custom_org() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/other-org/workspaces/proj"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(workspace_mock("ws-other", "proj", "1.7.0")),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let r = c
        .handle_invoke(json!({
            "operation_id": "terraform.init",
            "input": {"working_dir": "/code/proj", "organization": "other-org"}
        }))
        .await
        .unwrap();
    assert_eq!(r["initialized"], true);
    assert_eq!(r["workspace_id"], "ws-other");
}
