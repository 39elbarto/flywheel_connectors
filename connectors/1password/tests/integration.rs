//! Integration tests for the FCP `1Password` connector.

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

use fcp_onepassword::connector::OnePasswordConnector;

async fn setup_connector(mock_url: &str) -> OnePasswordConnector {
    let mut c = OnePasswordConnector::new();
    c.handle_configure(json!({ "access_token": "test-token", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = OnePasswordConnector::new();
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
    let mut c = OnePasswordConnector::new();
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
async fn lifecycle_self_check_unconfigured() {
    let c = OnePasswordConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = OnePasswordConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = OnePasswordConnector::new();
    c.handle_configure(json!({ "access_token": "tok", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Vaults List -------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn vaults_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "vault-1", "name": "Personal", "type": "USER_CREATED"},
            {"id": "vault-2", "name": "Shared", "type": "USER_CREATED"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "1password.vaults.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["vaults"].as_array().unwrap().len(), 2);
    assert_eq!(result["vaults"][0]["name"], "Personal");
}

#[fcp_async_core::runtime::test]
async fn vaults_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "1password.vaults.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["vaults"].as_array().unwrap().is_empty());
}

// -- Items List --------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn items_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults/vault-1/items"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "item-1", "title": "AWS Credentials", "category": "API_CREDENTIAL"},
            {"id": "item-2", "title": "Database Login", "category": "LOGIN"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "1password.items.list",
            "input": {"vault_id": "vault-1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
    assert_eq!(result["items"][0]["title"], "AWS Credentials");
}

#[fcp_async_core::runtime::test]
async fn items_list_missing_vault_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Items Get ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn items_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults/vault-1/items/item-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "item-1",
            "title": "AWS Credentials",
            "category": "API_CREDENTIAL",
            "fields": [
                {"id": "access_key", "label": "access_key", "value": "AKIA..."},
                {"id": "secret_key", "label": "secret_key", "value": "wJal...", "type": "CONCEALED"}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "1password.items.get",
            "input": {"vault_id": "vault-1", "item_id": "item-1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["item"]["id"], "item-1");
    assert_eq!(result["item"]["fields"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn items_get_missing_vault_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.get",
            "input": {"item_id": "item-1"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn items_get_missing_item_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.get",
            "input": {"vault_id": "vault-1"}
        }))
        .await
        .is_err()
    );
}

// -- Items Create ------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn items_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/vaults/vault-1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new-item-1",
            "title": "Stripe Key",
            "category": "API_CREDENTIAL",
            "vault": {"id": "vault-1"},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "1password.items.create",
            "input": {
                "vault_id": "vault-1",
                "category": "API_CREDENTIAL",
                "title": "Stripe Key",
                "fields": [{"label": "api_key", "value": "sk_live_abc", "type": "CONCEALED"}]
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new-item-1");
}

#[fcp_async_core::runtime::test]
async fn items_create_missing_vault_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.create",
            "input": {"category": "LOGIN", "title": "Test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn items_create_missing_category() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.create",
            "input": {"vault_id": "vault-1", "title": "Test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn items_create_missing_title() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.create",
            "input": {"vault_id": "vault-1", "category": "LOGIN"}
        }))
        .await
        .is_err()
    );
}

// -- Items Delete ------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn items_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v1/vaults/vault-1/items/item-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "1password.items.delete",
            "input": {"vault_id": "vault-1", "item_id": "item-1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn items_delete_missing_vault_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.delete",
            "input": {"item_id": "item-1"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn items_delete_missing_item_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.delete",
            "input": {"vault_id": "vault-1"}
        }))
        .await
        .is_err()
    );
}

// -- Error handling ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"status": 401, "message": "Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.vaults.list",
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
        .and(path_regex("/v1/vaults/.*/items"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"status": 403, "message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.list",
            "input": {"vault_id": "vault-secret"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/v1/vaults/.*/items/.*"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"status": 404, "message": "Item not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.items.get",
            "input": {"vault_id": "vault-1", "item_id": "missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"status": 429, "message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.vaults.list",
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
        .and(path("/v1/vaults"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"status": 500, "message": "Internal server error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.vaults.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate ---------------------------------------------------

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "1password.nope",
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
        c.handle_simulate(json!({"operation_id": "1password.vaults.list"}))
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
        !c.handle_simulate(json!({"operation_id": "1password.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_each_known_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    for op in &[
        "1password.vaults.list",
        "1password.items.list",
        "1password.items.get",
        "1password.items.create",
        "1password.items.delete",
    ] {
        let res = c
            .handle_simulate(json!({"operation_id": op}))
            .await
            .unwrap();
        assert!(res["allowed"].as_bool().unwrap(), "op {op} should be allowed");
    }
}

// -- Counters ----------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "1password.vaults.list",
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
        .and(path("/v1/vaults"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"status": 500, "message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "1password.vaults.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "1password.vaults.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}
