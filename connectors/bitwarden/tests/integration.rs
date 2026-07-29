//! Integration tests for the FCP `Bitwarden` connector.

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
use wiremock::matchers::{body_string_contains, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_bitwarden::connector::BitwardenConnector;

async fn setup_connector(mock_url: &str) -> BitwardenConnector {
    let mut c = BitwardenConnector::new();
    c.handle_configure(json!({ "access_token": "test-token", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

async fn setup_public_api_connector(mock_url: &str) -> BitwardenConnector {
    let mut c = BitwardenConnector::new();
    c.handle_configure(json!({
        "client_id": "organization.client-id",
        "client_secret": "client-secret",
        "organization_id": "org-1",
        "base_url": mock_url,
        "identity_url": format!("{mock_url}/connect/token")
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test-public-api"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = BitwardenConnector::new();
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
    let mut c = BitwardenConnector::new();
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
    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configured_not_handshaken() {
    let mut c = BitwardenConnector::new();
    c.handle_configure(json!({ "access_token": "tok" }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Collections List --

#[fcp_async_core::runtime::test]
async fn collections_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/collections"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "col-1", "name": "Engineering", "organizationId": "org-1"},
                {"id": "col-2", "name": "DevOps", "organizationId": "org-1"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
    assert_eq!(result["object"], "list");
}

#[fcp_async_core::runtime::test]
async fn collections_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn collections_list_public_api_client_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("scope=api.organization"))
        .and(body_string_contains("client_id=organization.client-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "public-api-token",
            "expires_in": 3600,
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/public/collections"))
        .and(header("Authorization", "Bearer public-api-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "col-public", "name": "Sandbox Collection", "organizationId": "org-1"}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_public_api_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
    assert_eq!(result["object"], "list");
}

#[fcp_async_core::runtime::test]
async fn public_api_client_credentials_reject_vault_item_operations() {
    let server = MockServer::start().await;
    let c = setup_public_api_connector(&server.uri()).await;
    let error = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.list",
            "input": {}
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Public API client credentials"));
}

// -- Items List --

#[fcp_async_core::runtime::test]
async fn items_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/list/object/items.*"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "item-1", "name": "GitHub Token", "type": 1},
                {"id": "item-2", "name": "SSH Key", "type": 2},
                {"id": "item-3", "name": "Credit Card", "type": 3},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn items_list_with_collection_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/list/object/items"))
        .and(query_param("collectionId", "col-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "item-1", "name": "Filtered Item"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.list",
            "input": {"collection_id": "col-1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn items_list_with_folder_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/list/object/items"))
        .and(query_param("folderId", "f-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "item-2", "name": "Folder Item"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.list",
            "input": {"folder_id": "f-1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

// -- Items Get --

#[fcp_async_core::runtime::test]
async fn items_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/object/item/item-1"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "item",
            "id": "item-1",
            "name": "GitHub Token",
            "type": 1,
            "login": {
                "username": "admin",
                "password": "super-secret",
                "totp": "JBSWY3DPEHPK3PXP",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.get",
            "input": {"item_id": "item-1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["item"]["id"], "item-1");
    assert_eq!(result["item"]["login"]["password"], "super-secret");
}

#[fcp_async_core::runtime::test]
async fn items_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.items.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Items Create --

#[fcp_async_core::runtime::test]
async fn items_create_login() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/object/item"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "item",
            "id": "new-item-1",
            "name": "New Login",
            "type": 1,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.create",
            "input": {
                "type": 1,
                "name": "New Login",
                "login": {"username": "user", "password": "pass"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new-item-1");
}

#[fcp_async_core::runtime::test]
async fn items_create_secure_note() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/object/item"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "item",
            "id": "new-item-2",
            "name": "Note",
            "type": 2,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.create",
            "input": {
                "type": 2,
                "name": "Note",
                "notes": "Secret info"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new-item-2");
    assert_eq!(result["type"], 2);
}

#[fcp_async_core::runtime::test]
async fn items_create_missing_type() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.items.create",
            "input": {"name": "No Type"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn items_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.items.create",
            "input": {"type": 1}
        }))
        .await
        .is_err()
    );
}

// -- Items Delete --

#[fcp_async_core::runtime::test]
async fn items_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/object/item/item-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.delete",
            "input": {"item_id": "item-1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn items_delete_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.items.delete",
            "input": {}
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
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "Unauthorized"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
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
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
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
        .and(path("/object/item/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.items.get",
            "input": {"item_id": "missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
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
        .and(path("/collections"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_200_empty_body_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/collections"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .is_ok()
    );
}

#[fcp_async_core::runtime::test]
async fn error_with_oauth_format() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Invalid credentials"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
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
            "operation_id": "bitwarden.nope",
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
        c.handle_simulate(json!({"operation_id": "bitwarden.collections.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_items_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "bitwarden.items.get"}))
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
        !c.handle_simulate(json!({"operation_id": "bitwarden.nope"}))
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
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "bitwarden.collections.list",
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
        .and(path("/collections"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
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
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}
