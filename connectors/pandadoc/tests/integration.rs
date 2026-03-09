//! Integration tests for the FCP `PandaDoc` connector.

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

use fcp_pandadoc::connector::PandaDocConnector;

async fn setup_connector(mock_url: &str) -> PandaDocConnector {
    let mut c = PandaDocConnector::new();
    c.handle_configure(json!({ "api_key": "test-api-key", "base_url": mock_url }))
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
    let c = PandaDocConnector::new();
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
    let mut c = PandaDocConnector::new();
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
        .and(path("/documents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
        .mount(&server)
        .await;
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

// -- Documents List --

#[fcp_async_core::runtime::test]
async fn documents_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/documents.*"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": "d1", "name": "NDA", "status": "document.draft"},
                {"id": "d2", "name": "Invoice", "status": "document.sent"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.documents.list",
            "input": {"status": "draft", "count": 20}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn documents_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/documents.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.documents.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["results"].as_array().unwrap().is_empty());
}

// -- Documents Get --

#[fcp_async_core::runtime::test]
async fn documents_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/documents/doc_abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "doc_abc123",
            "name": "Test NDA",
            "status": "document.draft",
            "date_created": "2026-03-01T00:00:00Z",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.documents.get",
            "input": {"document_id": "doc_abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "doc_abc123");
    assert_eq!(result["name"], "Test NDA");
}

#[fcp_async_core::runtime::test]
async fn documents_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Documents Create --

#[fcp_async_core::runtime::test]
async fn documents_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/documents"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "new_doc_123",
            "status": "document.uploaded",
            "name": "NDA for Acme",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.documents.create",
            "input": {
                "name": "NDA for Acme",
                "template_uuid": "tpl_abc123",
                "recipients": [{"email": "bob@acme.com", "role": "signer"}]
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new_doc_123");
}

#[fcp_async_core::runtime::test]
async fn documents_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.create",
            "input": {
                "template_uuid": "tpl_abc",
                "recipients": [{"email": "a@b.com"}]
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn documents_create_missing_template() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.create",
            "input": {
                "name": "Test",
                "recipients": [{"email": "a@b.com"}]
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn documents_create_missing_recipients() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.create",
            "input": {
                "name": "Test",
                "template_uuid": "tpl_abc"
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn documents_create_recipients_not_array() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.create",
            "input": {
                "name": "Test",
                "template_uuid": "tpl_abc",
                "recipients": "not_an_array"
            }
        }))
        .await
        .is_err()
    );
}

// -- Documents Send --

#[fcp_async_core::runtime::test]
async fn documents_send() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/documents/doc_abc/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "doc_abc",
            "status": "document.sent",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.documents.send",
            "input": {
                "document_id": "doc_abc",
                "message": "Please sign this NDA."
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["status"], "document.sent");
}

#[fcp_async_core::runtime::test]
async fn documents_send_without_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/documents/doc_abc/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "doc_abc",
            "status": "document.sent",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.documents.send",
            "input": {"document_id": "doc_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["status"], "document.sent");
}

#[fcp_async_core::runtime::test]
async fn documents_send_missing_document_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.send",
            "input": {"message": "Please sign"}
        }))
        .await
        .is_err()
    );
}

// -- Documents Delete --

#[fcp_async_core::runtime::test]
async fn documents_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/documents/doc_abc123"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.documents.delete",
            "input": {"document_id": "doc_abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn documents_delete_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Templates List --

#[fcp_async_core::runtime::test]
async fn templates_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/templates"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": "tpl_1", "name": "Standard NDA"},
                {"id": "tpl_2", "name": "Invoice Template"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.templates.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 2);
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/documents.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"detail": "Unauthorized"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.list",
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
        .and(path_regex("/documents.*"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"detail": "Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.list",
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
        .and(path_regex("/documents/.*"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"detail": "Document not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.get",
            "input": {"document_id": "missing_doc"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/documents.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"detail": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "pandadoc.documents.list",
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
            "operation_id": "pandadoc.nope",
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
        c.handle_simulate(json!({"operation_id": "pandadoc.documents.list"}))
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
        !c.handle_simulate(json!({"operation_id": "pandadoc.nope"}))
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
        .and(path_regex("/documents.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "pandadoc.documents.list",
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
        .and(path_regex("/documents.*"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"detail": "Internal error"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "pandadoc.documents.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
