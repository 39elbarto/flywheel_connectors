//! Integration tests for the FCP `SendGrid` connector.

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
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_sendgrid::connector::SendGridConnector;

async fn setup_connector(mock_url: &str) -> SendGridConnector {
    let mut c = SendGridConnector::new();
    c.handle_configure(json!({ "api_key": "SG.test_key_123", "base_url": mock_url }))
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
    let c = SendGridConnector::new();
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
    let mut c = SendGridConnector::new();
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
    assert!(check.get("details").is_some());
    let prov = &check["details"]["provisioning"];
    assert_eq!(prov["auth_mode"], "api_key");
    assert_eq!(prov["api_key_configured"], true);
    assert!(prov["network_ok"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = SendGridConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 10);
}

// -- Mail Send (202 empty body) --

#[fcp_async_core::runtime::test]
async fn mail_send() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mail/send"))
        .and(header("Authorization", "Bearer SG.test_key_123"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.mail.send",
            "input": {
                "personalizations": [{"to": [{"email": "bob@example.com"}]}],
                "from": {"email": "noreply@myapp.com"},
                "subject": "Hello",
                "content": [{"type": "text/plain", "value": "Hi Bob!"}]
            }
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn mail_send_missing_personalizations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.mail.send",
            "input": {
                "from": {"email": "noreply@myapp.com"},
                "subject": "Hello"
            }
        }))
        .await
        .is_err()
    );
}

// -- Contacts List --

#[fcp_async_core::runtime::test]
async fn contacts_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/marketing/contacts"))
        .and(header("Authorization", "Bearer SG.test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                {"id": "c1", "email": "alice@example.com", "first_name": "Alice"},
                {"id": "c2", "email": "bob@example.com", "first_name": "Bob"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.contacts.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["contacts"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn contacts_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/marketing/contacts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.contacts.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["contacts"].as_array().unwrap().is_empty());
}

// -- Contacts Search --

#[fcp_async_core::runtime::test]
async fn contacts_search() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/marketing/contacts/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                {"id": "c1", "email": "alice@example.com"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.contacts.search",
            "input": {"query": "email LIKE 'alice%'"}
        }))
        .await
        .unwrap();
    assert_eq!(result["contacts"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn contacts_search_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.contacts.search",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Contacts Get --

#[fcp_async_core::runtime::test]
async fn contacts_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/marketing/contacts/contact_abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "contact_abc123",
            "email": "alice@example.com",
            "first_name": "Alice",
            "last_name": "Smith",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.contacts.get",
            "input": {"contact_id": "contact_abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["email"], "alice@example.com");
}

#[fcp_async_core::runtime::test]
async fn contacts_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.contacts.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Lists List --

#[fcp_async_core::runtime::test]
async fn lists_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/marketing/lists"))
        .and(header("Authorization", "Bearer SG.test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                {"id": "l1", "name": "Newsletter", "contact_count": 1000},
                {"id": "l2", "name": "VIP", "contact_count": 50},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.lists.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["lists"].as_array().unwrap().len(), 2);
}

// -- Lists Create --

#[fcp_async_core::runtime::test]
async fn lists_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/marketing/lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new_list_123",
            "name": "Beta Testers",
            "contact_count": 0,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.lists.create",
            "input": {"name": "Beta Testers"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new_list_123");
}

#[fcp_async_core::runtime::test]
async fn lists_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.lists.create",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Lists Delete --

#[fcp_async_core::runtime::test]
async fn lists_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/marketing/lists/list_abc"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.lists.delete",
            "input": {"list_id": "list_abc"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn lists_delete_missing_list_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.lists.delete",
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
        .and(query_param("generations", "dynamic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "templates": [
                {"id": "d-abc", "name": "Welcome", "generation": "dynamic"},
                {"id": "d-def", "name": "Invoice", "generation": "dynamic"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.templates.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["templates"].as_array().unwrap().len(), 2);
}

// -- Templates Get --

#[fcp_async_core::runtime::test]
async fn templates_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/templates/d-abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "d-abc123",
            "name": "Welcome Email",
            "generation": "dynamic",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.templates.get",
            "input": {"template_id": "d-abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["name"], "Welcome Email");
}

#[fcp_async_core::runtime::test]
async fn templates_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.templates.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Stats Get --

#[fcp_async_core::runtime::test]
async fn stats_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stats"))
        .and(query_param("start_date", "2026-01-01"))
        .and(query_param("end_date", "2026-01-31"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"date": "2026-01-01", "stats": [{"metrics": {"requests": 100, "delivered": 95}}]},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.stats.get",
            "input": {"start_date": "2026-01-01", "end_date": "2026-01-31"}
        }))
        .await
        .unwrap();
    assert!(result.get("stats").is_some());
}

#[fcp_async_core::runtime::test]
async fn stats_get_missing_start_date() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.stats.get",
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
        .and(path("/marketing/contacts"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"errors": [{"message": "Authorization required"}]})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.contacts.list",
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
        .and(path("/marketing/contacts"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"errors": [{"message": "Forbidden"}]})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.contacts.list",
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
        .and(path("/marketing/contacts/missing_id"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"errors": [{"message": "Contact not found"}]})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.contacts.get",
            "input": {"contact_id": "missing_id"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/marketing/contacts"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"errors": [{"message": "Rate limit exceeded"}]}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.contacts.list",
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
        .and(path("/marketing/lists"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "sendgrid.lists.list",
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
            "operation_id": "sendgrid.nope",
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
        c.handle_simulate(json!({"operation_id": "sendgrid.mail.send"}))
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
        !c.handle_simulate(json!({"operation_id": "sendgrid.nope"}))
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
        .and(path("/marketing/contacts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "sendgrid.contacts.list",
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
        .and(path("/marketing/contacts"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.contacts.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- Auth header verification --

#[fcp_async_core::runtime::test]
async fn bearer_auth_header_sent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/marketing/contacts"))
        .and(header("Authorization", "Bearer SG.test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": []})))
        .expect(1)
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "sendgrid.contacts.list",
        "input": {}
    }))
    .await
    .unwrap();
    // Mock expectation verifies the header was sent
}

// -- Stats without end_date --

#[fcp_async_core::runtime::test]
async fn stats_get_without_end_date() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stats"))
        .and(query_param("start_date", "2026-03-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"date": "2026-03-01", "stats": [{"metrics": {"requests": 50}}]},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "sendgrid.stats.get",
            "input": {"start_date": "2026-03-01"}
        }))
        .await
        .unwrap();
    assert!(result.get("stats").is_some());
}
