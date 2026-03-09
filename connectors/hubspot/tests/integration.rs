//! Integration tests for the FCP `HubSpot` connector.
//!
//! Uses wiremock to simulate `HubSpot` API responses.

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
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_hubspot::connector::HubSpotConnector;

// ── Helper ───────────────────────────────────────────────────────────

async fn setup_connector(mock_url: &str) -> HubSpotConnector {
    let mut connector = HubSpotConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "pat-na1-test",
            "base_url": mock_url,
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({"session_id": "test-session"}))
        .await
        .unwrap();
    connector
}

// ── Lifecycle ────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = HubSpotConnector::new();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_and_health() {
    let server = MockServer::start().await;
    let mut c = HubSpotConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();

    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full_handshake() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = HubSpotConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_invoke_before_handshake_fails() {
    let server = MockServer::start().await;
    let mut c = HubSpotConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
    assert_eq!(check["connector_id"], "fcp.hubspot");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let doctor = c.handle_doctor().await.unwrap();
    assert_eq!(doctor["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 24);
}

// ── Contacts List ────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn contacts_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/crm/v3/objects/contacts.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": "1", "properties": {"email": "alice@example.com", "firstname": "Alice"}},
                {"id": "2", "properties": {"email": "bob@example.com", "firstname": "Bob"}}
            ],
            "paging": {"next": {"after": "cursor2"}}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.list",
            "input": {"limit": 50, "properties": ["email", "firstname"]}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 2);
}

// ── Contacts Get ─────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn contacts_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/crm/v3/objects/contacts/123.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "123",
            "properties": {"email": "alice@example.com", "firstname": "Alice"},
            "createdAt": "2026-01-01T00:00:00Z"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.get",
            "input": {"contact_id": "123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["contact"]["id"], "123");
}

#[fcp_async_core::runtime::test]
async fn contacts_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.get",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Contacts Create ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn contacts_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/crm/v3/objects/contacts"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "456",
            "properties": {"email": "new@example.com", "firstname": "New"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.create",
            "input": {"properties": {"email": "new@example.com", "firstname": "New"}}
        }))
        .await
        .unwrap();
    assert_eq!(result["contact"]["id"], "456");
}

#[fcp_async_core::runtime::test]
async fn contacts_create_missing_properties() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.create",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Contacts Update ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn contacts_update() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/crm/v3/objects/contacts/123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "123",
            "properties": {"phone": "+1-555-0100"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.update",
            "input": {"contact_id": "123", "properties": {"phone": "+1-555-0100"}}
        }))
        .await
        .unwrap();
    assert_eq!(result["contact"]["id"], "123");
}

// ── Contacts Delete ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn contacts_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/crm/v3/objects/contacts/123"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.delete",
            "input": {"contact_id": "123"}
        }))
        .await
        .unwrap();
    assert!(result["deleted"].as_bool().unwrap());
}

// ── Companies List ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn companies_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/crm/v3/objects/companies.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"id": "1", "properties": {"name": "Acme Corp"}}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.companies.list",
            "input": {"limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 1);
}

// ── Deals List ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn deals_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/crm/v3/objects/deals.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"id": "1", "properties": {"dealname": "Enterprise", "amount": "50000"}}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.deals.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 1);
}

// ── Deals Create ─────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn deals_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/crm/v3/objects/deals"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "789",
            "properties": {"dealname": "New Deal", "amount": "10000"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.deals.create",
            "input": {"properties": {"dealname": "New Deal", "amount": "10000"}}
        }))
        .await
        .unwrap();
    assert_eq!(result["deal"]["id"], "789");
}

#[fcp_async_core::runtime::test]
async fn deals_create_missing_properties() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.deals.create",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Pipelines List ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn pipelines_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/crm/v3/pipelines/deals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": "default", "label": "Sales Pipeline", "stages": [
                    {"id": "1", "label": "Qualification"},
                    {"id": "2", "label": "Closed Won"}
                ]}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.pipelines.list",
            "input": {"object_type": "deals"}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn pipelines_list_missing_object_type() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.pipelines.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Analytics Report ─────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn analytics_report() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/analytics/v2/reports"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"label": "Q1", "value": 50000}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.analytics.report",
            "input": {"report_type": "deal_forecast"}
        }))
        .await
        .unwrap();
    assert!(result["report"].is_object());
}

#[fcp_async_core::runtime::test]
async fn analytics_report_missing_type() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.analytics.report",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Events Stream ────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn events_stream() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/events/v3/events.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"eventType": "contact.propertyChange", "objectId": 123, "occurredAt": "2026-03-01T00:00:00Z"}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.events.stream",
            "input": {"object_types": ["contacts"]}
        }))
        .await
        .unwrap();
    assert!(result["events"].is_object());
}

// ── Error handling ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_401_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/crm/v3/objects/contacts.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "Invalid token", "status": "error"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/crm/v3/objects/contacts.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "10"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.contacts.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Unknown operation ────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "hubspot.nonexistent",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Simulate ─────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn simulate_known_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({"operation_id": "hubspot.contacts.list"}))
        .await
        .unwrap();
    assert!(result["allowed"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({"operation_id": "hubspot.nonexistent"}))
        .await
        .unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
}

// ── Counters ─────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/crm/v3/objects/contacts.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "hubspot.contacts.list",
        "input": {}
    }))
    .await
    .unwrap();

    let health = c.handle_health().await.unwrap();
    assert_eq!(health["requests"], 1);
    assert_eq!(health["errors"], 0);
}
