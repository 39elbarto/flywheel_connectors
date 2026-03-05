//! Integration tests for the FCP `Salesforce` connector.

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

use fcp_salesforce::connector::SalesforceConnector;

/// API path prefix used by the `Salesforce` REST API.
const API: &str = "/services/data/v59.0";

async fn setup_connector(mock_url: &str) -> SalesforceConnector {
    let mut c = SalesforceConnector::new();
    c.handle_configure(json!({
        "access_token": "00Dxx0000001gEg!test_token",
        "base_url": mock_url
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[tokio::test]
async fn lifecycle_health_unconfigured() {
    let c = SalesforceConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = SalesforceConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[tokio::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(
        c.handle_health().await.unwrap()["status"],
        "unconfigured"
    );
}

#[tokio::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
}

#[tokio::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 13);
}

// -- Accounts Get --

#[tokio::test]
async fn accounts_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/sobjects/Account/001xx1.*")))
        .and(header("authorization", "Bearer 00Dxx0000001gEg!test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Id": "001xx1", "Name": "Acme Corp", "Industry": "Technology"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.accounts.get",
            "input": {"account_id": "001xx1", "fields": ["Name", "Industry"]}
        }))
        .await
        .unwrap();
    assert_eq!(result["account"]["Name"], "Acme Corp");
}

#[tokio::test]
async fn accounts_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.accounts.get", "input": {}}))
        .await
        .is_err());
}

// -- Accounts List --

#[tokio::test]
async fn accounts_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "totalSize": 2, "done": true,
            "records": [
                {"Id": "001xx1", "Name": "Acme"},
                {"Id": "001xx2", "Name": "Globex"}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.accounts.list",
            "input": {"limit": 50}
        }))
        .await
        .unwrap();
    assert_eq!(result["records"].as_array().unwrap().len(), 2);
    assert_eq!(result["total_size"], 2);
}

// -- Contacts List --

#[tokio::test]
async fn contacts_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "totalSize": 1, "done": true,
            "records": [{"Id": "003xx1", "FirstName": "Alice", "LastName": "Smith"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.contacts.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
}

// -- Contacts Create --

#[tokio::test]
async fn contacts_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/sobjects/Contact")))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "003xx000004TmiQ", "success": true, "errors": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.contacts.create",
            "input": {"last_name": "Smith", "first_name": "Alice", "email": "alice@example.com"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "003xx000004TmiQ");
}

#[tokio::test]
async fn contacts_create_missing_last_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({
            "operation_id": "salesforce.contacts.create",
            "input": {"first_name": "Alice"}
        }))
        .await
        .is_err());
}

// -- Contacts Delete --

#[tokio::test]
async fn contacts_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(format!("{API}/sobjects/Contact/003xx1")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.contacts.delete",
            "input": {"contact_id": "003xx1"}
        }))
        .await
        .unwrap();
    // 204 No Content returns empty JSON object
    assert!(result.is_object());
}

#[tokio::test]
async fn contacts_delete_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.contacts.delete", "input": {}}))
        .await
        .is_err());
}

// -- Leads List --

#[tokio::test]
async fn leads_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "totalSize": 1, "done": true,
            "records": [{"Id": "00Qxx1", "FirstName": "Bob", "Company": "Acme"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.leads.list",
            "input": {"limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
}

// -- Leads Convert --

#[tokio::test]
async fn leads_convert() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/actions/standard/convertLead")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accountId": "001xx1", "contactId": "003xx1", "opportunityId": "006xx1"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.leads.convert",
            "input": {"lead_id": "00Qxx1", "create_opportunity": true}
        }))
        .await
        .unwrap();
    assert_eq!(result["accountId"], "001xx1");
}

#[tokio::test]
async fn leads_convert_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.leads.convert", "input": {}}))
        .await
        .is_err());
}

// -- Opportunities List --

#[tokio::test]
async fn opportunities_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "totalSize": 1, "done": true,
            "records": [{"Id": "006xx1", "Name": "Big Deal", "StageName": "Prospecting"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.opportunities.list",
            "input": {"limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
}

// -- Opportunities Create --

#[tokio::test]
async fn opportunities_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/sobjects/Opportunity")))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "006xx2", "success": true, "errors": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.opportunities.create",
            "input": {
                "name": "Enterprise Deal",
                "stage_name": "Prospecting",
                "close_date": "2026-06-30",
                "amount": 50000
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "006xx2");
}

#[tokio::test]
async fn opportunities_create_missing_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    // Missing stage_name and close_date
    assert!(c
        .handle_invoke(json!({
            "operation_id": "salesforce.opportunities.create",
            "input": {"name": "Deal"}
        }))
        .await
        .is_err());
}

// -- Cases List --

#[tokio::test]
async fn cases_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "totalSize": 1, "done": true,
            "records": [{"Id": "500xx1", "Subject": "Login issue", "Status": "Open"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.cases.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
}

// -- Cases Create --

#[tokio::test]
async fn cases_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/sobjects/Case")))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "500xx2", "success": true, "errors": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.cases.create",
            "input": {"subject": "Login issue", "priority": "High"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "500xx2");
}

#[tokio::test]
async fn cases_create_missing_subject() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({
            "operation_id": "salesforce.cases.create",
            "input": {"priority": "High"}
        }))
        .await
        .is_err());
}

// -- SOQL Query --

#[tokio::test]
async fn soql_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "totalSize": 1, "done": true,
            "records": [{"Id": "001xx1", "Name": "Acme", "Amount": 50000}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.soql.query",
            "input": {"query": "SELECT Id, Name, Amount FROM Opportunity WHERE StageName = 'Closed Won' LIMIT 100"}
        }))
        .await
        .unwrap();
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
    assert_eq!(result["done"], true);
}

#[tokio::test]
async fn soql_query_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.soql.query", "input": {}}))
        .await
        .is_err());
}

// -- Reports Get --

#[tokio::test]
async fn reports_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/analytics/reports/00Oxx1.*")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "reportMetadata": {"id": "00Oxx1", "name": "Q1 Pipeline"},
            "factMap": {"T!T": {"rows": []}},
            "hasDetailedData": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "salesforce.reports.get",
            "input": {"report_id": "00Oxx1", "include_details": true}
        }))
        .await
        .unwrap();
    assert_eq!(result["reportMetadata"]["name"], "Q1 Pipeline");
}

#[tokio::test]
async fn reports_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.reports.get", "input": {}}))
        .await
        .is_err());
}

// -- Error Handling --

#[tokio::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!([{"message": "Session expired", "errorCode": "INVALID_SESSION_ID"}])),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.accounts.list", "input": {}}))
        .await
        .is_err());
}

#[tokio::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!([{"message": "Insufficient privileges", "errorCode": "INSUFFICIENT_ACCESS"}])),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.accounts.list", "input": {}}))
        .await
        .is_err());
}

#[tokio::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/sobjects/Account/.*")))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!([{"message": "Not Found", "errorCode": "NOT_FOUND"}])),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({
            "operation_id": "salesforce.accounts.get",
            "input": {"account_id": "nonexistent"}
        }))
        .await
        .is_err());
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!([{"message": "Request limit exceeded", "errorCode": "REQUEST_LIMIT_EXCEEDED"}]))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.accounts.list", "input": {}}))
        .await
        .is_err());
}

// -- Unknown Op / Simulate --

#[tokio::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_invoke(json!({"operation_id": "salesforce.nope", "input": {}}))
        .await
        .is_err());
}

#[tokio::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c
        .handle_simulate(json!({"operation_id": "salesforce.accounts.list"}))
        .await
        .unwrap()["allowed"]
        .as_bool()
        .unwrap());
}

#[tokio::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(!c
        .handle_simulate(json!({"operation_id": "salesforce.nope"}))
        .await
        .unwrap()["allowed"]
        .as_bool()
        .unwrap());
}

// -- Counters --

#[tokio::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "totalSize": 0, "done": true, "records": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({"operation_id": "salesforce.accounts.list", "input": {}}))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[tokio::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!("{API}/query.*")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "Internal error"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({"operation_id": "salesforce.accounts.list", "input": {}}))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- Config validation --

#[tokio::test]
async fn configure_missing_auth_fails() {
    let mut c = SalesforceConnector::new();
    assert!(c.handle_configure(json!({})).await.is_err());
}

#[tokio::test]
async fn configure_empty_token_fails() {
    let mut c = SalesforceConnector::new();
    assert!(c.handle_configure(json!({"access_token": ""})).await.is_err());
}
