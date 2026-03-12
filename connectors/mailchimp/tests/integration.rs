//! Integration tests for the FCP Mailchimp connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_mailchimp::connector::MailchimpConnector;

async fn setup_connector(mock_url: &str) -> MailchimpConnector {
    let mut c = MailchimpConnector::new();
    c.handle_configure(json!({ "api_key": "testkey123-us1", "base_url": mock_url }))
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
    let c = MailchimpConnector::new();
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
    let mut c = MailchimpConnector::new();
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

// -- Lists (Audiences) List --

#[fcp_async_core::runtime::test]
async fn lists_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lists"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lists": [
                {"id": "abc123", "name": "Newsletter"},
                {"id": "def456", "name": "Customers"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.lists.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["lists"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn lists_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lists": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.lists.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["lists"].as_array().unwrap().is_empty());
}

// -- Members List --

#[fcp_async_core::runtime::test]
async fn members_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lists/abc123/members"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "members": [
                {"id": "m1", "email_address": "user1@example.com", "status": "subscribed"},
                {"id": "m2", "email_address": "user2@example.com", "status": "unsubscribed"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.members.list",
            "input": {"list_id": "abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["members"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn members_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lists/abc123/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "members": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.members.list",
            "input": {"list_id": "abc123"}
        }))
        .await
        .unwrap();
    assert!(result["members"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn members_list_missing_list_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.members.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Members Delete --

#[fcp_async_core::runtime::test]
async fn members_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(
            "/lists/abc123/members/d41d8cd98f00b204e9800998ecf8427e",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.members.delete",
            "input": {
                "list_id": "abc123",
                "subscriber_hash": "d41d8cd98f00b204e9800998ecf8427e"
            }
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn members_delete_missing_list_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.members.delete",
            "input": {"subscriber_hash": "abc"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn members_delete_missing_subscriber_hash() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.members.delete",
            "input": {"list_id": "abc123"}
        }))
        .await
        .is_err()
    );
}

// -- Campaigns List --

#[fcp_async_core::runtime::test]
async fn campaigns_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/campaigns"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "campaigns": [
                {"id": "camp1", "type": "regular", "status": "sent"},
                {"id": "camp2", "type": "regular", "status": "draft"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.campaigns.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["campaigns"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn campaigns_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/campaigns"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "campaigns": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.campaigns.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["campaigns"].as_array().unwrap().is_empty());
}

// -- Campaigns Send --

#[fcp_async_core::runtime::test]
async fn campaigns_send() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/campaigns/camp1/actions/send"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.campaigns.send",
            "input": {"campaign_id": "camp1"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn campaigns_send_missing_campaign_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.campaigns.send",
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
        .and(path("/lists"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "type": "https://mailchimp.com/developer/marketing/docs/errors/",
            "title": "API Key Invalid",
            "status": 401,
            "detail": "Your API key may be invalid, or you've attempted to access the wrong datacenter.",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.lists.list",
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
        .and(path("/lists"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "title": "Forbidden",
            "status": 403,
            "detail": "You don't have permission to access this resource.",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.lists.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/lists/abc123/members/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "title": "Resource Not Found",
            "status": 404,
            "detail": "The requested resource could not be found.",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.members.delete",
            "input": {"list_id": "abc123", "subscriber_hash": "nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lists"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "title": "Too Many Requests",
                    "status": 429,
                    "detail": "You have exceeded the rate limit.",
                }))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.lists.list",
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
        .and(path("/campaigns"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mailchimp.campaigns.list",
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
            "operation_id": "mailchimp.nope",
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
        c.handle_simulate(json!({"operation_id": "mailchimp.lists.list"}))
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
        !c.handle_simulate(json!({"operation_id": "mailchimp.nope"}))
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
        .and(path("/lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"lists": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "mailchimp.lists.list",
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
        .and(path("/lists"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "mailchimp.lists.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
