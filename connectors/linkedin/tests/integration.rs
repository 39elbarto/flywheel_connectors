//! Integration tests for the FCP LinkedIn connector.

#![allow(clippy::doc_markdown)]

use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_linkedin::connector::LinkedInConnector;

async fn setup_connector(mock_url: &str) -> LinkedInConnector {
    let mut c = LinkedInConnector::new();
    c.handle_configure(json!({ "access_token": "AQVh_test_token_123", "base_url": mock_url }))
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
    let c = LinkedInConnector::new();
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
    let mut c = LinkedInConnector::new();
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 10);
}

// -- Verify X-Restli-Protocol-Version header --

#[fcp_async_core::runtime::test]
async fn restli_header_sent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("X-Restli-Protocol-Version", "2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "abc123",
            "localizedFirstName": "Jane",
            "localizedLastName": "Doe",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.profile.get",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "abc123");
}

// -- Bearer auth header --

#[fcp_async_core::runtime::test]
async fn bearer_auth_header_sent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer AQVh_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "abc123",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.profile.get",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "abc123");
}

// -- Profile Get --

#[fcp_async_core::runtime::test]
async fn profile_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "abc123",
            "localizedFirstName": "Jane",
            "localizedLastName": "Doe",
            "localizedHeadline": "Software Engineer",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.profile.get",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["localizedFirstName"], "Jane");
    assert_eq!(result["localizedLastName"], "Doe");
}

// -- Profile Get By ID --

#[fcp_async_core::runtime::test]
async fn profile_get_by_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/people/\(id:person_xyz\)"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "person_xyz",
            "localizedFirstName": "Bob",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.profile.get_by_id",
            "input": {"person_id": "person_xyz"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "person_xyz");
}

#[fcp_async_core::runtime::test]
async fn profile_get_by_id_missing_person_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.profile.get_by_id",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Connections List --

#[fcp_async_core::runtime::test]
async fn connections_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/connections.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "elements": [
                {"id": "conn_1", "firstName": "Alice"},
                {"id": "conn_2", "firstName": "Bob"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.connections.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["elements"].as_array().unwrap().len(), 2);
}

// -- Company Get --

#[fcp_async_core::runtime::test]
async fn company_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/company_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "company_123",
            "localizedName": "ACME Corp",
            "vanityName": "acme",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.company.get",
            "input": {"company_id": "company_123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["localizedName"], "ACME Corp");
}

#[fcp_async_core::runtime::test]
async fn company_get_missing_company_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.company.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Company Followers --

#[fcp_async_core::runtime::test]
async fn company_followers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/organizationalEntityFollowerStatistics.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "elements": [
                {"followerCounts": {"organicFollowerCount": 1500}}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.company.followers",
            "input": {"company_id": "company_123"}
        }))
        .await
        .unwrap();
    assert!(result["elements"].is_array());
}

#[fcp_async_core::runtime::test]
async fn company_followers_missing_company_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.company.followers",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Posts Create --

#[fcp_async_core::runtime::test]
async fn posts_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ugcPosts"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "urn:li:share:12345",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.posts.create",
            "input": {
                "author": "urn:li:person:abc123",
                "text": "Hello LinkedIn!"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "urn:li:share:12345");
}

#[fcp_async_core::runtime::test]
async fn posts_create_missing_author() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.posts.create",
            "input": {"text": "Hello"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn posts_create_missing_text() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.posts.create",
            "input": {"author": "urn:li:person:abc123"}
        }))
        .await
        .is_err()
    );
}

// -- Posts Delete --

#[fcp_async_core::runtime::test]
async fn posts_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"/ugcPosts/.*"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.posts.delete",
            "input": {"post_urn": "urn:li:share:12345"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn posts_delete_missing_post_urn() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.posts.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Posts Get --

#[fcp_async_core::runtime::test]
async fn posts_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/ugcPosts/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "urn:li:share:12345",
            "author": "urn:li:person:abc123",
            "lifecycleState": "PUBLISHED",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.posts.get",
            "input": {"post_urn": "urn:li:share:12345"}
        }))
        .await
        .unwrap();
    assert_eq!(result["lifecycleState"], "PUBLISHED");
}

#[fcp_async_core::runtime::test]
async fn posts_get_missing_post_urn() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.posts.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Analytics Shares --

#[fcp_async_core::runtime::test]
async fn analytics_shares() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/organizationalEntityShareStatistics.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "elements": [{
                "totalShareStatistics": {
                    "shareCount": 42,
                    "clickCount": 150,
                }
            }]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.analytics.shares",
            "input": {"share_urn": "urn:li:organization:12345"}
        }))
        .await
        .unwrap();
    assert!(result["elements"].is_array());
}

#[fcp_async_core::runtime::test]
async fn analytics_shares_missing_share_urn() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.analytics.shares",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Search Companies --

#[fcp_async_core::runtime::test]
async fn search_companies() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/search/blended.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "elements": [
                {"name": "ACME Corp"},
                {"name": "Beta Inc"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "linkedin.search.companies",
            "input": {"keywords": "technology"}
        }))
        .await
        .unwrap();
    assert_eq!(result["elements"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn search_companies_missing_keywords() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.search.companies",
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
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(401).set_body_json(
            json!({"message": "Invalid access token", "serviceErrorCode": 65601, "status": 401}),
        ))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.profile.get",
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
        .and(path("/me"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Forbidden", "status": 403})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.profile.get",
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
        .and(path("/organizations/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Organization not found", "status": 404})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.company.get",
            "input": {"company_id": "nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Rate limit exceeded", "status": 429}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.profile.get",
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
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "linkedin.profile.get",
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
            "operation_id": "linkedin.nope",
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
        c.handle_simulate(json!({"operation_id": "linkedin.profile.get"}))
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
        !c.handle_simulate(json!({"operation_id": "linkedin.nope"}))
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
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "test"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "linkedin.profile.get",
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
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "linkedin.profile.get",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- Health status transitions --

#[fcp_async_core::runtime::test]
async fn health_configured_but_not_handshaken() {
    let mut c = LinkedInConnector::new();
    c.handle_configure(json!({ "access_token": "tok" }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn self_check_unconfigured() {
    let c = LinkedInConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured() {
    let c = LinkedInConnector::new();
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "unhealthy");
}
