//! Twitter/X connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Twitter API v2.
//! No real API calls. Covers:
//! - Happy-path operations (user.me, user.get, tweet.get, tweet.search, tweet.create)
//! - Error taxonomy (401/403/429 -> FcpError mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use fcp_twitter::TwitterConnector;

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[cap])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken { raw: cose }
}

/// Mock the `/2/users/me` endpoint required by handshake.
async fn mount_get_me_mock(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/2/users/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "12345",
                "name": "Test Bot",
                "username": "test_bot_fcp"
            }
        })))
        .mount(mock_server)
        .await;
}

async fn setup_configure(connector: &mut TwitterConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "consumer_key": "test-ck",
            "consumer_secret": "test-cs",
            "access_token": "test-at",
            "access_token_secret": "test-ats",
            "bearer_token": "test-bt",
            "api_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_handshake(
    connector: &mut TwitterConnector,
    mock_server: &MockServer,
    caps: &[&str],
) -> Ed25519SigningKey {
    mount_get_me_mock(mock_server).await;

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn user_me_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.user.me.happy_path");
    let mock_server = MockServer::start().await;

    // get_me is called both during handshake and during invoke
    Mock::given(method("GET"))
        .and(path("/2/users/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "12345",
                "name": "Test Bot",
                "username": "test_bot_fcp"
            }
        })))
        .expect(2..)
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.me"]).await;
    let token = generate_valid_token(&signing_key, "twitter.user.me");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.me",
            "args": {},
            "capability_token": token
        }))
        .await
        .expect("user.me invoke should succeed");

    assert_eq!(result["user"]["username"], "test_bot_fcp");
}

#[fcp_async_core::runtime::test]
async fn user_get_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.user.get.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/users/67890"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "67890",
                "name": "Other User",
                "username": "other_user"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.get"]).await;
    let token = generate_valid_token(&signing_key, "twitter.user.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.get",
            "args": { "user_id": "67890" },
            "capability_token": token
        }))
        .await
        .expect("user.get invoke should succeed");

    assert_eq!(result["user"]["id"], "67890");
    assert_eq!(result["user"]["username"], "other_user");
}

#[fcp_async_core::runtime::test]
async fn tweet_get_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.get.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/tweets/111222333"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "111222333",
                "text": "Hello from FCP integration test!",
                "author_id": "12345"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.tweet.get"]).await;
    let token = generate_valid_token(&signing_key, "twitter.tweet.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.get",
            "args": { "tweet_id": "111222333" },
            "capability_token": token
        }))
        .await
        .expect("tweet.get invoke should succeed");

    assert_eq!(result["tweet"]["id"], "111222333");
    assert_eq!(result["tweet"]["text"], "Hello from FCP integration test!");
}

#[fcp_async_core::runtime::test]
async fn tweet_search_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.search.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/2/tweets/search/recent.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "t1",
                    "text": "Rust is great!",
                    "author_id": "u1"
                },
                {
                    "id": "t2",
                    "text": "Learning Rust today",
                    "author_id": "u2"
                }
            ],
            "meta": {
                "result_count": 2,
                "newest_id": "t1",
                "oldest_id": "t2"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.search"]).await;
    let token = generate_valid_token(&signing_key, "twitter.tweet.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.search",
            "args": { "query": "rust programming", "max_results": 10 },
            "capability_token": token
        }))
        .await
        .expect("tweet.search invoke should succeed");

    let tweets = result["tweets"].as_array().expect("tweets array");
    assert_eq!(tweets.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn tweet_create_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.create.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/2/tweets"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "data": {
                "id": "new-tweet-1",
                "text": "Hello world from FCP!"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.create"]).await;
    let token = generate_valid_token(&signing_key, "twitter.tweet.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.create",
            "args": { "text": "Hello world from FCP!" },
            "capability_token": token
        }))
        .await
        .expect("tweet.create invoke should succeed");

    assert_eq!(result["tweet"]["id"], "new-tweet-1");
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("twitter.error.unauthorized");
    let mock_server = MockServer::start().await;

    // Mount get_me for handshake (succeeds), then user.get fails with 401
    Mock::given(method("GET"))
        .and(path("/2/users/bad-id"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "title": "Unauthorized",
            "detail": "Invalid or expired token",
            "type": "about:blank",
            "status": 401
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.get"]).await;
    let token = generate_valid_token(&signing_key, "twitter.user.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.get",
            "args": { "user_id": "bad-id" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn rate_limited_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("twitter.error.rate_limited");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/2/tweets/search/recent.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "title": "Too Many Requests",
                    "detail": "Rate limit exceeded",
                    "type": "about:blank",
                    "status": 429
                }))
                .insert_header("retry-after", "1"),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    // Use max_attempts=0 in retry config to avoid retrying the 429
    connector
        .handle_configure(json!({
            "consumer_key": "test-ck",
            "consumer_secret": "test-cs",
            "access_token": "test-at",
            "access_token_secret": "test-ats",
            "bearer_token": "test-bt",
            "api_url": mock_server.uri(),
            "retry": { "max_attempts": 0 }
        }))
        .await
        .expect("configure should succeed");
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.search"]).await;
    let token = generate_valid_token(&signing_key, "twitter.tweet.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.search",
            "args": { "query": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_without_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.deny.not_configured");
    let connector = TwitterConnector::new();

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, "twitter.user.me");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.me",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("twitter.deny.wrong_capability");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    // Handshake grants twitter.tweet.search but we invoke twitter.user.me
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.search"]).await;
    let token = generate_valid_token(&signing_key, "twitter.tweet.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.me",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("twitter.deny.unknown_operation");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "twitter.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.nonexistent",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.health_not_configured");
    let connector = TwitterConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_ready");
}

#[fcp_async_core::runtime::test]
async fn health_configured() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.health_configured");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    // Twitter requires handshake (which calls get_me) to become "healthy"
    let _signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.me"]).await;
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.introspect");
    let connector = TwitterConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"twitter.user.me"));
    assert!(op_ids.contains(&"twitter.user.get"));
    assert!(op_ids.contains(&"twitter.tweet.get"));
    assert!(op_ids.contains(&"twitter.tweet.search"));
    assert!(op_ids.contains(&"twitter.tweet.create"));
    assert!(op_ids.contains(&"twitter.tweet.delete"));
    assert_eq!(ops.len(), 13);
}

#[fcp_async_core::runtime::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.shutdown");
    let mut connector = TwitterConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn user_get_missing_user_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.user_get_missing_id");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.get"]).await;
    let token = generate_valid_token(&signing_key, "twitter.user.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.get",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("user_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn tweet_search_missing_query_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.tweet_search_missing_query");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.search"]).await;
    let token = generate_valid_token(&signing_key, "twitter.tweet.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.search",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("query"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}
