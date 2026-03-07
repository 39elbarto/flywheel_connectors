//! Integration tests for the FCP `Reddit` connector.

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

use fcp_reddit::connector::RedditConnector;

async fn setup_connector(mock_url: &str) -> RedditConnector {
    let mut c = RedditConnector::new();
    c.handle_configure(json!({ "bearer_token": "test-bearer-tok", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

fn listing_response(posts: &serde_json::Value, after: Option<&str>) -> serde_json::Value {
    let children: Vec<serde_json::Value> = posts
        .as_array()
        .unwrap()
        .iter()
        .map(|p| json!({"kind": "t3", "data": p}))
        .collect();
    json!({
        "data": {
            "children": children,
            "after": after
        }
    })
}

// ── Lifecycle ────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = RedditConnector::new();
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
    let mut c = RedditConnector::new();
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 9);
}

// ── Search Posts ─────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn search_posts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/r/rust/search.*"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([
                {"name": "t3_abc", "title": "Rust async"},
                {"name": "t3_def", "title": "Rust borrow checker"}
            ]),
            Some("t3_def"),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.search_posts",
            "input": {"query": "async", "subreddit": "rust", "limit": 25}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 2);
    assert_eq!(result["next_after"], "t3_def");
}

#[fcp_async_core::runtime::test]
async fn search_posts_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.search_posts", "input": {}}))
            .await
            .is_err()
    );
}

// ── List Subreddit New ───────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn list_subreddit_new() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/r/machinelearning/new.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([{"name": "t3_ml1", "title": "New ML paper"}]),
            None,
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.list_subreddit_new",
            "input": {"subreddit": "machinelearning"}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn list_subreddit_new_missing_subreddit() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.list_subreddit_new", "input": {}}))
            .await
            .is_err()
    );
}

// ── Get Post Thread ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn get_post_thread() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/comments/abc123.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"data": {"children": [{"kind": "t3", "data": {"name": "t3_abc123", "title": "Thread"}}]}},
            {"data": {"children": [{"kind": "t1", "data": {"name": "t1_c1", "body": "Great!"}}]}}
        ])))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.get_post_thread",
            "input": {"post_fullname": "t3_abc123"}
        }))
        .await
        .unwrap();
    assert!(result.get("post").is_some());
    assert!(result.get("comments").is_some());
}

#[fcp_async_core::runtime::test]
async fn get_post_thread_missing_fullname() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.get_post_thread", "input": {}}))
            .await
            .is_err()
    );
}

// ── Create Post ──────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn create_post() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "json": {"data": {"name": "t3_new123", "url": "/r/test/comments/new123/my_post/"}}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.create_post",
            "input": {"subreddit": "test", "kind": "self", "title": "My Post", "text": "Body here"}
        }))
        .await
        .unwrap();
    assert!(result.get("json").is_some());
}

#[fcp_async_core::runtime::test]
async fn create_post_missing_title() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "reddit.create_post", "input": {"subreddit": "test", "kind": "self"}})).await.is_err());
}

// ── Create Comment ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn create_comment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "json": {"data": {"things": [{"data": {"name": "t1_newcmt"}}]}}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.create_comment",
            "input": {"parent_fullname": "t3_abc123", "text": "Nice post!"}
        }))
        .await
        .unwrap();
    assert!(result.get("json").is_some());
}

#[fcp_async_core::runtime::test]
async fn create_comment_missing_text() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "reddit.create_comment", "input": {"parent_fullname": "t3_abc"}})
        )
        .await
        .is_err()
    );
}

// ── Send Message ─────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn send_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/compose"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"json": {"errors": []}})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.send_message",
            "input": {"recipient": "testuser", "subject": "Hello", "message": "Hi there"}
        }))
        .await
        .unwrap();
    assert!(result.get("json").is_some());
}

#[fcp_async_core::runtime::test]
async fn send_message_missing_recipient() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "reddit.send_message", "input": {"subject": "Hi", "message": "Yo"}})).await.is_err());
}

// ── Mod Remove ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn mod_remove() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/remove"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.mod_remove",
            "input": {"thing_fullname": "t1_xyz", "spam": false}
        }))
        .await
        .unwrap();
    assert_eq!(result["removed"], true);
}

#[fcp_async_core::runtime::test]
async fn mod_remove_missing_fullname() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.mod_remove", "input": {}}))
            .await
            .is_err()
    );
}

// ── Stream Subreddit New ─────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn stream_subreddit_new() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/r/agentflywheel/new.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([{"name": "t3_s1", "title": "Stream event"}]),
            Some("t3_s1"),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.stream_subreddit_new",
            "input": {"subreddit": "agentflywheel", "batch_limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["events"].as_array().unwrap().len(), 1);
    assert_eq!(result["next_checkpoint"], "t3_s1");
}

// ── Error handling ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "Unauthorized"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.search_posts", "input": {"query": "test"}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/comments.*"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "reddit.get_post_thread", "input": {"post_fullname": "t3_missing"}})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.search_posts", "input": {"query": "test"}}))
            .await
            .is_err()
    );
}

// ── Unknown op / Simulate ────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.nope", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "reddit.search_posts"}))
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
        !c.handle_simulate(json!({"operation_id": "reddit.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// ── Counters ─────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn counters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(&json!([]), None)))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({"operation_id": "reddit.search_posts", "input": {"query": "test"}}))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}
