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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 22);
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

// ── Subreddit Get ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn subreddit_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/r/rust/about"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "t5",
            "data": {
                "display_name": "rust",
                "subscribers": 350000,
                "public_description": "A place for all things related to the Rust programming language.",
                "over18": false,
                "quarantine": false
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.subreddit.get",
            "input": {"subreddit": "rust"}
        }))
        .await
        .unwrap();
    assert!(result.get("data").is_some());
    assert_eq!(result["data"]["display_name"], "rust");
}

#[fcp_async_core::runtime::test]
async fn subreddit_get_missing_subreddit() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.subreddit.get", "input": {}}))
            .await
            .is_err()
    );
}

// ── Subreddit Search ────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn subreddit_search() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/subreddits/search.*"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([
                {"display_name": "rust", "subscribers": 350000},
                {"display_name": "rustjerk", "subscribers": 5000}
            ]),
            Some("t5_rustjerk"),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.subreddit.search",
            "input": {"query": "rust", "limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 2);
    assert_eq!(result["next_after"], "t5_rustjerk");
}

#[fcp_async_core::runtime::test]
async fn subreddit_search_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.subreddit.search", "input": {}}))
            .await
            .is_err()
    );
}

// ── User Posts ──────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn user_posts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/user/testuser/submitted.*"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([
                {"name": "t3_p1", "title": "My first post"},
                {"name": "t3_p2", "title": "My second post"}
            ]),
            Some("t3_p2"),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.user.posts",
            "input": {"username": "testuser", "limit": 10, "sort": "new"}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 2);
    assert_eq!(result["next_after"], "t3_p2");
}

#[fcp_async_core::runtime::test]
async fn user_posts_missing_username() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.user.posts", "input": {}}))
            .await
            .is_err()
    );
}

// ── User Comments ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn user_comments() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/user/testuser/comments.*"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([
                {"name": "t1_c1", "body": "First comment"},
                {"name": "t1_c2", "body": "Second comment"}
            ]),
            Some("t1_c2"),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.user.comments",
            "input": {"username": "testuser", "limit": 10, "sort": "top"}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 2);
    assert_eq!(result["next_after"], "t1_c2");
}

#[fcp_async_core::runtime::test]
async fn user_comments_missing_username() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.user.comments", "input": {}}))
            .await
            .is_err()
    );
}

// ── Edit Content ────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn edit_content() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/editusertext"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "json": {"data": {"things": [{"data": {"name": "t3_abc123", "body": "Updated text"}}]}}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.edit_content",
            "input": {"thing_fullname": "t3_abc123", "text": "Updated text"}
        }))
        .await
        .unwrap();
    assert!(result.get("json").is_some());
}

#[fcp_async_core::runtime::test]
async fn edit_content_missing_text() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "reddit.edit_content", "input": {"thing_fullname": "t3_abc"}})
        )
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn edit_content_missing_fullname() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "reddit.edit_content", "input": {"text": "new text"}})
        )
        .await
        .is_err()
    );
}

// ── Delete Content ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn delete_content() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/del"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.delete_content",
            "input": {"thing_fullname": "t1_xyz789"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn delete_content_missing_fullname() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.delete_content", "input": {}}))
            .await
            .is_err()
    );
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

// ── Saved List ──────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn saved_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/user/testuser/saved.*"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([
                {"name": "t3_saved1", "title": "Saved post"},
                {"name": "t1_saved2", "body": "Saved comment"}
            ]),
            Some("t1_saved2"),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.saved.list",
            "input": {"username": "testuser", "limit": 25}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 2);
    assert_eq!(result["next_after"], "t1_saved2");
}

#[fcp_async_core::runtime::test]
async fn saved_list_missing_username() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.saved.list", "input": {}}))
            .await
            .is_err()
    );
}

// ── Saved Save ──────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn saved_save() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/save"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.saved.save",
            "input": {"thing_fullname": "t3_abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["saved"], true);
}

#[fcp_async_core::runtime::test]
async fn saved_save_missing_fullname() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.saved.save", "input": {}}))
            .await
            .is_err()
    );
}

// ── Saved Unsave ────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn saved_unsave() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/unsave"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.saved.unsave",
            "input": {"thing_fullname": "t3_abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["unsaved"], true);
}

#[fcp_async_core::runtime::test]
async fn saved_unsave_missing_fullname() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.saved.unsave", "input": {}}))
            .await
            .is_err()
    );
}

// ── Mod Queue ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn mod_queue() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/r/rust/about/modqueue.*"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([
                {"name": "t3_flagged1", "title": "Flagged post"},
                {"name": "t1_flagged2", "body": "Flagged comment"}
            ]),
            Some("t1_flagged2"),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.mod.queue",
            "input": {"subreddit": "rust", "limit": 25}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 2);
    assert_eq!(result["next_after"], "t1_flagged2");
}

#[fcp_async_core::runtime::test]
async fn mod_queue_missing_subreddit() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.mod.queue", "input": {}}))
            .await
            .is_err()
    );
}

// ── Mod Approve ─────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn mod_approve() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/approve"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.mod.approve",
            "input": {"thing_fullname": "t3_flagged1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["approved"], true);
}

#[fcp_async_core::runtime::test]
async fn mod_approve_missing_fullname() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.mod.approve", "input": {}}))
            .await
            .is_err()
    );
}

// ── Inbox List ──────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn inbox_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/message/unread.*"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([
                {"name": "t4_msg1", "subject": "Hello", "body": "Hi there"},
                {"name": "t4_msg2", "subject": "Re: Hello", "body": "Thanks"}
            ]),
            Some("t4_msg2"),
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.inbox.list",
            "input": {"category": "unread", "limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 2);
    assert_eq!(result["next_after"], "t4_msg2");
}

#[fcp_async_core::runtime::test]
async fn inbox_list_default_category() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/message/inbox.*"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing_response(
            &json!([{"name": "t4_msg1", "subject": "Test"}]),
            None,
        )))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.inbox.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["posts"].as_array().unwrap().len(), 1);
}

// ── Inbox Mark Read ─────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn inbox_mark_read() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/read_message"))
        .and(header("Authorization", "Bearer test-bearer-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "reddit.inbox.mark_read",
            "input": {"fullnames": ["t4_msg1", "t4_msg2"]}
        }))
        .await
        .unwrap();
    assert_eq!(result["marked_read"], true);
}

#[fcp_async_core::runtime::test]
async fn inbox_mark_read_missing_fullnames() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "reddit.inbox.mark_read", "input": {}}))
            .await
            .is_err()
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
