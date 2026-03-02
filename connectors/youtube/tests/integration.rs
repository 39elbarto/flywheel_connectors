//! YouTube connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the YouTube Data API v3.
//! No real API calls. Covers:
//! - Happy-path operations (search, get_video, list_videos, get_channel, list_playlists, list_playlist_items,
//!   list_comments, post_comment, get_captions)
//! - Error taxonomy (401/403/404/429 -> FcpError mapping)
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
    matchers::{method, path_regex},
};

use fcp_youtube::connector::YouTubeConnector;

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

async fn setup_handshake(connector: &mut YouTubeConnector, caps: &[&str]) -> Ed25519SigningKey {
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

async fn setup_configure(connector: &mut YouTubeConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn search_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.search.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#searchListResponse",
            "etag": "abc123",
            "pageInfo": { "totalResults": 2, "resultsPerPage": 5 },
            "items": [
                {
                    "kind": "youtube#searchResult",
                    "etag": "e1",
                    "id": { "kind": "youtube#video", "videoId": "vid001" },
                    "snippet": {
                        "title": "Rust Tutorial",
                        "description": "Learn Rust programming",
                        "thumbnails": {}
                    }
                },
                {
                    "kind": "youtube#searchResult",
                    "etag": "e2",
                    "id": { "kind": "youtube#video", "videoId": "vid002" },
                    "snippet": {
                        "title": "Rust Advanced",
                        "description": "Advanced Rust topics",
                        "thumbnails": {}
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.search"]).await;
    let token = generate_valid_token(&signing_key, "youtube.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.search",
            "input": { "query": "rust programming", "max_results": 5, "type": "video" },
            "capability_token": token
        }))
        .await
        .expect("search invoke should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    assert_eq!(result["total_results"], 2);
}

#[fcp_async_core::runtime::test]
async fn get_video_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_video.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/videos.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#videoListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 1, "resultsPerPage": 1 },
            "items": [{
                "kind": "youtube#video",
                "etag": "def",
                "id": "dQw4w9WgXcQ",
                "snippet": {
                    "title": "Rick Astley - Never Gonna Give You Up",
                    "description": "Official music video",
                    "thumbnails": {}
                },
                "contentDetails": { "duration": "PT3M33S", "definition": "hd" },
                "statistics": { "viewCount": "1500000000", "likeCount": "15000000" }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let token = generate_valid_token(&signing_key, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": token
        }))
        .await
        .expect("get_video invoke should succeed");

    assert_eq!(result["video"]["id"], "dQw4w9WgXcQ");
    assert_eq!(
        result["video"]["snippet"]["title"],
        "Rick Astley - Never Gonna Give You Up"
    );
}

#[fcp_async_core::runtime::test]
async fn list_videos_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.list_videos.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/videos.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#videoListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 2, "resultsPerPage": 2 },
            "items": [
                {
                    "kind": "youtube#video",
                    "etag": "def1",
                    "id": "vid001",
                    "snippet": { "title": "Video 1", "description": "First", "thumbnails": {} }
                },
                {
                    "kind": "youtube#video",
                    "etag": "def2",
                    "id": "vid002",
                    "snippet": { "title": "Video 2", "description": "Second", "thumbnails": {} }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_videos"]).await;
    let token = generate_valid_token(&signing_key, "youtube.list_videos");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_videos",
            "input": { "video_ids": ["vid001", "vid002"] },
            "capability_token": token
        }))
        .await
        .expect("list_videos invoke should succeed");

    let videos = result["videos"].as_array().expect("videos array");
    assert_eq!(videos.len(), 2);
    assert_eq!(result["total_results"], 2);
}

#[fcp_async_core::runtime::test]
async fn get_channel_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_channel.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/channels.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#channelListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 1, "resultsPerPage": 1 },
            "items": [{
                "kind": "youtube#channel",
                "etag": "def",
                "id": "UCuAXFkgsw1L7xaCfnd5JJOw",
                "snippet": {
                    "title": "Rick Astley",
                    "description": "Official channel"
                },
                "statistics": { "subscriberCount": "5000000", "videoCount": "100" }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_channel"]).await;
    let token = generate_valid_token(&signing_key, "youtube.get_channel");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_channel",
            "input": { "channel_id": "UCuAXFkgsw1L7xaCfnd5JJOw" },
            "capability_token": token
        }))
        .await
        .expect("get_channel invoke should succeed");

    assert_eq!(result["channel"]["id"], "UCuAXFkgsw1L7xaCfnd5JJOw");
    assert_eq!(result["channel"]["snippet"]["title"], "Rick Astley");
}

#[fcp_async_core::runtime::test]
async fn list_playlists_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.list_playlists.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/playlists.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#playlistListResponse",
            "etag": "abc",
            "nextPageToken": "next-token",
            "pageInfo": { "totalResults": 2, "resultsPerPage": 2 },
            "items": [
                {
                    "kind": "youtube#playlist",
                    "etag": "pl1",
                    "id": "PL001",
                    "snippet": {
                        "channelId": "UCtest",
                        "title": "Playlist 1",
                        "description": "First playlist",
                        "thumbnails": {}
                    },
                    "contentDetails": { "itemCount": 10 }
                },
                {
                    "kind": "youtube#playlist",
                    "etag": "pl2",
                    "id": "PL002",
                    "snippet": {
                        "channelId": "UCtest",
                        "title": "Playlist 2",
                        "description": "Second playlist",
                        "thumbnails": {}
                    },
                    "contentDetails": { "itemCount": 8 }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_playlists"]).await;
    let token = generate_valid_token(&signing_key, "youtube.list_playlists");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_playlists",
            "input": { "channel_id": "UCtest", "max_results": 10 },
            "capability_token": token
        }))
        .await
        .expect("list_playlists invoke should succeed");

    let playlists = result["playlists"].as_array().expect("playlists array");
    assert_eq!(playlists.len(), 2);
    assert_eq!(result["next_page_token"], "next-token");
}

#[fcp_async_core::runtime::test]
async fn list_playlist_items_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.list_playlist_items.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/playlistItems.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#playlistItemListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 2, "resultsPerPage": 5 },
            "items": [
                {
                    "kind": "youtube#playlistItem",
                    "etag": "d1",
                    "id": "item1",
                    "snippet": { "title": "Video 1", "description": "First", "position": 0 },
                    "contentDetails": { "videoId": "vid1" }
                },
                {
                    "kind": "youtube#playlistItem",
                    "etag": "d2",
                    "id": "item2",
                    "snippet": { "title": "Video 2", "description": "Second", "position": 1 },
                    "contentDetails": { "videoId": "vid2" }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_playlist_items"]).await;
    let token = generate_valid_token(&signing_key, "youtube.list_playlist_items");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_playlist_items",
            "input": { "playlist_id": "PLtest123", "max_results": 5 },
            "capability_token": token
        }))
        .await
        .expect("list_playlist_items invoke should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn list_comments_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.list_comments.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/commentThreads.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#commentThreadListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 1, "resultsPerPage": 20 },
            "items": [{
                "kind": "youtube#commentThread",
                "etag": "def",
                "id": "ct1",
                "snippet": {
                    "videoId": "dQw4w9WgXcQ",
                    "topLevelComment": {
                        "id": "c1",
                        "snippet": {
                            "textDisplay": "Great video!",
                            "authorDisplayName": "TestUser",
                            "likeCount": 5
                        }
                    },
                    "totalReplyCount": 0
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_comments"]).await;
    let token = generate_valid_token(&signing_key, "youtube.list_comments");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_comments",
            "input": { "video_id": "dQw4w9WgXcQ", "max_results": 20 },
            "capability_token": token
        }))
        .await
        .expect("list_comments invoke should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn post_comment_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.post_comment.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/commentThreads.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "c-new-1",
            "snippet": {
                "textDisplay": "Great tutorial!",
                "authorDisplayName": "FCP Agent",
                "videoId": "dQw4w9WgXcQ",
                "likeCount": 0
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.post_comment"]).await;
    let token = generate_valid_token(&signing_key, "youtube.post_comment");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.post_comment",
            "input": { "video_id": "dQw4w9WgXcQ", "text": "Great tutorial!" },
            "capability_token": token
        }))
        .await
        .expect("post_comment invoke should succeed");

    assert!(result.get("comment").is_some());
}

#[fcp_async_core::runtime::test]
async fn get_captions_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_captions.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/captions.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#captionListResponse",
            "etag": "abc",
            "items": [{
                "kind": "youtube#caption",
                "etag": "def",
                "id": "cap1",
                "snippet": {
                    "videoId": "dQw4w9WgXcQ",
                    "language": "en",
                    "trackKind": "asr",
                    "name": "English (auto-generated)"
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_captions"]).await;
    let token = generate_valid_token(&signing_key, "youtube.get_captions");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_captions",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": token
        }))
        .await
        .expect("get_captions invoke should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("youtube.error.unauthorized");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/videos.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": 401,
                "message": "Invalid API key",
                "errors": [{ "reason": "authError", "domain": "global" }]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let token = generate_valid_token(&signing_key, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn not_found_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("youtube.error.not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/channels.*"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": 404,
                "message": "Channel not found",
                "errors": [{ "reason": "notFound", "domain": "youtube.channel" }]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_channel"]).await;
    let token = generate_valid_token(&signing_key, "youtube.get_channel");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_channel",
            "input": { "channel_id": "UCnonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn quota_exceeded_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("youtube.error.quota_exceeded");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": 403,
                "message": "Quota exceeded",
                "errors": [{ "reason": "quotaExceeded", "domain": "youtube.quota" }]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.search"]).await;
    let token = generate_valid_token(&signing_key, "youtube.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.search",
            "input": { "query": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn rate_limited_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("youtube.error.rate_limited");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/videos.*"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": {
                "code": 429,
                "message": "Rate limit exceeded"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let token = generate_valid_token(&signing_key, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
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
    let _ctx = AsyncTestContext::for_scenario("youtube.deny.not_configured");
    let mut connector = YouTubeConnector::new();
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let token = generate_valid_token(&signing_key, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::NotConfigured
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("youtube.deny.wrong_capability");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    // Handshake grants youtube.search but we invoke youtube.get_video
    let signing_key = setup_handshake(&mut connector, &["youtube.search"]).await;
    let token = generate_valid_token(&signing_key, "youtube.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("youtube.deny.unknown_operation");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "youtube.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.nonexistent",
            "input": {},
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
    let _ctx = AsyncTestContext::for_scenario("youtube.lifecycle.health_not_configured");
    let connector = YouTubeConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn health_configured() {
    let _ctx = AsyncTestContext::for_scenario("youtube.lifecycle.health_configured");
    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, "http://localhost:9999").await;
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("youtube.lifecycle.introspect");
    let connector = YouTubeConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"youtube.search"));
    assert!(op_ids.contains(&"youtube.get_video"));
    assert!(op_ids.contains(&"youtube.list_videos"));
    assert!(op_ids.contains(&"youtube.get_channel"));
    assert!(op_ids.contains(&"youtube.list_playlists"));
    assert!(op_ids.contains(&"youtube.list_playlist_items"));
    assert!(op_ids.contains(&"youtube.list_comments"));
    assert!(op_ids.contains(&"youtube.post_comment"));
    assert!(op_ids.contains(&"youtube.get_captions"));
    assert_eq!(ops.len(), 9);
}

#[fcp_async_core::runtime::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("youtube.lifecycle.shutdown");
    let connector = YouTubeConnector::new();
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
async fn search_missing_query_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.search_missing_query");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.search"]).await;
    let token = generate_valid_token(&signing_key, "youtube.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.search",
            "input": {},
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

#[fcp_async_core::runtime::test]
async fn get_video_missing_video_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.get_video_missing_id");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let token = generate_valid_token(&signing_key, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("video_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn list_videos_empty_video_ids_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.list_videos_empty_ids");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_videos"]).await;
    let token = generate_valid_token(&signing_key, "youtube.list_videos");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_videos",
            "input": { "video_ids": [] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("video_ids"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn list_playlists_missing_channel_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.list_playlists_missing_channel");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_playlists"]).await;
    let token = generate_valid_token(&signing_key, "youtube.list_playlists");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_playlists",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("channel_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn post_comment_missing_text_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.post_comment_missing_text");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.post_comment"]).await;
    let token = generate_valid_token(&signing_key, "youtube.post_comment");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.post_comment",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("text"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}
