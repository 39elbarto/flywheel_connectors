//! Integration tests for the FCP `Spotify` connector.

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

use fcp_spotify::connector::SpotifyConnector;

async fn setup_connector(mock_url: &str) -> SpotifyConnector {
    let mut c = SpotifyConnector::new();
    c.handle_configure(json!({ "access_token": "BQtest_token_123", "base_url": mock_url }))
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
    let c = SpotifyConnector::new();
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
    let mut c = SpotifyConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[tokio::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 10);
}

// -- Profile Get --

#[tokio::test]
async fn profile_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer BQtest_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user123",
            "display_name": "Test User",
            "email": "test@example.com",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.profile.get",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["profile"]["id"], "user123");
    assert_eq!(result["profile"]["display_name"], "Test User");
}

// -- Search --

#[tokio::test]
async fn search_tracks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("type", "track"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tracks": {
                "items": [
                    {"id": "t1", "name": "Kind of Blue"},
                    {"id": "t2", "name": "Blue in Green"},
                ]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.search",
            "input": {"query": "kind of blue", "types": "track", "limit": 10}
        }))
        .await
        .unwrap();
    assert!(result["results"].is_object());
}

#[tokio::test]
async fn search_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.search",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tracks Get --

#[tokio::test]
async fn tracks_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tracks/11dFghVXANMlKmJXsNCbNl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "11dFghVXANMlKmJXsNCbNl",
            "name": "Cut To The Feeling",
            "duration_ms": 207959,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.tracks.get",
            "input": {"track_id": "11dFghVXANMlKmJXsNCbNl"}
        }))
        .await
        .unwrap();
    assert_eq!(result["track"]["id"], "11dFghVXANMlKmJXsNCbNl");
    assert_eq!(result["track"]["name"], "Cut To The Feeling");
}

#[tokio::test]
async fn tracks_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.tracks.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Albums Get --

#[tokio::test]
async fn albums_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/albums/4aawyAB9vmqN3uQ7FjRGTy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "4aawyAB9vmqN3uQ7FjRGTy",
            "name": "Kind of Blue",
            "release_date": "1959-08-17",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.albums.get",
            "input": {"album_id": "4aawyAB9vmqN3uQ7FjRGTy"}
        }))
        .await
        .unwrap();
    assert_eq!(result["album"]["name"], "Kind of Blue");
}

#[tokio::test]
async fn albums_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.albums.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Artists Get --

#[tokio::test]
async fn artists_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/artists/06HL4z0CvFAxyc27GXpf02"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "06HL4z0CvFAxyc27GXpf02",
            "name": "Taylor Swift",
            "followers": {"total": 100000000},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.artists.get",
            "input": {"artist_id": "06HL4z0CvFAxyc27GXpf02"}
        }))
        .await
        .unwrap();
    assert_eq!(result["artist"]["name"], "Taylor Swift");
}

#[tokio::test]
async fn artists_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.artists.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Playlists Get --

#[tokio::test]
async fn playlists_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/playlists/37i9dQZF1DXcBWIGoYBM5M"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "37i9dQZF1DXcBWIGoYBM5M",
            "name": "Today's Top Hits",
            "tracks": {"total": 50},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playlists.get",
            "input": {"playlist_id": "37i9dQZF1DXcBWIGoYBM5M"}
        }))
        .await
        .unwrap();
    assert_eq!(result["playlist"]["name"], "Today's Top Hits");
}

#[tokio::test]
async fn playlists_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.playlists.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Playlists List --

#[tokio::test]
async fn playlists_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/playlists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"id": "p1", "name": "My Playlist"},
                {"id": "p2", "name": "Chill Vibes"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playlists.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["playlists"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn playlists_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/playlists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playlists.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["playlists"].as_array().unwrap().is_empty());
}

// -- Recently Played --

#[tokio::test]
async fn recently_played() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/player/recently-played"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"track": {"id": "t1", "name": "Song 1"}},
                {"track": {"id": "t2", "name": "Song 2"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.player.recently_played",
            "input": {"limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
}

// -- Top Items --

#[tokio::test]
async fn top_items_artists() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/top/artists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"id": "a1", "name": "Artist 1"},
                {"id": "a2", "name": "Artist 2"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.top_items",
            "input": {"item_type": "artists", "time_range": "medium_term", "limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn top_items_missing_type() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.top_items",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Recommendations --

#[tokio::test]
async fn recommendations_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/recommendations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tracks": [
                {"id": "t1", "name": "Rec 1"},
                {"id": "t2", "name": "Rec 2"},
                {"id": "t3", "name": "Rec 3"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.recommendations.get",
            "input": {"seed_artists": "artist1", "seed_genres": "jazz", "limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["tracks"].as_array().unwrap().len(), 3);
}

// -- Error handling --

#[tokio::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {"status": 401, "message": "Invalid access token"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.profile.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {"status": 403, "message": "Insufficient client scope"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.profile.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tracks/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {"status": 404, "message": "Resource not found"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.tracks.get",
            "input": {"track_id": "nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "error": {"status": 429, "message": "API rate limit exceeded"}
                }))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.profile.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/playlists"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.playlists.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[tokio::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.search"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "spotify.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[tokio::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "u1"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "spotify.profile.get",
        "input": {}
    }))
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
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "spotify.profile.get",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- Health degraded --

#[tokio::test]
async fn health_degraded_after_configure_only() {
    let mut c = SpotifyConnector::new();
    c.handle_configure(json!({ "access_token": "BQtoken" }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Self check unconfigured --

#[tokio::test]
async fn self_check_unconfigured() {
    let c = SpotifyConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}
