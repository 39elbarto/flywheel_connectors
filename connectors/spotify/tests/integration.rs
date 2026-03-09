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

// ============================================================
// Lifecycle tests
// ============================================================

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = SpotifyConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
    assert_eq!(h["configured"], false);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], true);
    assert_eq!(h["requests"], 0);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = SpotifyConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
    assert_eq!(h["configured"], false);
    // session_id is not cleared by shutdown, but config is gone so status is unconfigured
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
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "healthy");
    let checks = doc["checks"].as_array().unwrap();
    assert!(checks.len() >= 3);
    for check in checks {
        assert!(check["passed"].as_bool().unwrap());
    }
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = SpotifyConnector::new();
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "unhealthy");
    let checks = doc["checks"].as_array().unwrap();
    let config_check = checks
        .iter()
        .find(|c| c["name"] == "configuration")
        .unwrap();
    assert_eq!(config_check["passed"], false);
    assert!(config_check["critical"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["connector_id"], "fcp.spotify");
    assert_eq!(intro["version"], "0.1.0");
    let ops = intro["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 42);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_all_ops_have_required_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().unwrap();
    for op in ops {
        assert!(op["id"].as_str().is_some(), "missing id in op");
        assert!(op["summary"].as_str().is_some(), "missing summary in op");
        assert!(
            op["capability"].as_str().is_some(),
            "missing capability in op"
        );
        assert!(
            op["risk_level"].as_str().is_some(),
            "missing risk_level in op"
        );
        assert!(
            op["safety_tier"].as_str().is_some(),
            "missing safety_tier in op"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_response_fields() {
    let server = MockServer::start().await;
    let mut c = SpotifyConnector::new();
    c.handle_configure(json!({ "access_token": "BQtoken", "base_url": server.uri() }))
        .await
        .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "sess-42"}))
        .await
        .unwrap();
    assert_eq!(hs["protocol_version"], "2.0");
    assert_eq!(hs["connector_id"], "fcp.spotify");
    assert_eq!(hs["connector_version"], "0.1.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "spotify.read"));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_reconfigure_after_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");

    // Reconfigure
    c.handle_configure(json!({ "access_token": "BQnew_token", "base_url": server.uri() }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "sess2"}))
        .await
        .unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "healthy");
}

// ============================================================
// Configuration validation
// ============================================================

#[fcp_async_core::runtime::test]
async fn configure_missing_auth() {
    let mut c = SpotifyConnector::new();
    assert!(c.handle_configure(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_empty_access_token() {
    let mut c = SpotifyConnector::new();
    assert!(
        c.handle_configure(json!({"access_token": ""}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configure_whitespace_access_token() {
    let mut c = SpotifyConnector::new();
    assert!(
        c.handle_configure(json!({"access_token": "   "}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configure_both_auth_methods() {
    let mut c = SpotifyConnector::new();
    assert!(
        c.handle_configure(json!({
            "access_token": "BQtoken",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configure_credential_id() {
    let mut c = SpotifyConnector::new();
    let result = c
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn configure_invalid_credential_id() {
    let mut c = SpotifyConnector::new();
    assert!(
        c.handle_configure(json!({"credential_id": "not-a-uuid"}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configure_non_string_credential_id() {
    let mut c = SpotifyConnector::new();
    assert!(
        c.handle_configure(json!({"credential_id": 12345}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configure_custom_base_url() {
    let server = MockServer::start().await;
    let mut c = SpotifyConnector::new();
    c.handle_configure(json!({
        "access_token": "BQtoken",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    // Health should show configured
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
}

// ============================================================
// Invoke before ready
// ============================================================

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = SpotifyConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.profile.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"input": {}})).await.is_err());
}

// ============================================================
// Profile Get
// ============================================================

#[fcp_async_core::runtime::test]
async fn profile_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer BQtest_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user123",
            "display_name": "Test User",
            "email": "test@example.com",
            "followers": {"total": 42},
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
    assert_eq!(result["profile"]["email"], "test@example.com");
}

// ============================================================
// Search
// ============================================================

#[fcp_async_core::runtime::test]
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
    assert!(result["results"]["tracks"].is_object());
}

#[fcp_async_core::runtime::test]
async fn search_albums() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("type", "album"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "albums": {
                "items": [{"id": "alb1", "name": "Thriller"}]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.search",
            "input": {"query": "thriller", "types": "album"}
        }))
        .await
        .unwrap();
    assert!(result["results"]["albums"].is_object());
}

#[fcp_async_core::runtime::test]
async fn search_defaults() {
    let server = MockServer::start().await;
    // Default type is "track", default limit is 20
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("type", "track"))
        .and(query_param("limit", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tracks": {"items": []}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.search",
            "input": {"query": "test"}
        }))
        .await
        .unwrap();
    assert!(result["results"].is_object());
}

#[fcp_async_core::runtime::test]
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

// ============================================================
// Typed Search
// ============================================================

#[fcp_async_core::runtime::test]
async fn search_tracks_typed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("type", "track"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tracks": {
                "items": [{"id": "t1", "name": "Bohemian Rhapsody"}]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.search.tracks",
            "input": {"query": "bohemian rhapsody", "limit": 10}
        }))
        .await
        .unwrap();
    assert!(result["results"].is_object());
    assert!(result["results"]["tracks"].is_object());
}

#[fcp_async_core::runtime::test]
async fn search_albums_typed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("type", "album"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "albums": {
                "items": [{"id": "alb1", "name": "A Night at the Opera"}]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.search.albums",
            "input": {"query": "a night at the opera", "limit": 10}
        }))
        .await
        .unwrap();
    assert!(result["results"].is_object());
    assert!(result["results"]["albums"].is_object());
}

// ============================================================
// Recommendations - Genre Seeds
// ============================================================

#[fcp_async_core::runtime::test]
async fn recommendations_genre_seeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/recommendations/available-genre-seeds"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "genres": ["acoustic", "alt-rock", "blues", "classical", "country"]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.recommendations.genres",
            "input": {}
        }))
        .await
        .unwrap();
    let genres = result["genres"].as_array().unwrap();
    assert_eq!(genres.len(), 5);
    assert_eq!(genres[0], "acoustic");
}

// ============================================================
// Podcasts - Shows & Episodes
// ============================================================

#[fcp_async_core::runtime::test]
async fn show_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shows/5CfCWKI5pZ28U0uOzXkDHe"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "5CfCWKI5pZ28U0uOzXkDHe",
            "name": "The Joe Rogan Experience",
            "publisher": "Joe Rogan",
            "total_episodes": 2000
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.show.get",
            "input": {"show_id": "5CfCWKI5pZ28U0uOzXkDHe"}
        }))
        .await
        .unwrap();
    assert_eq!(result["show"]["id"], "5CfCWKI5pZ28U0uOzXkDHe");
    assert_eq!(result["show"]["name"], "The Joe Rogan Experience");
}

#[fcp_async_core::runtime::test]
async fn show_episodes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shows/5CfCWKI5pZ28U0uOzXkDHe/episodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"id": "ep1", "name": "Episode 1"},
                {"id": "ep2", "name": "Episode 2"}
            ],
            "total": 100
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.show.episodes",
            "input": {"show_id": "5CfCWKI5pZ28U0uOzXkDHe", "limit": 20, "offset": 0}
        }))
        .await
        .unwrap();
    let items = result["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(result["total"], 100);
}

#[fcp_async_core::runtime::test]
async fn episode_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/episodes/512ojhOuo1ktJprKbVcKyQ"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "512ojhOuo1ktJprKbVcKyQ",
            "name": "AI and the Future",
            "duration_ms": 3600000,
            "show": {"id": "show123", "name": "Tech Talk"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.episode.get",
            "input": {"episode_id": "512ojhOuo1ktJprKbVcKyQ"}
        }))
        .await
        .unwrap();
    assert_eq!(result["episode"]["id"], "512ojhOuo1ktJprKbVcKyQ");
    assert_eq!(result["episode"]["name"], "AI and the Future");
}

// ============================================================
// Tracks Get
// ============================================================

#[fcp_async_core::runtime::test]
async fn tracks_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tracks/11dFghVXANMlKmJXsNCbNl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "11dFghVXANMlKmJXsNCbNl",
            "name": "Cut To The Feeling",
            "duration_ms": 207959,
            "explicit": false,
            "artists": [{"id": "a1", "name": "Carly Rae Jepsen"}],
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
    assert_eq!(result["track"]["duration_ms"], 207959);
}

#[fcp_async_core::runtime::test]
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

// ============================================================
// Albums Get
// ============================================================

#[fcp_async_core::runtime::test]
async fn albums_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/albums/4aawyAB9vmqN3uQ7FjRGTy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "4aawyAB9vmqN3uQ7FjRGTy",
            "name": "Kind of Blue",
            "release_date": "1959-08-17",
            "total_tracks": 5,
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
    assert_eq!(result["album"]["release_date"], "1959-08-17");
}

#[fcp_async_core::runtime::test]
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

// ============================================================
// Artists Get
// ============================================================

#[fcp_async_core::runtime::test]
async fn artists_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/artists/06HL4z0CvFAxyc27GXpf02"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "06HL4z0CvFAxyc27GXpf02",
            "name": "Taylor Swift",
            "followers": {"total": 100000000},
            "genres": ["pop", "country"],
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
    assert_eq!(result["artist"]["followers"]["total"], 100000000);
}

#[fcp_async_core::runtime::test]
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

// ============================================================
// Playlists Get
// ============================================================

#[fcp_async_core::runtime::test]
async fn playlists_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/playlists/37i9dQZF1DXcBWIGoYBM5M"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "37i9dQZF1DXcBWIGoYBM5M",
            "name": "Today's Top Hits",
            "description": "The biggest songs right now",
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
    assert_eq!(result["playlist"]["tracks"]["total"], 50);
}

#[fcp_async_core::runtime::test]
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

// ============================================================
// Playlists List
// ============================================================

#[fcp_async_core::runtime::test]
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
    assert_eq!(result["playlists"][0]["name"], "My Playlist");
}

#[fcp_async_core::runtime::test]
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

// ============================================================
// Recently Played
// ============================================================

#[fcp_async_core::runtime::test]
async fn recently_played() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/player/recently-played"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"track": {"id": "t1", "name": "Song 1"}, "played_at": "2026-03-01T12:00:00Z"},
                {"track": {"id": "t2", "name": "Song 2"}, "played_at": "2026-03-01T11:00:00Z"},
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

#[fcp_async_core::runtime::test]
async fn recently_played_default_limit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/player/recently-played"))
        .and(query_param("limit", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.player.recently_played",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["items"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn recently_played_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/player/recently-played"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.player.recently_played",
            "input": {"limit": 5}
        }))
        .await
        .unwrap();
    assert!(result["items"].as_array().unwrap().is_empty());
}

// ============================================================
// Top Items
// ============================================================

#[fcp_async_core::runtime::test]
async fn top_items_artists() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/top/artists"))
        .and(query_param("time_range", "medium_term"))
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

#[fcp_async_core::runtime::test]
async fn top_items_tracks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/top/tracks"))
        .and(query_param("time_range", "short_term"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"id": "t1", "name": "Track 1"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.top_items",
            "input": {"item_type": "tracks", "time_range": "short_term", "limit": 5}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn top_items_default_time_range() {
    let server = MockServer::start().await;
    // Default time_range is "medium_term", default limit is 20
    Mock::given(method("GET"))
        .and(path("/me/top/artists"))
        .and(query_param("time_range", "medium_term"))
        .and(query_param("limit", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.top_items",
            "input": {"item_type": "artists"}
        }))
        .await
        .unwrap();
    assert!(result["items"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
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

// ============================================================
// Recommendations
// ============================================================

#[fcp_async_core::runtime::test]
async fn recommendations_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/recommendations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tracks": [
                {"id": "t1", "name": "Rec 1"},
                {"id": "t2", "name": "Rec 2"},
                {"id": "t3", "name": "Rec 3"},
            ],
            "seeds": [{"id": "artist1", "type": "ARTIST"}]
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
    assert_eq!(result["tracks"][0]["name"], "Rec 1");
}

#[fcp_async_core::runtime::test]
async fn recommendations_empty_seeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/recommendations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tracks": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.recommendations.get",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["tracks"].as_array().unwrap().is_empty());
}

// ============================================================
// Error handling
// ============================================================

#[fcp_async_core::runtime::test]
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

#[fcp_async_core::runtime::test]
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

#[fcp_async_core::runtime::test]
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

#[fcp_async_core::runtime::test]
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

#[fcp_async_core::runtime::test]
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

#[fcp_async_core::runtime::test]
async fn error_502() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
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

#[fcp_async_core::runtime::test]
async fn error_empty_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    // Should still handle the error, even without a JSON body
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.profile.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_non_json_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/albums/badid"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Something went terribly wrong"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.albums.get",
            "input": {"album_id": "badid"}
        }))
        .await
        .is_err()
    );
}

// ============================================================
// Unknown op / Simulate
// ============================================================

#[fcp_async_core::runtime::test]
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

#[fcp_async_core::runtime::test]
async fn simulate_known_search() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let sim = c
        .handle_simulate(json!({"operation_id": "spotify.search"}))
        .await
        .unwrap();
    assert!(sim["allowed"].as_bool().unwrap());
    assert_eq!(sim["reason"], "Operation supported");
}

#[fcp_async_core::runtime::test]
async fn simulate_known_profile() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.profile.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_tracks() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.tracks.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_albums() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.albums.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_playlists_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.playlists.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_recommendations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.recommendations.get"}))
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
    let sim = c
        .handle_simulate(json!({"operation_id": "spotify.nope"}))
        .await
        .unwrap();
    assert!(!sim["allowed"].as_bool().unwrap());
    assert_eq!(sim["reason"], "Unknown operation");
}

#[fcp_async_core::runtime::test]
async fn simulate_empty_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let sim = c
        .handle_simulate(json!({"operation_id": ""}))
        .await
        .unwrap();
    assert!(!sim["allowed"].as_bool().unwrap());
}

// ============================================================
// Counters
// ============================================================

#[fcp_async_core::runtime::test]
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
            "operation_id": "spotify.profile.get",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "u1"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/me/playlists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "spotify.profile.get",
        "input": {}
    }))
    .await
    .unwrap();
    c.handle_invoke(json!({
        "operation_id": "spotify.playlists.list",
        "input": {}
    }))
    .await
    .unwrap();
    c.handle_invoke(json!({
        "operation_id": "spotify.profile.get",
        "input": {}
    }))
    .await
    .unwrap();

    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_mixed_success_and_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "u1"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/tracks/bad"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {"status": 404, "message": "Not found"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "spotify.profile.get",
        "input": {}
    }))
    .await
    .unwrap();
    let _ = c
        .handle_invoke(json!({
            "operation_id": "spotify.tracks.get",
            "input": {"track_id": "bad"}
        }))
        .await;

    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 2);
    assert_eq!(h["errors"], 1);
}

// ============================================================
// Health / Doctor edge cases
// ============================================================

#[fcp_async_core::runtime::test]
async fn health_degraded_after_configure_only() {
    let mut c = SpotifyConnector::new();
    c.handle_configure(json!({ "access_token": "BQtoken" }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn self_check_unconfigured() {
    let c = SpotifyConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn doctor_degraded_without_handshake() {
    let mut c = SpotifyConnector::new();
    c.handle_configure(json!({ "access_token": "BQtoken" }))
        .await
        .unwrap();
    let doc = c.handle_doctor().await.unwrap();
    // Configuration and client pass, but handshake fails (non-critical) => degraded
    assert_eq!(doc["status"], "degraded");
    let checks = doc["checks"].as_array().unwrap();
    let hs_check = checks.iter().find(|c| c["name"] == "handshake").unwrap();
    assert_eq!(hs_check["passed"], false);
    assert_eq!(hs_check["critical"], false);
}

// ============================================================
// Auth header verification
// ============================================================

#[fcp_async_core::runtime::test]
async fn auth_header_is_bearer() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer BQtest_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "u1"})))
        .expect(1)
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "spotify.profile.get",
        "input": {}
    }))
    .await
    .unwrap();
}

#[fcp_async_core::runtime::test]
async fn accept_header_is_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "u1"})))
        .expect(1)
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "spotify.profile.get",
        "input": {}
    }))
    .await
    .unwrap();
}

// ============================================================
// Response wrapping
// ============================================================

#[fcp_async_core::runtime::test]
async fn playlists_list_unwraps_items() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/playlists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{"id": "p1"}, {"id": "p2"}, {"id": "p3"}],
            "total": 3,
            "limit": 20,
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
    // The connector extracts "items" into "playlists"
    assert_eq!(result["playlists"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn recently_played_unwraps_items() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/player/recently-played"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{"track": {"id": "t1"}}],
            "cursors": {"after": "cursor123"},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.player.recently_played",
            "input": {"limit": 5}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn recommendations_unwraps_tracks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/recommendations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tracks": [{"id": "r1"}, {"id": "r2"}],
            "seeds": [{"id": "s1"}],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.recommendations.get",
            "input": {"seed_artists": "a1", "seed_genres": "pop"}
        }))
        .await
        .unwrap();
    // The connector extracts "tracks" only
    assert_eq!(result["tracks"].as_array().unwrap().len(), 2);
}

// ============================================================
// Empty response body from API (200 with empty body)
// ============================================================

#[fcp_async_core::runtime::test]
async fn empty_200_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
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
    // Empty body returns {} which wraps into {"profile": {}}
    assert!(result["profile"].is_object());
}

// ============================================================
// Playback Control
// ============================================================

#[fcp_async_core::runtime::test]
async fn playback_get_state() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/player"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_playing": true,
            "device": {"id": "dev1", "name": "My Speaker", "volume_percent": 50},
            "item": {"id": "t1", "name": "Track 1"},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.get_state",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["state"]["is_playing"].as_bool().unwrap());
    assert_eq!(result["state"]["device"]["name"], "My Speaker");
}

#[fcp_async_core::runtime::test]
async fn playback_devices() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/player/devices"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "devices": [
                {"id": "dev1", "name": "Laptop", "type": "Computer", "is_active": true},
                {"id": "dev2", "name": "Phone", "type": "Smartphone", "is_active": false},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.devices",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["devices"].as_array().unwrap().len(), 2);
    assert_eq!(result["devices"][0]["name"], "Laptop");
}

#[fcp_async_core::runtime::test]
async fn playback_play() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/player/play"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.play",
            "input": {"context_uri": "spotify:album:4aawyAB9vmqN3uQ7FjRGTy"}
        }))
        .await
        .unwrap();
    assert_eq!(result["started"], true);
}

#[fcp_async_core::runtime::test]
async fn playback_pause() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/player/pause"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.pause",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["paused"], true);
}

#[fcp_async_core::runtime::test]
async fn playback_skip_next() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/me/player/next"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.skip_next",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["skipped"], "next");
}

#[fcp_async_core::runtime::test]
async fn playback_skip_previous() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/me/player/previous"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.skip_previous",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["skipped"], "previous");
}

#[fcp_async_core::runtime::test]
async fn playback_seek() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/player/seek"))
        .and(query_param("position_ms", "30000"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.seek",
            "input": {"position_ms": 30000}
        }))
        .await
        .unwrap();
    assert_eq!(result["seeked_to_ms"], 30000);
}

#[fcp_async_core::runtime::test]
async fn playback_volume() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/player/volume"))
        .and(query_param("volume_percent", "75"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.volume",
            "input": {"volume_percent": 75}
        }))
        .await
        .unwrap();
    assert_eq!(result["volume_percent"], 75);
}

#[fcp_async_core::runtime::test]
async fn playback_shuffle() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/player/shuffle"))
        .and(query_param("state", "true"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.shuffle",
            "input": {"state": true}
        }))
        .await
        .unwrap();
    assert_eq!(result["shuffle"], true);
}

#[fcp_async_core::runtime::test]
async fn playback_repeat() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/player/repeat"))
        .and(query_param("state", "track"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.repeat",
            "input": {"state": "track"}
        }))
        .await
        .unwrap();
    assert_eq!(result["repeat"], "track");
}

#[fcp_async_core::runtime::test]
async fn playback_transfer() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/player"))
        .respond_with(ResponseTemplate::new(204).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playback.transfer",
            "input": {"device_id": "dev123", "play": true}
        }))
        .await
        .unwrap();
    assert_eq!(result["transferred"], true);
    assert_eq!(result["device_id"], "dev123");
}

#[fcp_async_core::runtime::test]
async fn playback_transfer_missing_device_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.playback.transfer",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ============================================================
// Library Management
// ============================================================

#[fcp_async_core::runtime::test]
async fn library_tracks_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/tracks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"track": {"id": "t1", "name": "Track 1"}},
                {"track": {"id": "t2", "name": "Track 2"}},
            ],
            "total": 100,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.library.tracks.list",
            "input": {"limit": 20, "offset": 0}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
    assert_eq!(result["total"], 100);
}

#[fcp_async_core::runtime::test]
async fn library_tracks_save() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/tracks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.library.tracks.save",
            "input": {"ids": ["t1", "t2"]}
        }))
        .await
        .unwrap();
    assert_eq!(result["saved"], true);
}

#[fcp_async_core::runtime::test]
async fn library_tracks_remove() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/me/tracks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.library.tracks.remove",
            "input": {"ids": ["t1"]}
        }))
        .await
        .unwrap();
    assert_eq!(result["removed"], true);
}

#[fcp_async_core::runtime::test]
async fn library_tracks_check() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/tracks/contains"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([true, false])),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.library.tracks.check",
            "input": {"ids": ["t1", "t2"]}
        }))
        .await
        .unwrap();
    let results = result["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0], true);
    assert_eq!(results[1], false);
}

#[fcp_async_core::runtime::test]
async fn library_albums_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/albums"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{"album": {"id": "a1", "name": "Kind of Blue"}}],
            "total": 50,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.library.albums.list",
            "input": {"limit": 10, "offset": 0}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
    assert_eq!(result["total"], 50);
}

#[fcp_async_core::runtime::test]
async fn library_albums_save() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/me/albums"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.library.albums.save",
            "input": {"ids": ["a1"]}
        }))
        .await
        .unwrap();
    assert_eq!(result["saved"], true);
}

#[fcp_async_core::runtime::test]
async fn library_albums_remove() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/me/albums"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.library.albums.remove",
            "input": {"ids": ["a1"]}
        }))
        .await
        .unwrap();
    assert_eq!(result["removed"], true);
}

#[fcp_async_core::runtime::test]
async fn library_tracks_save_missing_ids() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.library.tracks.save",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn library_tracks_remove_missing_ids() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.library.tracks.remove",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ============================================================
// Playlist CRUD
// ============================================================

#[fcp_async_core::runtime::test]
async fn playlist_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/users/user123/playlists"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "pl_new",
            "name": "My New Playlist",
            "public": false,
            "description": "A test playlist",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playlist.create",
            "input": {
                "user_id": "user123",
                "name": "My New Playlist",
                "public": false,
                "description": "A test playlist"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["playlist"]["id"], "pl_new");
    assert_eq!(result["playlist"]["name"], "My New Playlist");
}

#[fcp_async_core::runtime::test]
async fn playlist_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.playlist.create",
            "input": {"user_id": "user123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn playlist_update() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/playlists/pl123"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playlist.update",
            "input": {
                "playlist_id": "pl123",
                "name": "Renamed Playlist",
                "description": "Updated description"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["updated"], true);
}

#[fcp_async_core::runtime::test]
async fn playlist_tracks_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/playlists/pl123/tracks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"track": {"id": "t1", "name": "Song 1"}},
                {"track": {"id": "t2", "name": "Song 2"}},
            ],
            "total": 42,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playlist.tracks.list",
            "input": {"playlist_id": "pl123", "limit": 20, "offset": 0}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
    assert_eq!(result["total"], 42);
}

#[fcp_async_core::runtime::test]
async fn playlist_tracks_add() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/playlists/pl123/tracks"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "snapshot_id": "snap_abc123"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playlist.tracks.add",
            "input": {
                "playlist_id": "pl123",
                "uris": ["spotify:track:t1", "spotify:track:t2"]
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["snapshot_id"], "snap_abc123");
}

#[fcp_async_core::runtime::test]
async fn playlist_tracks_remove() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/playlists/pl123/tracks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "snapshot_id": "snap_def456"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "spotify.playlist.tracks.remove",
            "input": {
                "playlist_id": "pl123",
                "uris": ["spotify:track:t1"]
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["snapshot_id"], "snap_def456");
}

#[fcp_async_core::runtime::test]
async fn playlist_tracks_add_missing_uris() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.playlist.tracks.add",
            "input": {"playlist_id": "pl123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn playlist_tracks_remove_missing_playlist_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "spotify.playlist.tracks.remove",
            "input": {"uris": ["spotify:track:t1"]}
        }))
        .await
        .is_err()
    );
}

// ============================================================
// Simulate for new operations
// ============================================================

#[fcp_async_core::runtime::test]
async fn simulate_playback_play() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.playback.play"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_library_tracks_save() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.library.tracks.save"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_playlist_create() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "spotify.playlist.create"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}
