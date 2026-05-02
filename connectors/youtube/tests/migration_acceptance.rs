//! Google migration acceptance suite for `YouTube`.
//!
//! Validates that the shared `fcp-google-discovery` substrate correctly
//! integrates with the `YouTube` connector.
//!
//! Required by bead `lszk.45.2.6`.

#![allow(clippy::too_many_lines)]

use fcp_prelude::FcpError;
use serde_json::json;

use fcp_youtube::{connector::YouTubeConnector, error::YouTubeError};

// ── Shared substrate auth integration ────────────────────────────────

#[fcp_async_core::runtime::test]
async fn youtube_configure_with_api_key_succeeds() {
    let mut connector = YouTubeConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "test-api-key-123",
        }))
        .await;
    assert!(
        result.is_ok(),
        "Configure with api_key should succeed: {:?}",
        result.err()
    );
    let value = result.unwrap();
    assert_eq!(value["status"], "configured");
}

#[fcp_async_core::runtime::test]
async fn youtube_configure_with_access_token_succeeds() {
    let mut connector = YouTubeConnector::new();
    let result = connector
        .handle_configure(json!({
            "access_token": "ya29.test-youtube-token",
        }))
        .await;
    assert!(
        result.is_ok(),
        "Configure with shared auth access_token should succeed: {:?}",
        result.err()
    );
    let value = result.unwrap();
    assert_eq!(value["status"], "configured");
}

#[fcp_async_core::runtime::test]
async fn youtube_configure_with_credential_id_succeeds() {
    let mut connector = YouTubeConnector::new();
    let cred_id = fcp_core::CredentialId::new();
    let result = connector
        .handle_configure(json!({
            "credential_id": cred_id.to_string(),
        }))
        .await;
    assert!(
        result.is_ok(),
        "Configure with credential_id should succeed: {:?}",
        result.err()
    );
}

// ── Introspection surface validation ─────────────────────────────────

#[fcp_async_core::runtime::test]
async fn youtube_introspect_has_required_operations() {
    let connector = YouTubeConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    let required = [
        "youtube.search",
        "youtube.get_video",
        "youtube.list_videos",
        "youtube.get_channel",
        "youtube.list_playlists",
        "youtube.list_playlist_items",
        "youtube.list_comments",
        "youtube.post_comment",
        "youtube.get_captions",
        "youtube.get_caption_transcript",
        "youtube.upload_caption",
        "youtube.get_analytics",
        "youtube.upload_video",
    ];

    for op in &required {
        assert!(
            op_ids.contains(op),
            "Missing required YouTube operation: {op}. Available: {op_ids:?}"
        );
    }

    assert_eq!(ops.len(), 13, "YouTube should have exactly 13 operations");
}

#[fcp_async_core::runtime::test]
async fn youtube_introspect_operations_have_capability() {
    let connector = YouTubeConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().expect("operations array");

    for op in ops {
        let id = op["id"].as_str().unwrap();
        let cap = op["capability"].as_str();
        assert!(cap.is_some(), "Operation {id} is missing capability field");
        let cap_val = cap.unwrap();
        assert!(
            cap_val == "youtube.read" || cap_val == "youtube.write",
            "Operation {id} has unexpected capability: {cap_val}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn youtube_write_operations_use_write_capability() {
    let connector = YouTubeConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();

    let write_ops = [
        "youtube.post_comment",
        "youtube.upload_caption",
        "youtube.upload_video",
    ];
    for op in ops {
        let id = op["id"].as_str().unwrap();
        if write_ops.contains(&id) {
            assert_eq!(
                op["capability"].as_str().unwrap(),
                "youtube.write",
                "Write operation {id} should use youtube.write capability"
            );
        }
    }
}

// ── Error taxonomy preserved ─────────────────────────────────────────

#[test]
fn youtube_error_unauthorized_maps_correctly() {
    let err = YouTubeError::Unauthorized;
    let fcp = err.to_fcp_error();
    assert!(
        matches!(fcp, FcpError::Unauthorized { .. }),
        "Unauthorized should map correctly, got {fcp:?}"
    );
}

#[test]
fn youtube_error_rate_limited_maps_correctly() {
    let err = YouTubeError::RateLimited {
        retry_after_ms: 60_000,
    };
    let fcp = err.to_fcp_error();
    assert!(
        matches!(fcp, FcpError::RateLimited { .. }),
        "RateLimited should map correctly, got {fcp:?}"
    );
}

#[test]
fn youtube_error_quota_exceeded_maps_correctly() {
    let err = YouTubeError::QuotaExceeded;
    let fcp = err.to_fcp_error();
    assert!(
        matches!(fcp, FcpError::RateLimited { .. }),
        "QuotaExceeded should map to RateLimited, got {fcp:?}"
    );
}

// ── Manifest parity ──────────────────────────────────────────────────

#[test]
fn youtube_manifest_is_parseable() {
    use fcp_manifest::ConnectorManifest;
    let manifest =
        ConnectorManifest::parse_str(include_str!("../manifest.toml")).expect("youtube manifest");
    assert!(!manifest.connector.name.is_empty());
    assert!(!manifest.provides.operations.is_empty());
}
