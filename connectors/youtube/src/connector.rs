//! FCP YouTube Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::YouTubeClient, error::YouTubeError};

/// FCP YouTube Connector.
pub struct YouTubeConnector {
    base: Arc<BaseConnector>,
    client: Option<YouTubeClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl YouTubeConnector {
    /// Create a new YouTube connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("youtube"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let api_key =
            params
                .get("api_key")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let mut client = YouTubeClient::new(api_key).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("YouTube connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:youtube-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "youtube.search",
                    "Search for videos, channels, or playlists",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "max_results": { "type": "integer" },
                            "type": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" },
                            "total_results": { "type": "integer" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search YouTube for videos, channels, or playlists.".into(),
                        common_mistakes: vec![
                            "Search quota costs 100 units - use sparingly".into(),
                        ],
                        examples: vec![
                            r#"{"query": "rust programming tutorial", "max_results": 10, "type": "video"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("youtube.get_video")],
                    },
                ),
                op_info(
                    "youtube.get_video",
                    "Get video details by ID",
                    json!({
                        "type": "object",
                        "required": ["video_id"],
                        "properties": {
                            "video_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "video": { "type": "object" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get details about a specific video.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"video_id": "dQw4w9WgXcQ"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("youtube.search"),
                            CapabilityId::from_static("youtube.list_comments"),
                        ],
                    },
                ),
                op_info(
                    "youtube.get_channel",
                    "Get channel details",
                    json!({
                        "type": "object",
                        "required": ["channel_id"],
                        "properties": {
                            "channel_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "channel": { "type": "object" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get details about a YouTube channel.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"channel_id": "UCxxxxxxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("youtube.search")],
                    },
                ),
                op_info(
                    "youtube.list_playlist_items",
                    "List videos in a playlist",
                    json!({
                        "type": "object",
                        "required": ["playlist_id"],
                        "properties": {
                            "playlist_id": { "type": "string" },
                            "max_results": { "type": "integer" },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List videos in a playlist.".into(),
                        common_mistakes: vec![
                            "Not handling pagination for large playlists".into(),
                        ],
                        examples: vec![r#"{"playlist_id": "PLxxxxxxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("youtube.get_video")],
                    },
                ),
                op_info(
                    "youtube.list_comments",
                    "List comments on a video",
                    json!({
                        "type": "object",
                        "required": ["video_id"],
                        "properties": {
                            "video_id": { "type": "string" },
                            "max_results": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read comments on a video.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"video_id": "dQw4w9WgXcQ"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("youtube.get_video"),
                            CapabilityId::from_static("youtube.post_comment"),
                        ],
                    },
                ),
                op_info(
                    "youtube.post_comment",
                    "Post a comment on a video",
                    json!({
                        "type": "object",
                        "required": ["video_id", "text"],
                        "properties": {
                            "video_id": { "type": "string" },
                            "text": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "comment": { "type": "object" }
                        }
                    }),
                    "youtube.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Post a public comment on a YouTube video.".into(),
                        common_mistakes: vec![
                            "Comments are public and permanent".into(),
                        ],
                        examples: vec![
                            r#"{"video_id": "dQw4w9WgXcQ", "text": "Great video!"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("youtube.list_comments")],
                    },
                ),
                op_info(
                    "youtube.get_captions",
                    "Get available captions/subtitles for a video",
                    json!({
                        "type": "object",
                        "required": ["video_id"],
                        "properties": {
                            "video_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get available subtitles/captions for a video.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"video_id": "dQw4w9WgXcQ"}"#.into()],
                        related: vec![CapabilityId::from_static("youtube.get_video")],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        // Extract and verify capability token
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "youtube.search" => self.invoke_search(input).await,
            "youtube.get_video" => self.invoke_get_video(input).await,
            "youtube.get_channel" => self.invoke_get_channel(input).await,
            "youtube.list_playlist_items" => self.invoke_list_playlist_items(input).await,
            "youtube.list_comments" => self.invoke_list_comments(input).await,
            "youtube.post_comment" => self.invoke_post_comment(input).await,
            "youtube.get_captions" => self.invoke_get_captions(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_search(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let result_type = input.get("type").and_then(|v| v.as_str());

        let results = client
            .search(query, max_results, result_type)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let total_results = results
            .page_info
            .as_ref()
            .map_or(results.items.len() as u32, |p| p.total_results);

        Ok(json!({
            "items": results.items,
            "total_results": total_results
        }))
    }

    async fn invoke_get_video(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;

        let results = client
            .get_video(video_id)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let video = results
            .items
            .into_iter()
            .next()
            .ok_or(FcpError::ResourceNotFound {
                resource: format!("video:{video_id}"),
            })?;

        Ok(json!({ "video": video }))
    }

    async fn invoke_get_channel(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel_id = require_str(&input, "channel_id")?;

        let results = client
            .get_channel(channel_id)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let channel = results
            .items
            .into_iter()
            .next()
            .ok_or(FcpError::ResourceNotFound {
                resource: format!("channel:{channel_id}"),
            })?;

        Ok(json!({ "channel": channel }))
    }

    async fn invoke_list_playlist_items(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let playlist_id = require_str(&input, "playlist_id")?;
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let results = client
            .list_playlist_items(playlist_id, max_results, page_token)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({
            "items": results.items,
            "next_page_token": results.next_page_token
        }))
    }

    async fn invoke_list_comments(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let results = client
            .list_comments(video_id, max_results)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({ "items": results.items }))
    }

    async fn invoke_post_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;
        let text = require_str(&input, "text")?;

        let comment = client
            .post_comment(video_id, text)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({ "comment": comment }))
    }

    async fn invoke_get_captions(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;

        let results = client
            .get_captions(video_id)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({ "items": results.items }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("YouTube connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for YouTubeConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
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
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = YouTubeConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["youtube.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = YouTubeConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = YouTubeConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["youtube.get_video"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "youtube.get_video");

        let result = connector
            .handle_invoke(json!({
                "operation": "youtube.get_video",
                "input": { "video_id": "dQw4w9WgXcQ" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = YouTubeConnector::new();
        connector.client = Some(
            YouTubeClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["youtube.search"]
            }))
            .await
            .unwrap();

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
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = YouTubeConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"youtube.search"));
        assert!(op_ids.contains(&"youtube.get_video"));
        assert!(op_ids.contains(&"youtube.get_channel"));
        assert!(op_ids.contains(&"youtube.list_playlist_items"));
        assert!(op_ids.contains(&"youtube.list_comments"));
        assert!(op_ids.contains(&"youtube.post_comment"));
        assert!(op_ids.contains(&"youtube.get_captions"));
        assert_eq!(ops.len(), 7);
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
