//! FCP YouTube Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use fcp_google_discovery::{ServiceAliasRegistry, auth::GoogleAuthSelection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, YouTubeAuth, YouTubeClient},
    error::YouTubeError,
};

/// Parsed and validated YouTube connector configuration.
#[derive(Debug, Clone)]
struct YouTubeConfig {
    auth: YouTubeAuth,
    base_url: String,
    service_identity: String,
}

impl YouTubeConfig {
    async fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let service_selector = params
            .get("service_selector")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("youtube");
        let service = ServiceAliasRegistry::default()
            .resolve(service_selector)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid service_selector: {error}"),
            })?;
        if service.api_name != "youtube" || service.api_version != "v3" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "service_selector must resolve to youtube:v3 (got {})",
                    service.identity()
                ),
            });
        }

        let api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let shared_auth_fields_present = [
            "credential_id",
            "access_token",
            "refresh_token",
            "client_id",
            "client_secret",
            "credentials_file",
            "encrypted_local_credentials_profile",
            "use_default_credentials",
            "use_application_default_credentials",
        ]
        .iter()
        .any(|field| params.get(*field).is_some());

        let auth = if let Some(key) = api_key {
            if shared_auth_fields_present {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or shared Google auth source".into(),
                });
            }
            YouTubeAuth::ApiKey(key)
        } else {
            let selection =
                GoogleAuthSelection::from_connector_config(params).map_err(|error| {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid Google auth configuration: {error}"),
                    }
                })?;
            let materialized =
                selection
                    .materialize()
                    .await
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Failed to materialize Google auth source: {error}"),
                    })?;
            YouTubeAuth::GoogleShared(materialized)
        };

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self {
            auth,
            base_url,
            service_identity: service.identity(),
        })
    }
}

// ── Doctor types ─────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    #[serde(rename = "overall")]
    status: DoctorStatus,
    #[serde(rename = "checks")]
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

impl DoctorResult {
    /// Derive overall status from individual checks.
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP YouTube Connector.
pub struct YouTubeConnector {
    base: Arc<BaseConnector>,
    config: Option<YouTubeConfig>,
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
            config: None,
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
        let config = YouTubeConfig::from_params(&params).await?;

        let mut client =
            YouTubeClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if config.base_url != DEFAULT_BASE_URL {
            client = client.with_base_url(&config.base_url);
        }

        info!(auth = %config.auth.redacted_label(), "YouTube connector configured");

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

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
        let mut result = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            result["auth"] = json!(config.auth.redacted_label());
            result["base_url"] = json!(config.base_url);
            result["service"] = json!(config.service_identity);
        }
        Ok(result)
    }

    /// Handle doctor readiness checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // 1. Configuration check
        checks.push(DoctorCheck {
            name: "configuration".into(),
            status: if self.config.is_some() {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Unhealthy
            },
            message: if self.config.is_some() {
                "Connector is configured".into()
            } else {
                "Connector not configured — call configure first".into()
            },
        });

        let Some(config) = self.config.as_ref() else {
            return DoctorResult::from_checks(checks);
        };

        // 2. Client initialized
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            status: if self.client.is_some() {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Unhealthy
            },
            message: if self.client.is_some() {
                "HTTP client is ready".into()
            } else {
                "HTTP client not initialized".into()
            },
        });

        // 3. Base URL
        checks.push(DoctorCheck {
            name: "base_url".into(),
            status: DoctorStatus::Healthy,
            message: format!("base_url={}", config.base_url),
        });

        // 4. Auth mode
        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            status: DoctorStatus::Healthy,
            message: format!("auth={}", config.auth.redacted_label()),
        });

        // 5. Discovery service binding
        checks.push(DoctorCheck {
            name: "discovery_service".into(),
            status: DoctorStatus::Healthy,
            message: format!("service={}", config.service_identity),
        });

        // 6. Network constraints
        let expected_host = "www.googleapis.com";
        let host_ok = config.base_url.contains(expected_host)
            || config.base_url.starts_with("http://localhost")
            || config.base_url.starts_with("http://127.0.0.1");
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: if host_ok {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Degraded
            },
            message: if host_ok {
                format!("Base URL targets expected host ({expected_host})")
            } else {
                format!(
                    "Base URL does not match expected host ({expected_host}); may be a test override"
                )
            },
        });

        // 7. Credential injection (secretless mode)
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            status: if config.auth.is_secretless() {
                DoctorStatus::Degraded
            } else {
                DoctorStatus::Healthy
            },
            message: if config.auth.is_secretless() {
                "Secretless mode — requires egress proxy for credential injection".into()
            } else {
                "Direct API key — no egress proxy required".into()
            },
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Not configured — call configure first");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let Some(config) = self.config.as_ref() else {
            let report =
                SelfCheckReport::failed("not_configured", "Not configured — call configure first");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode, we can't verify connectivity without the egress proxy
        if config.auth.is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; egress proxy injection required for checks",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
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
                    "youtube.list_videos",
                    "Get details for multiple videos by ID",
                    json!({
                        "type": "object",
                        "required": ["video_ids"],
                        "properties": {
                            "video_ids": {
                                "type": "array",
                                "items": { "type": "string" },
                                "minItems": 1
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "videos": { "type": "array" },
                            "total_results": { "type": "integer" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get metadata for multiple videos in one request.".into(),
                        common_mistakes: vec![
                            "Passing an empty video_ids list".into(),
                        ],
                        examples: vec![
                            r#"{"video_ids": ["dQw4w9WgXcQ", "9bZkp7q19f0"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("youtube.get_video"),
                            CapabilityId::from_static("youtube.search"),
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
                    "youtube.list_playlists",
                    "List playlists for a channel",
                    json!({
                        "type": "object",
                        "required": ["channel_id"],
                        "properties": {
                            "channel_id": { "type": "string" },
                            "max_results": { "type": "integer" },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "playlists": { "type": "array" },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List playlists owned by a channel.".into(),
                        common_mistakes: vec![
                            "Not handling next_page_token for pagination".into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "UCxxxxxxxx", "max_results": 10}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("youtube.list_playlist_items")],
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
                op_info(
                    "youtube.get_caption_transcript",
                    "Download transcript content for a caption track",
                    json!({
                        "type": "object",
                        "required": ["caption_id"],
                        "properties": {
                            "caption_id": { "type": "string" },
                            "format": { "type": "string", "enum": ["srt", "vtt", "ttml"] }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "caption_id": { "type": "string" },
                            "format": { "type": "string" },
                            "transcript": { "type": "string" },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve transcript text for downstream analysis.".into(),
                        common_mistakes: vec![
                            "Assuming transcript data is trusted input".into(),
                        ],
                        examples: vec![r#"{"caption_id":"cap1","format":"srt"}"#.into()],
                        related: vec![CapabilityId::from_static("youtube.get_captions")],
                    },
                ),
                op_info(
                    "youtube.upload_caption",
                    "Upload a caption/transcript track for a video",
                    json!({
                        "type": "object",
                        "required": ["video_id", "language", "transcript"],
                        "properties": {
                            "video_id": { "type": "string" },
                            "language": { "type": "string" },
                            "transcript": { "type": "string" },
                            "name": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "caption": { "type": "object" }
                        }
                    }),
                    "youtube.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Publish or replace caption text for a video.".into(),
                        common_mistakes: vec![
                            "Caption upload is a dangerous side-effect and must be approved".into(),
                        ],
                        examples: vec![
                            r#"{"video_id":"dQw4w9WgXcQ","language":"en","transcript":"..."}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("youtube.get_caption_transcript")],
                    },
                ),
                op_info(
                    "youtube.get_analytics",
                    "Get aggregated analytics for a channel's recent videos",
                    json!({
                        "type": "object",
                        "required": ["channel_id"],
                        "properties": {
                            "channel_id": { "type": "string" },
                            "max_videos": { "type": "integer", "minimum": 1, "maximum": 50 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "channelId": { "type": "string" },
                            "videoCount": { "type": "integer" },
                            "totalViews": { "type": "integer" },
                            "totalLikes": { "type": "integer" },
                            "totalComments": { "type": "integer" },
                            "videos": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get aggregated view/like/comment statistics for a channel's recent videos.".into(),
                        common_mistakes: vec![
                            "Uses multiple API calls (channel + playlist + videos) - costs ~150 quota units".into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "UCuAXFkgsw1L7xaCfnd5JJOw", "max_videos": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("youtube.get_channel"),
                            CapabilityId::from_static("youtube.get_video"),
                        ],
                    },
                ),
                op_info(
                    "youtube.upload_video",
                    "Upload a video to YouTube",
                    json!({
                        "type": "object",
                        "required": ["title", "description", "video_data_base64"],
                        "properties": {
                            "title": { "type": "string" },
                            "description": { "type": "string" },
                            "privacy": { "type": "string", "enum": ["private", "unlisted", "public"] },
                            "video_data_base64": { "type": "string", "description": "Base64-encoded video file data" },
                            "tags": { "type": "array", "items": { "type": "string" } },
                            "category_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "videoId": { "type": "string" },
                            "title": { "type": "string" },
                            "privacyStatus": { "type": "string" },
                            "uploadStatus": { "type": "string" }
                        }
                    }),
                    "youtube.write",
                    RiskLevel::Critical,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Upload a video to YouTube. Defaults to private visibility.".into(),
                        common_mistakes: vec![
                            "Video uploads are expensive (1600 quota units) and cannot be undone easily".into(),
                            "Always upload as private first, then change visibility after review".into(),
                        ],
                        examples: vec![
                            r#"{"title":"My Video","description":"A test video","video_data_base64":"...","privacy":"private"}"#.into(),
                        ],
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
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
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
            "youtube.list_videos" => self.invoke_list_videos(input).await,
            "youtube.get_channel" => self.invoke_get_channel(input).await,
            "youtube.list_playlists" => self.invoke_list_playlists(input).await,
            "youtube.list_playlist_items" => self.invoke_list_playlist_items(input).await,
            "youtube.list_comments" => self.invoke_list_comments(input).await,
            "youtube.post_comment" => self.invoke_post_comment(input).await,
            "youtube.get_captions" => self.invoke_get_captions(input).await,
            "youtube.get_caption_transcript" => self.invoke_get_caption_transcript(input).await,
            "youtube.upload_caption" => self.invoke_upload_caption(input).await,
            "youtube.get_analytics" => self.invoke_get_analytics(input).await,
            "youtube.upload_video" => self.invoke_upload_video(input).await,
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
            .and_then(|v| u32::try_from(v).ok());
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

    async fn invoke_list_videos(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_ids = require_str_array(&input, "video_ids")?;

        let results = client
            .list_videos(&video_ids)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let total_results = results
            .page_info
            .as_ref()
            .map_or(results.items.len() as u32, |p| p.total_results);

        Ok(json!({
            "videos": results.items,
            "total_results": total_results
        }))
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

    async fn invoke_list_playlists(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel_id = require_str(&input, "channel_id")?;
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let results = client
            .list_playlists(channel_id, max_results, page_token)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({
            "playlists": results.items,
            "next_page_token": results.next_page_token
        }))
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
            .and_then(|v| u32::try_from(v).ok());
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
            .and_then(|v| u32::try_from(v).ok());

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

    async fn invoke_get_caption_transcript(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let caption_id = require_str(&input, "caption_id")?;
        let format = input.get("format").and_then(|v| v.as_str());

        let transcript = client
            .get_caption_transcript(caption_id, format)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({
            "caption_id": caption_id,
            "format": format.unwrap_or("srt"),
            "transcript": transcript,
            "provenance": {
                "source": "youtube.captions.download",
                "derived": true,
                "resource": format!("caption:{caption_id}")
            },
            "taint": ["external_input", "derived_data"]
        }))
    }

    async fn invoke_upload_caption(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;
        let language = require_str(&input, "language")?;
        let transcript = require_str(&input, "transcript")?;
        let name = input.get("name").and_then(|v| v.as_str());

        let caption = client
            .upload_caption(video_id, language, transcript, name)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({
            "caption": caption
        }))
    }

    async fn invoke_get_analytics(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel_id = require_str(&input, "channel_id")?;
        let max_videos = input
            .get("max_videos")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let analytics = client
            .get_channel_analytics(channel_id, max_videos)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        serde_json::to_value(analytics).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize analytics: {e}"),
        })
    }

    async fn invoke_upload_video(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let title = require_str(&input, "title")?;
        let description = require_str(&input, "description")?;
        let privacy = input
            .get("privacy")
            .and_then(|v| v.as_str())
            .unwrap_or("private");
        let video_data = require_str(&input, "video_data_base64")?;
        let tags: Option<Vec<String>> = input.get("tags").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        });
        let category_id = input.get("category_id").and_then(|v| v.as_str());

        let result = client
            .upload_video(title, description, privacy, video_data, tags, category_id)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize upload result: {e}"),
        })
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
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

fn require_str_array(input: &serde_json::Value, field: &str) -> FcpResult<Vec<String>> {
    let values = input
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })?;

    if values.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Field {field} must not be empty"),
        });
    }

    values
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Field {field}[{idx}] must be a string"),
                })
        })
        .collect()
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

    fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
        let cap = match op {
            "youtube.post_comment" | "youtube.upload_caption" | "youtube.upload_video" => {
                "youtube.write"
            }
            _ => "youtube.read",
        };
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
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
        connector
            .handle_configure(json!({
                "api_key": "fake_key",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

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
        assert!(op_ids.contains(&"youtube.list_videos"));
        assert!(op_ids.contains(&"youtube.get_channel"));
        assert!(op_ids.contains(&"youtube.list_playlists"));
        assert!(op_ids.contains(&"youtube.list_playlist_items"));
        assert!(op_ids.contains(&"youtube.list_comments"));
        assert!(op_ids.contains(&"youtube.post_comment"));
        assert!(op_ids.contains(&"youtube.get_captions"));
        assert!(op_ids.contains(&"youtube.get_caption_transcript"));
        assert!(op_ids.contains(&"youtube.upload_caption"));
        assert!(op_ids.contains(&"youtube.get_analytics"));
        assert!(op_ids.contains(&"youtube.upload_video"));
        assert_eq!(ops.len(), 13);
    }

    // ── Provisioning / doctor / self_check tests ──────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_api_key_mode() {
        let mut connector = YouTubeConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "test-key-123" }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id_mode() {
        let mut connector = YouTubeConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert!(config.auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_both_auth_modes_rejected() {
        let mut connector = YouTubeConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "key",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_no_auth_rejected() {
        let mut connector = YouTubeConnector::new();
        let result = connector.handle_configure(json!({})).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(
                    message.contains("auth"),
                    "expected auth error, got: {message}"
                );
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_custom_base_url() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test",
                "base_url": "http://localhost:8080"
            }))
            .await
            .unwrap();

        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.base_url, "http://localhost:8080");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = YouTubeConnector::new();
        let result = connector.handle_doctor().await.unwrap();

        assert_eq!(result["overall"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_api_key() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({ "api_key": "test-key" }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["overall"], "healthy");

        let checks = result["checks"].as_array().unwrap();
        assert!(checks.len() >= 6);
        assert!(checks.iter().all(|c| c["status"] != "unhealthy"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        // Secretless mode → degraded due to credential_injection check
        assert_eq!(result["overall"], "degraded");

        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = YouTubeConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_returns_degraded() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({ "api_key": "test-key" }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert_eq!(result["auth"], "api_key:redacted");
        assert!(
            result["base_url"]
                .as_str()
                .unwrap()
                .contains("googleapis.com")
        );
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

    // ── require_str sync tests ──────────────────────────────────────

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"video_id": "abc123", "query": "rust"});
        assert_eq!(require_str(&input, "video_id").unwrap(), "abc123");
        assert_eq!(require_str(&input, "query").unwrap(), "rust");
    }

    #[test]
    fn require_str_missing_field() {
        let input = json!({"video_id": "abc"});
        let err = require_str(&input, "query").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("query")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn require_str_non_string_field() {
        let input = json!({"count": 42});
        assert!(require_str(&input, "count").is_err());
    }

    #[test]
    fn require_str_null_field() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"val": 1.23});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"val": {"nested": true}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"val": [1, 2, 3]});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"val": true});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_nested_object_value() {
        let input = json!({"val": {"a": {"b": "c"}}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_empty_string_returns_ok() {
        let input = json!({"val": ""});
        assert_eq!(require_str(&input, "val").unwrap(), "");
    }

    #[test]
    fn require_str_error_code_is_1003() {
        let input = json!({});
        match require_str(&input, "x").unwrap_err() {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── require_str_array sync tests ────────────────────────────────

    #[test]
    fn require_str_array_extracts_values() {
        let input = json!({"parts": ["snippet", "contentDetails"]});
        let result = require_str_array(&input, "parts").unwrap();
        assert_eq!(result, vec!["snippet", "contentDetails"]);
    }

    #[test]
    fn require_str_array_missing_field() {
        let input = json!({});
        assert!(require_str_array(&input, "parts").is_err());
    }

    #[test]
    fn require_str_array_empty_array_rejected() {
        let input = json!({"parts": []});
        let err = require_str_array(&input, "parts").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("must not be empty"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn require_str_array_non_string_element_rejected() {
        let input = json!({"parts": ["snippet", 42]});
        let err = require_str_array(&input, "parts").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("parts[1]"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn require_str_array_not_an_array() {
        let input = json!({"parts": "snippet"});
        assert!(require_str_array(&input, "parts").is_err());
    }

    #[test]
    fn require_str_array_null_value() {
        let input = json!({"parts": null});
        assert!(require_str_array(&input, "parts").is_err());
    }

    // ── DoctorResult / DoctorCheck / DoctorStatus serde ─────────────

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "config".into(),
            status: DoctorStatus::Healthy,
            message: "ok".into(),
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let c = DoctorCheck {
            name: "auth".into(),
            status: DoctorStatus::Healthy,
            message: "valid".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(c2.name, "auth");
        assert_eq!(c2.message, "valid");
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "dbgcheck".into(),
            status: DoctorStatus::Degraded,
            message: "warn".into(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("dbgcheck"));
    }

    #[test]
    fn doctor_status_serde_all_variants() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(&status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Unhealthy);
        assert!(dbg.contains("Unhealthy"));
    }

    #[test]
    fn doctor_status_eq_ne() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_empty_checks_is_healthy() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                status: DoctorStatus::Unhealthy,
                message: "bad".into(),
            },
            DoctorCheck {
                name: "b".into(),
                status: DoctorStatus::Degraded,
                message: "warn".into(),
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }
}
