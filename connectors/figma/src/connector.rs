//! FCP Figma Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::{DEFAULT_BASE_URL, FigmaAuth, FigmaClient};
use crate::error::FigmaError;
use crate::types::{DesignToken, TokenValue};

/// Parsed configuration for the Figma connector.
struct FigmaConfig {
    auth: FigmaAuth,
    base_url: String,
}

impl FigmaConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let token = params.get("token").and_then(|v| v.as_str());
        let credential_id = params.get("credential_id").and_then(|v| v.as_str());
        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BASE_URL);

        let auth = match (token, credential_id) {
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either token or credential_id, not both".into(),
                });
            }
            (Some(t), None) => FigmaAuth::Token(t.to_string()),
            (None, Some(raw)) => {
                let cid = CredentialId::parse(raw).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid credential_id: {e}"),
                })?;
                FigmaAuth::CredentialId(cid)
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing token or credential_id in configuration".into(),
                });
            }
        };

        Ok(Self {
            auth,
            base_url: base_url.to_string(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: String,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Pass,
    Fail,
    Warn,
}

/// FCP Figma Connector.
pub struct FigmaConnector {
    base: Arc<BaseConnector>,
    client: Option<FigmaClient>,
    config: Option<FigmaConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl FigmaConnector {
    /// Create a new Figma connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("figma"))),
            client: None,
            config: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let cfg = FigmaConfig::from_params(&params)?;

        let client =
            FigmaClient::new_with_auth(cfg.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_base_url(&cfg.base_url);

        self.client = Some(client);
        self.config = Some(cfg);
        self.base.set_configured(true);
        info!("Figma connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
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
            manifest_hash: "sha256:figma-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 25,
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let auth_mode = self
            .config
            .as_ref()
            .map_or("none", |c| c.auth.redacted_label());
        let api_url = self
            .config
            .as_ref()
            .map_or(DEFAULT_BASE_URL, |c| c.base_url.as_str());
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "auth_mode": auth_mode,
            "api_url": api_url,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor readiness diagnostics.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. configuration
        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            status: if configured {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if configured {
                "Connector configured".into()
            } else {
                "Not configured — call configure first".into()
            },
        });

        // 2. client_initialized
        let has_client = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            status: if has_client {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if has_client {
                "HTTP client ready".into()
            } else {
                "HTTP client not initialized".into()
            },
        });

        // 3. base_url
        let base_url = self
            .config
            .as_ref()
            .map_or(DEFAULT_BASE_URL, |c| c.base_url.as_str());
        let is_default = base_url == DEFAULT_BASE_URL;
        checks.push(DoctorCheck {
            name: "base_url".into(),
            status: DoctorStatus::Pass,
            message: if is_default {
                format!("Using default: {DEFAULT_BASE_URL}")
            } else {
                format!("Custom URL: {base_url}")
            },
        });

        // 4. auth_mode
        if let Some(cfg) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Pass,
                message: format!("Auth: {}", cfg.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Fail,
                message: "No auth configured".into(),
            });
        }

        // 5. network_constraints
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Pass,
            message: format!("Egress target: api.figma.com (via {base_url})"),
        });

        // 6. credential_injection
        let is_secretless = self.config.as_ref().is_some_and(|c| c.auth.is_secretless());
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            status: if is_secretless {
                DoctorStatus::Warn
            } else {
                DoctorStatus::Pass
            },
            message: if is_secretless {
                "Using credential_id — requires egress proxy for injection".into()
            } else {
                "Direct token auth — no proxy required".into()
            },
        });

        let all_pass = checks
            .iter()
            .all(|c| matches!(c.status, DoctorStatus::Pass));
        let any_fail = checks
            .iter()
            .any(|c| matches!(c.status, DoctorStatus::Fail));

        let overall = if any_fail {
            "unhealthy"
        } else if all_pass {
            "healthy"
        } else {
            "degraded"
        };

        let result = DoctorResult {
            status: overall.into(),
            checks,
        };
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(cfg) = &self.config else {
            let report = SelfCheckReport::failed("not_configured", "Call configure first");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        if cfg.auth.is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy — skipping live probe",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        }

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(e) => SelfCheckReport::failed("connectivity_error", format!("{e}")),
        };
        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check: {e}"),
        })
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                // ── Design Knowledge ──────────────────────────────────
                // ── Resource Discovery ─────────────────────────────────
                op_info(
                    "figma.list_team_projects",
                    "List projects within a Figma team",
                    json!({
                        "type": "object",
                        "required": ["team_id"],
                        "properties": {
                            "team_id": { "type": "string", "description": "Figma team ID" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "projects"],
                        "properties": {
                            "name": { "type": "string", "description": "Team name" },
                            "projects": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["id", "name"],
                                    "properties": {
                                        "id": { "type": "integer" },
                                        "name": { "type": "string" }
                                    }
                                }
                            },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover projects in a Figma team before listing files."
                            .into(),
                        common_mistakes: vec![
                            "Using project ID where team ID is expected.".into(),
                        ],
                        examples: vec![r#"{"team_id": "12345"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.list_project_files"),
                        ],
                    },
                ),
                op_info(
                    "figma.list_project_files",
                    "List files within a Figma project",
                    json!({
                        "type": "object",
                        "required": ["project_id"],
                        "properties": {
                            "project_id": { "type": "string", "description": "Figma project ID" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "files"],
                        "properties": {
                            "name": { "type": "string", "description": "Project name" },
                            "files": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["key", "name", "last_modified"],
                                    "properties": {
                                        "key": { "type": "string" },
                                        "name": { "type": "string" },
                                        "thumbnail_url": { "type": "string" },
                                        "last_modified": { "type": "string" }
                                    }
                                }
                            },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List files in a project after discovering projects with figma.list_team_projects.".into(),
                        common_mistakes: vec![
                            "Using team ID where project ID is expected.".into(),
                            "Accessing thumbnail_url without network constraints for CDN host.".into(),
                        ],
                        examples: vec![r#"{"project_id": "67890"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.list_team_projects"),
                            CapabilityId::from_static("figma.get_file"),
                        ],
                    },
                ),
                op_info(
                    "figma.get_file_meta",
                    "Get minimal file metadata (name, last modified, thumbnail) without the full document tree",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "lastModified", "version"],
                        "properties": {
                            "name": { "type": "string" },
                            "lastModified": { "type": "string" },
                            "version": { "type": "string" },
                            "thumbnailUrl": { "type": "string" },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get lightweight metadata for a file without downloading the full document tree. Cheaper and faster than figma.get_file.".into(),
                        common_mistakes: vec![
                            "Using get_file_meta when you need the full document tree (use figma.get_file instead).".into(),
                        ],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file"),
                            CapabilityId::from_static("figma.list_project_files"),
                        ],
                    },
                ),
                // ── Design Knowledge ──────────────────────────────────
                op_info(
                    "figma.get_file",
                    "Get a Figma file's document tree",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "ids": { "type": "string", "description": "Comma-separated node IDs" },
                            "depth": { "type": "integer", "description": "Traversal depth", "minimum": 1 },
                            "geometry": { "type": "string", "description": "Include vector path data", "enum": ["paths"] },
                            "plugin_data": { "type": "string", "description": "Plugin IDs for data inclusion" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "document", "lastModified", "version"],
                        "properties": {
                            "name": { "type": "string" },
                            "document": { "type": "object" },
                            "lastModified": { "type": "string" },
                            "version": { "type": "string" },
                            "components": { "type": "object" },
                            "styles": { "type": "object" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a Figma file's full or partial document tree.".into(),
                        common_mistakes: vec![
                            "Not using ids parameter for large files.".into(),
                            "Confusing file_key with node IDs.".into(),
                        ],
                        examples: vec![
                            r#"{"file_key": "abc123DEF456"}"#.into(),
                            r#"{"file_key": "abc123DEF456", "ids": "1:2,3:4", "depth": 2}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("figma.get_file_nodes"),
                            CapabilityId::from_static("figma.list_file_versions"),
                        ],
                    },
                ),
                op_info(
                    "figma.get_file_nodes",
                    "Get specific nodes from a Figma file by ID",
                    json!({
                        "type": "object",
                        "required": ["file_key", "ids"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "ids": { "type": "string", "description": "Comma-separated node IDs (e.g., '1:2,3:4')" },
                            "depth": { "type": "integer", "description": "Traversal depth per node", "minimum": 1 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["nodes"],
                        "properties": { "nodes": { "type": "object" } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve specific nodes by ID. More efficient than get_file for targeted access.".into(),
                        common_mistakes: vec!["Using wrong node ID format (should be 'X:Y').".into()],
                        examples: vec![r#"{"file_key": "abc123DEF456", "ids": "1:2,3:4"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file"),
                            CapabilityId::from_static("figma.export_images"),
                        ],
                    },
                ),
                op_info(
                    "figma.get_file_components",
                    "Get all components published in a file",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["meta"],
                        "properties": { "meta": { "type": "object" } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all published components in a file's library.".into(),
                        common_mistakes: vec!["Confusing file components with team library components.".into()],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file"),
                            CapabilityId::from_static("figma.get_file_styles"),
                        ],
                    },
                ),
                op_info(
                    "figma.get_file_styles",
                    "Get all published styles in a file",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["meta"],
                        "properties": { "meta": { "type": "object" } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all published styles (colors, text, effects, grids) in a file.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file"),
                            CapabilityId::from_static("figma.get_file_components"),
                        ],
                    },
                ),
                // ── Image Export ──────────────────────────────────────
                op_info(
                    "figma.export_images",
                    "Export node(s) as PNG, SVG, JPG, or PDF",
                    json!({
                        "type": "object",
                        "required": ["file_key", "ids", "format"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "ids": { "type": "string", "description": "Comma-separated node IDs" },
                            "format": { "type": "string", "description": "Export format", "enum": ["png", "svg", "jpg", "pdf"] },
                            "scale": { "type": "number", "description": "Export scale (0.01 - 4.0)", "minimum": 0.01, "maximum": 4.0 },
                            "svg_include_id": { "type": "boolean" },
                            "svg_simplify_stroke": { "type": "boolean" },
                            "use_absolute_bounds": { "type": "boolean" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["images"],
                        "properties": {
                            "images": { "type": "object" },
                            "err": { "type": "string" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Export design nodes as images. Returns time-limited download URLs.".into(),
                        common_mistakes: vec![
                            "Not downloading images before URL expires.".into(),
                            "Exporting at high scale for very large frames.".into(),
                        ],
                        examples: vec![r#"{"file_key": "abc123DEF456", "ids": "1:2", "format": "png", "scale": 2.0}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file_nodes"),
                            CapabilityId::from_static("figma.get_file"),
                        ],
                    },
                ),
                // ── Version History ──────────────────────────────────
                op_info(
                    "figma.list_file_versions",
                    "List version history for a file",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["versions"],
                        "properties": {
                            "versions": { "type": "array", "items": { "type": "object" } },
                            "pagination": { "type": "object" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve version history for a Figma file.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![CapabilityId::from_static("figma.get_file")],
                    },
                ),
                // ── Comments ─────────────────────────────────────────
                op_info(
                    "figma.list_comments",
                    "List comments on a Figma file",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "as_md": { "type": "boolean", "description": "Return as Markdown" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["comments"],
                        "properties": { "comments": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve all comments and replies on a Figma file.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.post_comment"),
                            CapabilityId::from_static("figma.get_file"),
                        ],
                    },
                ),
                op_info(
                    "figma.post_comment",
                    "Post a comment on a Figma file",
                    json!({
                        "type": "object",
                        "required": ["file_key", "message"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "message": { "type": "string", "description": "Comment body text" },
                            "comment_id": { "type": "string", "description": "Reply to comment by ID" },
                            "client_meta": { "type": "object", "description": "Anchor position" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "message", "created_at"],
                        "properties": {
                            "id": { "type": "string" },
                            "message": { "type": "string" },
                            "created_at": { "type": "string" },
                            "user": { "type": "object" }
                        }
                    }),
                    "figma.write",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add a comment to a Figma file. Can be top-level or reply.".into(),
                        common_mistakes: vec![
                            "Not providing client_meta when anchoring to a specific element.".into(),
                        ],
                        examples: vec![
                            r#"{"file_key": "abc123DEF456", "message": "Looks great!"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("figma.list_comments"),
                            CapabilityId::from_static("figma.delete_comment"),
                        ],
                    },
                ),
                op_info(
                    "figma.delete_comment",
                    "Delete a comment from a Figma file",
                    json!({
                        "type": "object",
                        "required": ["file_key", "comment_id"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "comment_id": { "type": "string", "description": "Comment ID to delete" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "figma.delete",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Delete a comment. Only the author or file owner can delete.".into(),
                        common_mistakes: vec!["Trying to delete comments authored by other users.".into()],
                        examples: vec![r#"{"file_key": "abc123DEF456", "comment_id": "12345"}"#.into()],
                        related: vec![CapabilityId::from_static("figma.list_comments")],
                    },
                ),
                // ── Webhooks ─────────────────────────────────────────
                op_info(
                    "figma.list_webhooks",
                    "List all webhooks registered for a team",
                    json!({
                        "type": "object",
                        "required": ["team_id"],
                        "properties": {
                            "team_id": { "type": "string", "description": "Team ID" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["webhooks"],
                        "properties": { "webhooks": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all registered webhooks for a team.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"team_id": "12345"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.create_webhook"),
                            CapabilityId::from_static("figma.delete_webhook"),
                        ],
                    },
                ),
                op_info(
                    "figma.create_webhook",
                    "Register a webhook for file change events",
                    json!({
                        "type": "object",
                        "required": ["team_id", "event_type", "endpoint", "passcode"],
                        "properties": {
                            "team_id": { "type": "string", "description": "Team ID" },
                            "event_type": { "type": "string", "description": "Event type", "enum": ["FILE_UPDATE", "FILE_DELETE", "FILE_VERSION_UPDATE", "LIBRARY_PUBLISH", "FILE_COMMENT"] },
                            "endpoint": { "type": "string", "description": "HTTPS URL for webhook POST" },
                            "passcode": { "type": "string", "description": "Secret for signature verification" },
                            "description": { "type": "string", "description": "Webhook description" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "team_id", "event_type", "endpoint", "status"],
                        "properties": {
                            "id": { "type": "string" },
                            "team_id": { "type": "string" },
                            "event_type": { "type": "string" },
                            "endpoint": { "type": "string" },
                            "status": { "type": "string" }
                        }
                    }),
                    "figma.webhook",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Register a webhook to receive events for file updates, deletions, comments.".into(),
                        common_mistakes: vec![
                            "Not providing a valid HTTPS endpoint URL.".into(),
                            "Forgetting the passcode for signature verification.".into(),
                        ],
                        examples: vec![
                            r#"{"team_id": "12345", "event_type": "FILE_UPDATE", "endpoint": "https://example.com/webhook", "passcode": "secret123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("figma.list_webhooks"),
                            CapabilityId::from_static("figma.delete_webhook"),
                        ],
                    },
                ),
                op_info(
                    "figma.delete_webhook",
                    "Delete a webhook subscription",
                    json!({
                        "type": "object",
                        "required": ["webhook_id"],
                        "properties": {
                            "webhook_id": { "type": "string", "description": "Webhook ID to delete" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "figma.delete",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Remove a webhook subscription.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"webhook_id": "67890"}"#.into()],
                        related: vec![CapabilityId::from_static("figma.list_webhooks")],
                    },
                ),
                // ── Design Tokens ───────────────────────────────────────
                op_info(
                    "figma.styles.list",
                    "List file styles as structured design tokens with categories and normalized names",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["tokens"],
                        "properties": {
                            "tokens": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["name", "category", "style_type", "value"],
                                    "properties": {
                                        "name": { "type": "string", "description": "Normalized kebab-case token name" },
                                        "original_name": { "type": "string", "description": "Original Figma style name" },
                                        "category": { "type": "string", "description": "Token category: color, typography, effect, grid" },
                                        "style_type": { "type": "string" },
                                        "value": { "type": "object" },
                                        "node_id": { "type": "string" },
                                        "description": { "type": "string" }
                                    }
                                }
                            },
                            "count": { "type": "integer" },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all design tokens from a file's published styles. Returns structured tokens with normalized names and categorized values.".into(),
                        common_mistakes: vec![
                            "Using get_file_styles when you want structured tokens — use styles.list instead.".into(),
                        ],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.tokens.export"),
                            CapabilityId::from_static("figma.get_file_styles"),
                        ],
                    },
                ),
                op_info(
                    "figma.tokens.export",
                    "Export design tokens as JSON or CSS custom properties",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "format": { "type": "string", "description": "Output format", "enum": ["json", "css"], "default": "json" },
                            "prefix": { "type": "string", "description": "CSS custom property prefix (default: empty)", "default": "" },
                            "categories": { "type": "array", "items": { "type": "string" }, "description": "Filter to specific categories: color, typography, effect, grid" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["output", "format", "count"],
                        "properties": {
                            "output": { "type": "string", "description": "Exported tokens in the requested format" },
                            "format": { "type": "string" },
                            "count": { "type": "integer" },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Export design tokens in a consumable format (JSON for code, CSS for stylesheets). Normalizes names and produces stable, sorted output.".into(),
                        common_mistakes: vec![
                            "Not specifying format — defaults to json.".into(),
                            "Using css format for typography tokens — CSS custom properties work best for colors.".into(),
                        ],
                        examples: vec![
                            r#"{"file_key": "abc123DEF456", "format": "json"}"#.into(),
                            r#"{"file_key": "abc123DEF456", "format": "css", "prefix": "ds"}"#.into(),
                            r#"{"file_key": "abc123DEF456", "format": "json", "categories": ["color"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("figma.styles.list"),
                            CapabilityId::from_static("figma.get_file_styles"),
                        ],
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
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
            "figma.list_team_projects" => self.invoke_list_team_projects(input).await,
            "figma.list_project_files" => self.invoke_list_project_files(input).await,
            "figma.get_file_meta" => self.invoke_get_file_meta(input).await,
            "figma.get_file" => self.invoke_get_file(input).await,
            "figma.get_file_nodes" => self.invoke_get_file_nodes(input).await,
            "figma.get_file_components" => self.invoke_get_file_components(input).await,
            "figma.get_file_styles" => self.invoke_get_file_styles(input).await,
            "figma.export_images" => self.invoke_export_images(input).await,
            "figma.list_file_versions" => self.invoke_list_file_versions(input).await,
            "figma.list_comments" => self.invoke_list_comments(input).await,
            "figma.post_comment" => self.invoke_post_comment(input).await,
            "figma.delete_comment" => self.invoke_delete_comment(input).await,
            "figma.list_webhooks" => self.invoke_list_webhooks(input).await,
            "figma.create_webhook" => self.invoke_create_webhook(input).await,
            "figma.delete_webhook" => self.invoke_delete_webhook(input).await,
            "figma.styles.list" => self.invoke_styles_list(input).await,
            "figma.tokens.export" => self.invoke_tokens_export(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Resource Discovery implementations ─────────────────────────

    async fn invoke_list_team_projects(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let team_id = require_str(&input, "team_id")?;

        let resp = client
            .list_team_projects(team_id)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        Ok(json!({
            "name": resp.name,
            "projects": resp.projects.iter().map(|p| json!({
                "id": p.id,
                "name": p.name,
            })).collect::<Vec<_>>(),
            "provenance": {
                "source": "figma.teams",
                "derived": false,
                "scope": "team"
            },
            "taint": ["external_input"]
        }))
    }

    async fn invoke_list_project_files(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let project_id = require_str(&input, "project_id")?;

        let resp = client
            .list_project_files(project_id)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        Ok(json!({
            "name": resp.name,
            "files": resp.files.iter().map(|f| json!({
                "key": f.key,
                "name": f.name,
                "thumbnail_url": f.thumbnail_url,
                "last_modified": f.last_modified,
            })).collect::<Vec<_>>(),
            "provenance": {
                "source": "figma.projects",
                "derived": false,
                "scope": "project"
            },
            "taint": ["external_input"]
        }))
    }

    async fn invoke_get_file_meta(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;

        // Use depth=1 for lightweight metadata (minimal document traversal)
        let file = client
            .get_file(file_key, None, Some(1), None, None)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        Ok(json!({
            "name": file.name,
            "lastModified": file.last_modified,
            "version": file.version,
            "provenance": {
                "source": "figma.files",
                "derived": false,
                "scope": "file"
            },
            "taint": ["external_input"]
        }))
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_get_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let ids = input.get("ids").and_then(|v| v.as_str());
        let depth = input
            .get("depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let geometry = input.get("geometry").and_then(|v| v.as_str());
        let plugin_data = input.get("plugin_data").and_then(|v| v.as_str());

        let file = client
            .get_file(file_key, ids, depth, geometry, plugin_data)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(file).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_file_nodes(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let ids = require_str(&input, "ids")?;
        let depth = input
            .get("depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let nodes = client
            .get_file_nodes(file_key, ids, depth)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(nodes).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_file_components(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;

        let components = client
            .get_file_components(file_key)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(components).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_file_styles(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;

        let styles = client
            .get_file_styles(file_key)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(styles).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_export_images(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let ids = require_str(&input, "ids")?;
        let format = require_str(&input, "format")?;
        let scale = input.get("scale").and_then(|v| v.as_f64());
        let svg_include_id = input.get("svg_include_id").and_then(|v| v.as_bool());
        let svg_simplify_stroke = input.get("svg_simplify_stroke").and_then(|v| v.as_bool());
        let use_absolute_bounds = input.get("use_absolute_bounds").and_then(|v| v.as_bool());

        let result = client
            .export_images(
                file_key,
                ids,
                format,
                scale,
                svg_include_id,
                svg_simplify_stroke,
                use_absolute_bounds,
            )
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_list_file_versions(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;

        let versions = client
            .list_file_versions(file_key)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(versions).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_list_comments(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let as_md = input.get("as_md").and_then(|v| v.as_bool());

        let comments = client
            .list_comments(file_key, as_md)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(comments).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_post_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let message = require_str(&input, "message")?;
        let comment_id = input.get("comment_id").and_then(|v| v.as_str());
        let client_meta = input.get("client_meta").cloned();

        let comment = client
            .post_comment(file_key, message, comment_id, client_meta)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(comment).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_delete_comment(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let comment_id = require_str(&input, "comment_id")?;

        client
            .delete_comment(file_key, comment_id)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        Ok(json!({}))
    }

    async fn invoke_list_webhooks(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let team_id = require_str(&input, "team_id")?;

        let webhooks = client
            .list_webhooks(team_id)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(webhooks).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_create_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let team_id = require_str(&input, "team_id")?;
        let event_type = require_str(&input, "event_type")?;
        let endpoint = require_str(&input, "endpoint")?;
        let passcode = require_str(&input, "passcode")?;
        let description = input.get("description").and_then(|v| v.as_str());

        let webhook = client
            .create_webhook(team_id, event_type, endpoint, passcode, description)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(webhook).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_delete_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let webhook_id = require_str(&input, "webhook_id")?;

        client
            .delete_webhook(webhook_id)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        Ok(json!({}))
    }

    // ── Design Token implementations ─────────────────────────────

    async fn invoke_styles_list(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;

        let styles = client
            .get_file_styles(file_key)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        let tokens = extract_tokens_from_styles(&styles.meta);

        Ok(json!({
            "tokens": tokens,
            "count": tokens.len(),
            "provenance": {
                "source": "figma.styles",
                "derived": true,
                "scope": "file"
            },
            "taint": ["external_input"]
        }))
    }

    async fn invoke_tokens_export(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let format = input
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("json");
        let prefix = input.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
        let categories: Option<Vec<&str>> = input.get("categories").and_then(|v| {
            v.as_array()
                .map(|arr| arr.iter().filter_map(|s| s.as_str()).collect())
        });

        if format != "json" && format != "css" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unsupported format: {format}. Use 'json' or 'css'."),
            });
        }

        let styles = client
            .get_file_styles(file_key)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        let mut tokens = extract_tokens_from_styles(&styles.meta);

        // Filter by categories if specified
        if let Some(ref cats) = categories {
            tokens.retain(|t| cats.contains(&t.category.as_str()));
        }

        let output = match format {
            "css" => tokens_to_css(&tokens, prefix),
            _ => tokens_to_json(&tokens),
        };

        Ok(json!({
            "output": output,
            "format": format,
            "count": tokens.len(),
            "provenance": {
                "source": "figma.styles",
                "derived": true,
                "scope": "file"
            },
            "taint": ["external_input"]
        }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Figma connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for FigmaConnector {
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

// ── Design token extraction helpers ──────────────────────────────

/// Normalize a Figma style name to kebab-case token name.
/// Examples: "Primary / 500" -> "primary-500", "Header Bold" -> "header-bold"
fn normalize_token_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Map Figma `style_type` to a token category.
fn style_type_to_category(style_type: &str) -> &'static str {
    match style_type {
        "FILL" => "color",
        "TEXT" => "typography",
        "EFFECT" => "effect",
        "GRID" => "grid",
        _ => "raw",
    }
}

/// Convert RGBA [0..1] floats to a hex color string.
fn rgba_to_hex(r: f64, g: f64, b: f64, a: f64) -> String {
    let ri = (r.clamp(0.0, 1.0) * 255.0).round() as u8;
    let gi = (g.clamp(0.0, 1.0) * 255.0).round() as u8;
    let bi = (b.clamp(0.0, 1.0) * 255.0).round() as u8;
    let ai = (a.clamp(0.0, 1.0) * 255.0).round() as u8;
    format!("#{ri:02x}{gi:02x}{bi:02x}{ai:02x}")
}

/// Extract structured design tokens from the Figma styles metadata.
///
/// The `meta` field from the styles API can be either:
/// - An object with `styles` array: `{ "styles": [...] }`
/// - Directly an array of style entries
///
/// Each style entry has: `key`, `name`, `style_type`, `description`, `node_id`.
fn extract_tokens_from_styles(meta: &serde_json::Value) -> Vec<DesignToken> {
    let styles = meta
        .get("styles")
        .and_then(|v| v.as_array())
        .or_else(|| meta.as_array());

    let Some(styles) = styles else {
        return Vec::new();
    };

    let mut tokens: Vec<DesignToken> = styles
        .iter()
        .filter_map(|style| {
            let name = style.get("name")?.as_str()?;
            let style_type = style.get("style_type").and_then(|v| v.as_str())?;
            let description = style
                .get("description")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            let node_id = style
                .get("node_id")
                .and_then(|v| v.as_str())
                .map(String::from);

            let category = style_type_to_category(style_type);
            let normalized = normalize_token_name(name);

            let value = match style_type {
                "FILL" => {
                    // Look for color in style properties
                    if let Some(color) = style.get("color") {
                        let r = color.get("r").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let g = color.get("g").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let b = color.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let a = color.get("a").and_then(|v| v.as_f64()).unwrap_or(1.0);
                        TokenValue::Color {
                            r,
                            g,
                            b,
                            a,
                            hex: rgba_to_hex(r, g, b, a),
                        }
                    } else {
                        TokenValue::Raw {
                            data: style.clone(),
                        }
                    }
                }
                "TEXT" => {
                    let font_family = style
                        .get("font_family")
                        .and_then(|v| v.as_str())
                        .unwrap_or("sans-serif")
                        .to_string();
                    let font_size = style
                        .get("font_size")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(16.0);
                    let font_weight = style
                        .get("font_weight")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(400.0);
                    let line_height = style.get("line_height").and_then(|v| v.as_f64());
                    let letter_spacing = style.get("letter_spacing").and_then(|v| v.as_f64());
                    TokenValue::Typography {
                        font_family,
                        font_size,
                        font_weight,
                        line_height,
                        letter_spacing,
                    }
                }
                "EFFECT" => {
                    let effect_type = style
                        .get("effect_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let radius = style.get("radius").and_then(|v| v.as_f64());
                    let color = style
                        .get("effect_color")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let offset_x = style.get("offset_x").and_then(|v| v.as_f64());
                    let offset_y = style.get("offset_y").and_then(|v| v.as_f64());
                    TokenValue::Effect {
                        effect_type,
                        radius,
                        color,
                        offset_x,
                        offset_y,
                    }
                }
                "GRID" => {
                    let pattern = style
                        .get("pattern")
                        .and_then(|v| v.as_str())
                        .unwrap_or("columns")
                        .to_string();
                    let size = style.get("size").and_then(|v| v.as_f64());
                    let gutter = style.get("gutter").and_then(|v| v.as_f64());
                    let count = style.get("count").and_then(|v| v.as_f64());
                    TokenValue::Grid {
                        pattern,
                        size,
                        gutter,
                        count,
                    }
                }
                _ => TokenValue::Raw {
                    data: style.clone(),
                },
            };

            Some(DesignToken {
                name: normalized,
                original_name: name.to_string(),
                category: category.to_string(),
                style_type: style_type.to_string(),
                value,
                node_id,
                description,
            })
        })
        .collect();

    // Stable sort by name for deterministic output
    tokens.sort_by(|a, b| a.name.cmp(&b.name));
    tokens
}

/// Serialize tokens to a pretty-printed JSON string.
fn tokens_to_json(tokens: &[DesignToken]) -> String {
    serde_json::to_string_pretty(tokens).unwrap_or_else(|_| "[]".to_string())
}

/// Serialize tokens to CSS custom properties.
fn tokens_to_css(tokens: &[DesignToken], prefix: &str) -> String {
    use std::fmt::Write;
    let mut css = String::from(":root {\n");
    let prefix_str = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}-")
    };

    for token in tokens {
        let var_name = format!("--{prefix_str}{}", token.name);
        let value = match &token.value {
            TokenValue::Color { hex, .. } => hex.clone(),
            TokenValue::Typography {
                font_family,
                font_size,
                ..
            } => format!("{font_size}px {font_family}"),
            TokenValue::Effect {
                effect_type,
                radius,
                ..
            } => {
                if let Some(r) = radius {
                    format!("{effect_type} {r}px")
                } else {
                    effect_type.clone()
                }
            }
            TokenValue::Grid { pattern, size, .. } => {
                if let Some(s) = size {
                    format!("{pattern} {s}px")
                } else {
                    pattern.clone()
                }
            }
            TokenValue::Raw { data } => data.to_string(),
        };
        let _ = writeln!(css, "  {var_name}: {value};");
    }

    css.push('}');
    css
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

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
        let mut connector = FigmaConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["figma.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = FigmaConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_configured() {
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "token": "fake-token",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = FigmaConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["figma.get_file"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "figma.get_file");

        let result = connector
            .handle_invoke(json!({
                "operation": "figma.get_file",
                "input": { "file_key": "abc123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "token": "fake_key",
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
                "capabilities_requested": ["figma.get_file_nodes"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "figma.get_file_nodes");

        let result = connector
            .handle_invoke(json!({
                "operation": "figma.get_file_nodes",
                "input": { "file_key": "abc123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("ids"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = FigmaConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"figma.list_team_projects"));
        assert!(op_ids.contains(&"figma.list_project_files"));
        assert!(op_ids.contains(&"figma.get_file_meta"));
        assert!(op_ids.contains(&"figma.get_file"));
        assert!(op_ids.contains(&"figma.get_file_nodes"));
        assert!(op_ids.contains(&"figma.get_file_components"));
        assert!(op_ids.contains(&"figma.get_file_styles"));
        assert!(op_ids.contains(&"figma.export_images"));
        assert!(op_ids.contains(&"figma.list_file_versions"));
        assert!(op_ids.contains(&"figma.list_comments"));
        assert!(op_ids.contains(&"figma.post_comment"));
        assert!(op_ids.contains(&"figma.delete_comment"));
        assert!(op_ids.contains(&"figma.list_webhooks"));
        assert!(op_ids.contains(&"figma.create_webhook"));
        assert!(op_ids.contains(&"figma.delete_webhook"));
        assert!(op_ids.contains(&"figma.styles.list"));
        assert!(op_ids.contains(&"figma.tokens.export"));
        assert_eq!(ops.len(), 17);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unknown_operation_rejected() {
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "token": "fake_key",
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
                "capabilities_requested": ["figma.nonexistent"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "figma.nonexistent");

        let result = connector
            .handle_invoke(json!({
                "operation": "figma.nonexistent",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::OperationNotGranted { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_token() {
        let mut connector = FigmaConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("token"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_returns_allowed() {
        let connector = FigmaConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, "figma.get_file");

        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-1",
                "connector_id": "figma",
                "operation": "figma.get_file",
                "zone_id": "z:work",
                "input": { "file_key": "abc123" },
                "capability_token": token
            }))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let connector = FigmaConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    // ── Provisioning tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_token() {
        let mut connector = FigmaConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "figd_test_token_123"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert_eq!(
            connector.config.as_ref().unwrap().auth.redacted_label(),
            "token"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = FigmaConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": cid
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth_modes() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = FigmaConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "figd_test",
                "credential_id": cid
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("not both"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth() {
        let mut connector = FigmaConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("token") || message.contains("credential_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_urls() {
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "token": "figd_test",
                "base_url": "http://localhost:8080"
            }))
            .await
            .unwrap();
        assert_eq!(
            connector.config.as_ref().unwrap().base_url,
            "http://localhost:8080"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": cid,
                "base_url": "http://proxy:9999"
            }))
            .await
            .unwrap();

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["auth_mode"], "credential_id");
        assert_eq!(health["api_url"], "http://proxy:9999");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = FigmaConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(
            checks
                .iter()
                .any(|c| c["name"] == "configuration" && c["status"] == "fail")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "token": "figd_test"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|c| c["status"] == "pass"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": cid
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "degraded");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "warn");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = FigmaConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": cid
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    // ── Design Token helper tests ────────────────────────────────

    #[test]
    fn test_normalize_token_name_basic() {
        assert_eq!(normalize_token_name("Primary / 500"), "primary-500");
        assert_eq!(normalize_token_name("Header Bold"), "header-bold");
        assert_eq!(normalize_token_name("color-gray-100"), "color-gray-100");
    }

    #[test]
    fn test_normalize_token_name_special_chars() {
        assert_eq!(
            normalize_token_name("Brand / Color / Primary"),
            "brand-color-primary"
        );
        assert_eq!(normalize_token_name("  spacing__large  "), "spacing-large");
        assert_eq!(normalize_token_name("A"), "a");
    }

    #[test]
    fn test_rgba_to_hex() {
        assert_eq!(rgba_to_hex(1.0, 0.0, 0.0, 1.0), "#ff0000ff");
        assert_eq!(rgba_to_hex(0.0, 0.0, 0.0, 1.0), "#000000ff");
        assert_eq!(rgba_to_hex(1.0, 1.0, 1.0, 0.5), "#ffffff80");
        assert_eq!(rgba_to_hex(0.0, 0.0, 0.0, 0.0), "#00000000");
    }

    #[test]
    fn test_style_type_to_category() {
        assert_eq!(style_type_to_category("FILL"), "color");
        assert_eq!(style_type_to_category("TEXT"), "typography");
        assert_eq!(style_type_to_category("EFFECT"), "effect");
        assert_eq!(style_type_to_category("GRID"), "grid");
        assert_eq!(style_type_to_category("UNKNOWN"), "raw");
    }

    #[test]
    fn test_extract_tokens_from_styles_color() {
        let meta = json!({
            "styles": [
                {
                    "key": "s1",
                    "name": "Primary / 500",
                    "style_type": "FILL",
                    "description": "Main brand color",
                    "node_id": "1:2",
                    "color": { "r": 0.2, "g": 0.4, "b": 0.8, "a": 1.0 }
                }
            ]
        });

        let tokens = extract_tokens_from_styles(&meta);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].name, "primary-500");
        assert_eq!(tokens[0].original_name, "Primary / 500");
        assert_eq!(tokens[0].category, "color");
        assert_eq!(tokens[0].description.as_deref(), Some("Main brand color"));
        assert_eq!(tokens[0].node_id.as_deref(), Some("1:2"));

        match &tokens[0].value {
            TokenValue::Color { r, g, b, a, hex } => {
                assert!((r - 0.2).abs() < f64::EPSILON);
                assert!((g - 0.4).abs() < f64::EPSILON);
                assert!((b - 0.8).abs() < f64::EPSILON);
                assert!((a - 1.0).abs() < f64::EPSILON);
                assert_eq!(hex, "#3366ccff");
            }
            other => panic!("Expected Color, got: {other:?}"),
        }
    }

    #[test]
    fn test_extract_tokens_from_styles_typography() {
        let meta = json!({
            "styles": [
                {
                    "key": "s2",
                    "name": "Heading Large",
                    "style_type": "TEXT",
                    "description": "",
                    "font_family": "Inter",
                    "font_size": 32.0,
                    "font_weight": 700.0,
                    "line_height": 40.0
                }
            ]
        });

        let tokens = extract_tokens_from_styles(&meta);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].name, "heading-large");
        assert_eq!(tokens[0].category, "typography");
        // Empty description should be None
        assert!(tokens[0].description.is_none());

        match &tokens[0].value {
            TokenValue::Typography {
                font_family,
                font_size,
                font_weight,
                line_height,
                ..
            } => {
                assert_eq!(font_family, "Inter");
                assert!((font_size - 32.0).abs() < f64::EPSILON);
                assert!((font_weight - 700.0).abs() < f64::EPSILON);
                assert_eq!(*line_height, Some(40.0));
            }
            other => panic!("Expected Typography, got: {other:?}"),
        }
    }

    #[test]
    fn test_extract_tokens_stable_sort_order() {
        let meta = json!({
            "styles": [
                { "name": "Zebra", "style_type": "FILL", "color": { "r": 0.0, "g": 0.0, "b": 0.0, "a": 1.0 } },
                { "name": "Apple", "style_type": "FILL", "color": { "r": 1.0, "g": 0.0, "b": 0.0, "a": 1.0 } },
                { "name": "Mango", "style_type": "FILL", "color": { "r": 0.0, "g": 1.0, "b": 0.0, "a": 1.0 } }
            ]
        });

        let tokens = extract_tokens_from_styles(&meta);
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].name, "apple");
        assert_eq!(tokens[1].name, "mango");
        assert_eq!(tokens[2].name, "zebra");
    }

    #[test]
    fn test_extract_tokens_empty_meta() {
        assert!(extract_tokens_from_styles(&json!({})).is_empty());
        assert!(extract_tokens_from_styles(&json!(null)).is_empty());
        assert!(extract_tokens_from_styles(&json!({ "styles": [] })).is_empty());
    }

    #[test]
    fn test_tokens_to_css() {
        let tokens = vec![DesignToken {
            name: "color-primary".into(),
            original_name: "Color/Primary".into(),
            category: "color".into(),
            style_type: "FILL".into(),
            value: TokenValue::Color {
                r: 1.0,
                g: 0.0,
                b: 0.0,
                a: 1.0,
                hex: "#ff0000ff".into(),
            },
            node_id: None,
            description: None,
        }];

        let css = tokens_to_css(&tokens, "");
        assert!(css.contains(":root {"));
        assert!(css.contains("--color-primary: #ff0000ff;"));
        assert!(css.ends_with('}'));

        let css_prefixed = tokens_to_css(&tokens, "ds");
        assert!(css_prefixed.contains("--ds-color-primary: #ff0000ff;"));
    }

    #[test]
    fn test_tokens_to_json_deterministic() {
        let tokens = vec![
            DesignToken {
                name: "a-token".into(),
                original_name: "A Token".into(),
                category: "color".into(),
                style_type: "FILL".into(),
                value: TokenValue::Color {
                    r: 1.0,
                    g: 0.0,
                    b: 0.0,
                    a: 1.0,
                    hex: "#ff0000ff".into(),
                },
                node_id: None,
                description: None,
            },
            DesignToken {
                name: "b-token".into(),
                original_name: "B Token".into(),
                category: "color".into(),
                style_type: "FILL".into(),
                value: TokenValue::Color {
                    r: 0.0,
                    g: 0.0,
                    b: 1.0,
                    a: 1.0,
                    hex: "#0000ffff".into(),
                },
                node_id: None,
                description: None,
            },
        ];

        let json1 = tokens_to_json(&tokens);
        let json2 = tokens_to_json(&tokens);
        assert_eq!(json1, json2, "JSON output must be deterministic");

        let parsed: Vec<DesignToken> = serde_json::from_str(&json1).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "a-token");
        assert_eq!(parsed[1].name, "b-token");
    }

    #[test]
    fn test_extract_tokens_mixed_types() {
        let meta = json!({
            "styles": [
                {
                    "name": "Shadow / Medium",
                    "style_type": "EFFECT",
                    "effect_type": "DROP_SHADOW",
                    "radius": 8.0,
                    "offset_x": 0.0,
                    "offset_y": 4.0
                },
                {
                    "name": "Grid / 12col",
                    "style_type": "GRID",
                    "pattern": "columns",
                    "count": 12.0,
                    "gutter": 24.0,
                    "size": 80.0
                }
            ]
        });

        let tokens = extract_tokens_from_styles(&meta);
        assert_eq!(tokens.len(), 2);

        // Sorted alphabetically: "grid-12col" < "shadow-medium"
        assert_eq!(tokens[0].name, "grid-12col");
        assert_eq!(tokens[0].category, "grid");
        assert_eq!(tokens[1].name, "shadow-medium");
        assert_eq!(tokens[1].category, "effect");

        match &tokens[1].value {
            TokenValue::Effect {
                effect_type,
                radius,
                offset_y,
                ..
            } => {
                assert_eq!(effect_type, "DROP_SHADOW");
                assert_eq!(*radius, Some(8.0));
                assert_eq!(*offset_y, Some(4.0));
            }
            other => panic!("Expected Effect, got: {other:?}"),
        }

        match &tokens[0].value {
            TokenValue::Grid {
                pattern,
                count,
                gutter,
                ..
            } => {
                assert_eq!(pattern, "columns");
                assert_eq!(*count, Some(12.0));
                assert_eq!(*gutter, Some(24.0));
            }
            other => panic!("Expected Grid, got: {other:?}"),
        }
    }
}
