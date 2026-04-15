//! FCP Notion Connector implementation.

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

use crate::{
    client::{
        DEFAULT_API_URL, DEFAULT_NOTION_VERSION, NotionAuth, NotionClient, normalize_notion_version,
    },
    error::NotionError,
    limits,
};

/// Validated configuration for the Notion connector.
struct NotionConfig {
    auth: NotionAuth,
    api_url: String,
    notion_version: Option<String>,
}

impl NotionConfig {
    /// Parse and validate configuration from FCP params.
    ///
    /// Strict auth: exactly one of `token` or `credential_id` must be supplied.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let token = params
            .get("token")
            .and_then(|v| v.as_str())
            .map(String::from);
        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let auth = match (token, credential_id) {
            (Some(t), None) => NotionAuth::Token(t),
            (None, Some(cid)) => NotionAuth::CredentialId(cid),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Supply exactly one of `token` or `credential_id`, not both".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing authentication: supply `token` or `credential_id`".into(),
                });
            }
        };

        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_URL)
            .to_string();

        let notion_version = match params.get("notion_version") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "notion_version must be a string".into(),
                })?;
                Some(
                    normalize_notion_version(raw).ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "notion_version must look like YYYY-MM-DD".into(),
                    })?,
                )
            }
            None => None,
        };

        Ok(Self {
            auth,
            api_url,
            notion_version,
        })
    }
}

/// Structured readiness diagnostic for the doctor command.
#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// FCP Notion Connector.
pub struct NotionConnector {
    base: Arc<BaseConnector>,
    config: Option<NotionConfig>,
    client: Option<NotionClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl NotionConnector {
    /// Create a new Notion connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("notion"))),
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
        let config = NotionConfig::from_params(&params)?;

        let client =
            NotionClient::new_with_version(config.auth.clone(), config.notion_version.as_deref())
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to create HTTP client: {e}"),
                })?
                .with_api_url(&config.api_url);

        info!(auth = %config.auth.redacted_label(), "Notion connector configured");

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
            manifest_hash: "sha256:notion-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 50,
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
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(config.auth.redacted_label());
            health["api_url"] = json!(config.api_url);
            health["notion_version"] = json!(
                self.client.as_ref().map_or(
                    config
                        .notion_version
                        .as_deref()
                        .unwrap_or(DEFAULT_NOTION_VERSION),
                    NotionClient::notion_version,
                )
            );
        }
        Ok(health)
    }

    /// Handle doctor readiness check.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. Configuration
        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured – call `configure` first".into(),
            }
        });

        // 2. Client initialized
        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "HTTP client is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "HTTP client is not initialized".into(),
            }
        });

        // 3. API URL
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("API URL: {}", config.api_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "API URL not set (not configured)".into(),
            });
        }

        // 4. Auth mode
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", config.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Unhealthy,
                message: "Auth mode not set (not configured)".into(),
            });
        }

        // 5. Effective Notion API version
        let notion_version = self.client.as_ref().map_or_else(
            || {
                self.config
                    .as_ref()
                    .and_then(|config| config.notion_version.clone())
                    .unwrap_or_else(|| DEFAULT_NOTION_VERSION.to_string())
            },
            |client| client.notion_version().to_string(),
        );
        checks.push(DoctorCheck {
            name: "notion_version".into(),
            status: DoctorStatus::Healthy,
            message: format!("Notion-Version header: {notion_version}"),
        });

        // 6. Network constraints
        let egress_target = self.config.as_ref().map_or("api.notion.com", |c| {
            c.api_url
                .strip_prefix("https://")
                .or_else(|| c.api_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .unwrap_or("api.notion.com")
        });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: format!("Egress target: {egress_target}"),
        });

        // 7. Credential injection
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Secretless mode – egress proxy will inject credentials".into(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Direct token mode – no proxy injection needed".into(),
                });
            }
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode, we can't verify connectivity without the egress proxy
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
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
                    "notion.create_page",
                    "Create a new page in a database or as a child page",
                    json!({
                        "type": "object",
                        "required": ["parent", "properties"],
                        "properties": {
                            "parent": { "type": "object" },
                            "properties": { "type": "object" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new page or database entry in Notion.".into(),
                        common_mistakes: vec!["Not specifying the parent database or page ID".into()],
                        examples: vec![
                            r#"{"parent": {"database_id": "abc123"}, "properties": {"Name": {"title": [{"text": {"content": "New page"}}]}}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("notion.get_page"),
                            CapabilityId::from_static("notion.query_database"),
                        ],
                    },
                ),
                op_info(
                    "notion.get_page",
                    "Retrieve a Notion page by ID",
                    json!({
                        "type": "object",
                        "required": ["page_id"],
                        "properties": {
                            "page_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve details of a specific Notion page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"page_id": "abc123-def456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.create_page"),
                            CapabilityId::from_static("notion.update_page"),
                        ],
                    },
                ),
                op_info(
                    "notion.update_page",
                    "Update properties of a Notion page",
                    json!({
                        "type": "object",
                        "required": ["page_id", "properties"],
                        "properties": {
                            "page_id": { "type": "string" },
                            "properties": { "type": "object" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Update properties on an existing Notion page.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"page_id": "abc123", "properties": {"Status": {"select": {"name": "Done"}}}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("notion.get_page")],
                    },
                ),
                op_info(
                    "notion.delete_page",
                    "Archive (soft-delete) a Notion page",
                    json!({
                        "type": "object",
                        "required": ["page_id"],
                        "properties": {
                            "page_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "notion.delete",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Archive a Notion page (soft delete).".into(),
                        common_mistakes: vec!["Expecting permanent deletion — Notion only archives".into()],
                        examples: vec![r#"{"page_id": "abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("notion.get_page")],
                    },
                ),
                op_info(
                    "notion.get_database",
                    "Retrieve a Notion database by ID",
                    json!({
                        "type": "object",
                        "required": ["database_id"],
                        "properties": {
                            "database_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "database": { "type": "object" } } }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a database schema and properties.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"database_id": "abc123-def456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.query_database"),
                            CapabilityId::from_static("notion.update_database"),
                        ],
                    },
                ),
                op_info(
                    "notion.create_database",
                    "Create a new database in a page",
                    json!({
                        "type": "object",
                        "required": ["parent", "title", "properties"],
                        "properties": {
                            "parent": { "type": "object" },
                            "title": { "type": "array" },
                            "properties": { "type": "object" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "database": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new inline database within a page.".into(),
                        common_mistakes: vec!["Not specifying at least one property definition".into()],
                        examples: vec![
                            r#"{"parent": {"page_id": "abc123"}, "title": [{"text": {"content": "Tasks"}}], "properties": {"Name": {"title": {}}}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("notion.get_database"),
                            CapabilityId::from_static("notion.query_database"),
                        ],
                    },
                ),
                op_info(
                    "notion.update_database",
                    "Update a database's title, description, or properties",
                    json!({
                        "type": "object",
                        "required": ["database_id"],
                        "properties": {
                            "database_id": { "type": "string" },
                            "title": { "type": "array" },
                            "properties": { "type": "object" },
                            "description": { "type": "array" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "database": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Update a database schema, title, or description.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"database_id": "abc123", "title": [{"text": {"content": "Updated Tasks"}}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("notion.get_database")],
                    },
                ),
                op_info(
                    "notion.query_database",
                    "Query a Notion database with filters and sorts",
                    json!({
                        "type": "object",
                        "required": ["database_id"],
                        "properties": {
                            "database_id": { "type": "string" },
                            "filter": { "type": "object" },
                            "start_cursor": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" },
                            "has_more": { "type": "boolean" },
                            "next_cursor": { "type": ["string", "null"], "description": "Cursor for the next page of results" }
                        }
                    }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Query a database with optional filters.".into(),
                        common_mistakes: vec!["Not handling pagination with start_cursor".into()],
                        examples: vec![r#"{"database_id": "abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.get_page"),
                            CapabilityId::from_static("notion.search"),
                        ],
                    },
                ),
                op_info(
                    "notion.search",
                    "Search pages and databases across the workspace (sensitive — results are redacted)",
                    json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string", "description": "Text query to search for" },
                            "filter": {
                                "type": "object",
                                "description": "Optional filter (e.g. {\"value\": \"page\", \"property\": \"object\"} to restrict to pages)"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["results", "has_more", "sensitivity", "provenance", "taint"],
                        "properties": {
                            "results": { "type": "array", "description": "Redacted search results" },
                            "has_more": { "type": "boolean" },
                            "next_cursor": { "type": ["string", "null"], "description": "Cursor for the next page of results" },
                            "result_count": { "type": "integer" },
                            "sensitivity": { "type": "string" },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "notion.search",
                    RiskLevel::Medium,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search across all pages and databases. Results include provenance metadata and PII is redacted.".into(),
                        common_mistakes: vec![
                            "Not checking the sensitivity field — search results may expose cross-workspace data".into(),
                        ],
                        examples: vec![
                            r#"{"query": "meeting notes"}"#.into(),
                            r#"{"query": "Q1 plan", "filter": {"value": "page", "property": "object"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("notion.query_database"),
                            CapabilityId::from_static("notion.get_page"),
                        ],
                    },
                ),
                op_info(
                    "notion.get_block",
                    "Retrieve a single block by ID",
                    json!({
                        "type": "object",
                        "required": ["block_id"],
                        "properties": {
                            "block_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "block": { "type": "object" } } }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a specific block by its ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"block_id": "abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.get_block_children"),
                            CapabilityId::from_static("notion.update_block"),
                        ],
                    },
                ),
                op_info(
                    "notion.update_block",
                    "Update a block's content",
                    json!({
                        "type": "object",
                        "required": ["block_id"],
                        "properties": {
                            "block_id": { "type": "string" },
                            "paragraph": { "type": "object" },
                            "heading_1": { "type": "object" },
                            "heading_2": { "type": "object" },
                            "heading_3": { "type": "object" },
                            "to_do": { "type": "object" },
                            "toggle": { "type": "object" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "block": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Update the content of a block.".into(),
                        common_mistakes: vec!["Sending the wrong block type key for the block".into()],
                        examples: vec![
                            r#"{"block_id": "abc123", "paragraph": {"rich_text": [{"text": {"content": "Updated text"}}]}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("notion.get_block"),
                            CapabilityId::from_static("notion.delete_block"),
                        ],
                    },
                ),
                op_info(
                    "notion.delete_block",
                    "Archive (soft-delete) a block",
                    json!({
                        "type": "object",
                        "required": ["block_id"],
                        "properties": {
                            "block_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "block": { "type": "object" } } }),
                    "notion.delete",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Archive a block (soft delete).".into(),
                        common_mistakes: vec!["Expecting permanent deletion — Notion only archives".into()],
                        examples: vec![r#"{"block_id": "abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("notion.get_block")],
                    },
                ),
                op_info(
                    "notion.get_block_children",
                    "Get child blocks of a block or page",
                    json!({
                        "type": "object",
                        "required": ["block_id"],
                        "properties": {
                            "block_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" },
                            "has_more": { "type": "boolean" },
                            "next_cursor": { "type": ["string", "null"], "description": "Cursor for the next page of results" }
                        }
                    }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read the content blocks of a page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"block_id": "abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.get_page"),
                            CapabilityId::from_static("notion.append_blocks"),
                        ],
                    },
                ),
                op_info(
                    "notion.append_blocks",
                    "Append child blocks to a page or block",
                    json!({
                        "type": "object",
                        "required": ["block_id", "children"],
                        "properties": {
                            "block_id": { "type": "string" },
                            "children": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" }
                        }
                    }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add content blocks to a page.".into(),
                        common_mistakes: vec![format!("Exceeding {} blocks per request", limits::BLOCKS_MAX_PER_REQUEST)],
                        examples: vec![
                            r#"{"block_id": "abc123", "children": [{"object": "block", "type": "paragraph", "paragraph": {"rich_text": [{"text": {"content": "Hello"}}]}}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("notion.get_block_children")],
                    },
                ),
                op_info(
                    "notion.add_comment",
                    "Add a comment to a page or discussion",
                    json!({
                        "type": "object",
                        "required": ["parent", "rich_text"],
                        "properties": {
                            "parent": { "type": "object" },
                            "rich_text": { "type": "array" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "comment": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add a comment to a Notion page.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"parent": {"page_id": "abc123"}, "rich_text": [{"text": {"content": "Looks good!"}}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("notion.list_comments")],
                    },
                ),
                op_info(
                    "notion.list_comments",
                    "List comments on a page or block",
                    json!({
                        "type": "object",
                        "required": ["block_id"],
                        "properties": {
                            "block_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" },
                            "has_more": { "type": "boolean" },
                            "next_cursor": { "type": ["string", "null"], "description": "Cursor for the next page of results" }
                        }
                    }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read comments on a page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"block_id": "abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("notion.add_comment")],
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
            verifier.verify(token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "notion.create_page" => self.invoke_create_page(input).await,
            "notion.get_page" => self.invoke_get_page(input).await,
            "notion.update_page" => self.invoke_update_page(input).await,
            "notion.delete_page" => self.invoke_delete_page(input).await,
            "notion.get_database" => self.invoke_get_database(input).await,
            "notion.create_database" => self.invoke_create_database(input).await,
            "notion.update_database" => self.invoke_update_database(input).await,
            "notion.query_database" => self.invoke_query_database(input).await,
            "notion.search" => self.invoke_search(input).await,
            "notion.get_block" => self.invoke_get_block(input).await,
            "notion.update_block" => self.invoke_update_block(input).await,
            "notion.delete_block" => self.invoke_delete_block(input).await,
            "notion.get_block_children" => self.invoke_get_block_children(input).await,
            "notion.append_blocks" => self.invoke_append_blocks(input).await,
            "notion.add_comment" => self.invoke_add_comment(input).await,
            "notion.list_comments" => self.invoke_list_comments(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        if input.get("parent").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: parent".into(),
            });
        }

        let page = client
            .create_page(input)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_get_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;

        let page = client
            .get_page(page_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_update_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;
        let properties = input.get("properties").cloned().unwrap_or(json!({}));

        let body = json!({ "properties": properties });
        let page = client
            .update_page(page_id, body)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_delete_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;

        let page = client
            .delete_page(page_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_get_database(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let database_id = require_str(&input, "database_id")?;

        let db = client
            .get_database(database_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "database": db }))
    }

    async fn invoke_create_database(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        if input.get("parent").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: parent".into(),
            });
        }
        if input.get("title").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: title".into(),
            });
        }
        if input.get("properties").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: properties".into(),
            });
        }

        let db = client
            .create_database(input)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "database": db }))
    }

    async fn invoke_update_database(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let database_id = require_str(&input, "database_id")?;

        let mut body = json!({});
        if let Some(title) = input.get("title") {
            body["title"] = title.clone();
        }
        if let Some(props) = input.get("properties") {
            body["properties"] = props.clone();
        }
        if let Some(desc) = input.get("description") {
            body["description"] = desc.clone();
        }

        let db = client
            .update_database(database_id, body)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "database": db }))
    }

    async fn invoke_query_database(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let database_id = require_str(&input, "database_id")?;
        let filter = input.get("filter").cloned();
        let start_cursor = input.get("start_cursor").and_then(|v| v.as_str());

        let result = client
            .query_database(database_id, filter, start_cursor)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor
        }))
    }

    async fn invoke_search(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = input.get("query").and_then(|v| v.as_str());
        let filter = input.get("filter").cloned();

        let result = client
            .search(query, filter)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        // Redact PII from search results — search can expose data across
        // the entire workspace, so strip email/person fields before returning.
        let redacted: Vec<serde_json::Value> = result
            .results
            .into_iter()
            .map(redact_search_result)
            .collect();

        Ok(json!({
            "results": redacted,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor,
            "result_count": redacted.len(),
            "sensitivity": "workspace_wide",
            "provenance": {
                "source": "notion.search",
                "derived": false,
                "scope": "workspace"
            },
            "taint": ["external_input", "cross_workspace"]
        }))
    }

    async fn invoke_get_block(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let block = client
            .get_block(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "block": block }))
    }

    async fn invoke_update_block(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        // Extract the block content (everything except block_id)
        let mut body = input.clone();
        if let Some(obj) = body.as_object_mut() {
            obj.remove("block_id");
        }

        let block = client
            .update_block(block_id, body)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "block": block }))
    }

    async fn invoke_delete_block(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let block = client
            .delete_block(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "block": block }))
    }

    async fn invoke_get_block_children(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let result = client
            .get_block_children(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor
        }))
    }

    async fn invoke_append_blocks(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let children = input
            .get("children")
            .cloned()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: children".into(),
            })?;

        let result = client
            .append_blocks(block_id, children)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "results": result.results }))
    }

    async fn invoke_add_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        if input.get("parent").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: parent".into(),
            });
        }

        let comment = client
            .add_comment(input)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "comment": comment }))
    }

    async fn invoke_list_comments(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let result = client
            .list_comments(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Notion connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for NotionConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

/// Redact PII from a single search result object.
///
/// Search results can include person mentions with email addresses, internal
/// URLs, and other sensitive workspace data. This strips or masks such fields
/// to prevent accidental PII leakage in downstream processing.
fn redact_search_result(mut item: serde_json::Value) -> serde_json::Value {
    // Redact `people` and `person` property values (contain email addresses)
    if let Some(props) = item.get_mut("properties") {
        if let Some(obj) = props.as_object_mut() {
            for value in obj.values_mut() {
                redact_person_fields(value);
            }
        }
    }

    // Redact `created_by` and `last_edited_by` email fields
    for key in &["created_by", "last_edited_by"] {
        if let Some(user) = item.get_mut(*key) {
            redact_user_email(user);
        }
    }

    item
}

/// Redact email addresses from person-type property values.
fn redact_person_fields(prop: &mut serde_json::Value) {
    let prop_type = prop
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_owned();

    match prop_type.as_str() {
        "people" => {
            if let Some(people) = prop.get_mut("people") {
                if let Some(arr) = people.as_array_mut() {
                    for person in arr.iter_mut() {
                        redact_user_email(person);
                    }
                }
            }
        }
        "created_by" | "last_edited_by" => {
            if let Some(user) = prop.get_mut(&prop_type) {
                redact_user_email(user);
            }
        }
        _ => {}
    }
}

/// Replace an email field on a user object with a redacted placeholder.
fn redact_user_email(user: &mut serde_json::Value) {
    if let Some(person) = user.get_mut("person") {
        if person.get("email").is_some() {
            person["email"] = json!("[redacted]");
        }
    }
}

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

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        operations: &[&str],
    ) -> CapabilityToken {
        use fcp_core::CapabilityConstraints;

        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();

        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .constraints_cbor(&constraints_cbor)
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["notion.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = NotionConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = NotionConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["notion.get_page"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "notion.read", &["notion.get_page"]);

        let result = connector
            .handle_invoke(json!({
                "operation": "notion.get_page",
                "input": { "page_id": "page-123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.get_page"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "notion.read", &["notion.get_page"]);

        let result = connector
            .handle_invoke(json!({
                "operation": "notion.get_page",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("page_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = NotionConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"notion.create_page"));
        assert!(op_ids.contains(&"notion.get_page"));
        assert!(op_ids.contains(&"notion.update_page"));
        assert!(op_ids.contains(&"notion.delete_page"));
        assert!(op_ids.contains(&"notion.get_database"));
        assert!(op_ids.contains(&"notion.create_database"));
        assert!(op_ids.contains(&"notion.update_database"));
        assert!(op_ids.contains(&"notion.query_database"));
        assert!(op_ids.contains(&"notion.search"));
        assert!(op_ids.contains(&"notion.get_block"));
        assert!(op_ids.contains(&"notion.update_block"));
        assert!(op_ids.contains(&"notion.delete_block"));
        assert!(op_ids.contains(&"notion.get_block_children"));
        assert!(op_ids.contains(&"notion.append_blocks"));
        assert!(op_ids.contains(&"notion.add_comment"));
        assert!(op_ids.contains(&"notion.list_comments"));
        assert_eq!(ops.len(), 16);
    }

    // ── Invoke missing-field tests for new operations ──────────────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_database_missing_field() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.get_database"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "notion.read", &["notion.get_database"]);

        let result = connector
            .handle_invoke(json!({
                "operation": "notion.get_database",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("database_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_database_missing_fields() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.create_database"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "notion.write", &["notion.create_database"]);

        // Missing parent
        let result = connector
            .handle_invoke(json!({
                "operation": "notion.create_database",
                "input": {"title": [], "properties": {}},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("parent"));
            }
            e => panic!("Expected InvalidRequest for parent, got: {e:?}"),
        }

        // Missing title
        let token2 =
            generate_valid_token(&signing_key, "notion.write", &["notion.create_database"]);
        let result2 = connector
            .handle_invoke(json!({
                "operation": "notion.create_database",
                "input": {"parent": {"page_id": "p1"}, "properties": {}},
                "capability_token": token2
            }))
            .await;
        assert!(result2.is_err());
        match result2.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("title"));
            }
            e => panic!("Expected InvalidRequest for title, got: {e:?}"),
        }

        // Missing properties
        let token3 =
            generate_valid_token(&signing_key, "notion.write", &["notion.create_database"]);
        let result3 = connector
            .handle_invoke(json!({
                "operation": "notion.create_database",
                "input": {"parent": {"page_id": "p1"}, "title": []},
                "capability_token": token3
            }))
            .await;
        assert!(result3.is_err());
        match result3.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("properties"));
            }
            e => panic!("Expected InvalidRequest for properties, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_block_missing_field() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.get_block"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "notion.read", &["notion.get_block"]);

        let result = connector
            .handle_invoke(json!({
                "operation": "notion.get_block",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("block_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_delete_block_missing_field() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "http://localhost:9999/v1"
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
                "capabilities_requested": ["notion.delete_block"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "notion.delete", &["notion.delete_block"]);

        let result = connector
            .handle_invoke(json!({
                "operation": "notion.delete_block",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("block_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels() {
        let connector = NotionConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        // Verify read ops are safe
        for read_op in &[
            "notion.get_page",
            "notion.get_database",
            "notion.query_database",
            "notion.get_block",
            "notion.get_block_children",
            "notion.list_comments",
        ] {
            let op = ops.iter().find(|o| o["id"] == *read_op).unwrap();
            assert_eq!(op["risk_level"], "low", "{read_op} should be low risk");
            assert_eq!(op["safety_tier"], "safe", "{read_op} should be safe");
        }

        // Verify search is medium risk (sensitive cross-workspace operation)
        let search_op = ops.iter().find(|o| o["id"] == "notion.search").unwrap();
        assert_eq!(
            search_op["risk_level"], "medium",
            "search should be medium risk"
        );
        assert_eq!(
            search_op["safety_tier"], "safe",
            "search is safe (read-only)"
        );
        assert_eq!(
            search_op["capability"], "notion.search",
            "search uses dedicated cap"
        );

        // Verify write ops are risky
        for write_op in &[
            "notion.create_page",
            "notion.update_page",
            "notion.create_database",
            "notion.update_database",
            "notion.update_block",
            "notion.append_blocks",
            "notion.add_comment",
        ] {
            let op = ops.iter().find(|o| o["id"] == *write_op).unwrap();
            assert_eq!(
                op["risk_level"], "medium",
                "{write_op} should be medium risk"
            );
            assert_eq!(op["safety_tier"], "risky", "{write_op} should be risky");
        }

        // Verify delete ops are high risk
        for del_op in &["notion.delete_page", "notion.delete_block"] {
            let op = ops.iter().find(|o| o["id"] == *del_op).unwrap();
            assert_eq!(op["risk_level"], "high", "{del_op} should be high risk");
        }
    }

    // ── Provisioning automation tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_token() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_configure(json!({ "token": "ntn_test123" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = NotionConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth_modes() {
        let mut connector = NotionConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "credential_id": cid
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
    async fn test_configure_rejects_no_auth() {
        let mut connector = NotionConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing authentication"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_api_url() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "api_url": "https://custom-notion.example.com/v1"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.api_url, "https://custom-notion.example.com/v1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_notion_version() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "notion_version": "2025-09-03"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.notion_version.as_deref(), Some("2025-09-03"));
        assert_eq!(
            connector.client.as_ref().unwrap().notion_version(),
            "2025-09-03"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_invalid_notion_version() {
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ntn_test123",
                "notion_version": "2026/03/11"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("notion_version must look like"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({ "token": "ntn_test123" }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert!(health["auth_mode"].as_str().unwrap().contains("token"));
        assert!(health["api_url"].as_str().is_some());
        assert_eq!(health["notion_version"], DEFAULT_NOTION_VERSION);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = NotionConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 7);
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = NotionConnector::new();
        connector
            .handle_configure(json!({ "token": "ntn_test123" }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 7);
        let version_check = checks
            .iter()
            .find(|check| check["name"] == "notion_version")
            .unwrap();
        assert_eq!(version_check["status"], "healthy");
        assert_eq!(
            version_check["message"],
            format!("Notion-Version header: {DEFAULT_NOTION_VERSION}")
        );
        for check in checks {
            assert_eq!(check["status"], "healthy");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = NotionConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "healthy");
        assert!(
            cred_check["message"]
                .as_str()
                .unwrap()
                .contains("Secretless")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = NotionConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = NotionConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    // ── Redaction unit tests (u56.4) ──────────────────────────────────

    #[test]
    fn redact_search_result_strips_person_emails() {
        let mut item = json!({
            "object": "page",
            "id": "pg-1",
            "properties": {
                "Assignee": {
                    "type": "people",
                    "people": [{
                        "object": "user",
                        "id": "u1",
                        "name": "Alice",
                        "person": { "email": "alice@example.com" }
                    }]
                }
            }
        });

        item = super::redact_search_result(item);

        assert_eq!(
            item["properties"]["Assignee"]["people"][0]["person"]["email"],
            "[redacted]"
        );
        assert_eq!(item["properties"]["Assignee"]["people"][0]["name"], "Alice");
    }

    #[test]
    fn redact_search_result_strips_created_by_email() {
        let mut item = json!({
            "object": "page",
            "id": "pg-2",
            "created_by": {
                "object": "user",
                "id": "u1",
                "person": { "email": "alice@acme.com" }
            },
            "last_edited_by": {
                "object": "user",
                "id": "u2",
                "person": { "email": "bob@acme.com" }
            }
        });

        item = super::redact_search_result(item);

        assert_eq!(item["created_by"]["person"]["email"], "[redacted]");
        assert_eq!(item["last_edited_by"]["person"]["email"], "[redacted]");
    }

    #[test]
    fn redact_search_result_preserves_non_pii_fields() {
        let item = json!({
            "object": "page",
            "id": "pg-3",
            "properties": {
                "Title": {
                    "type": "title",
                    "title": [{ "text": { "content": "Important" } }]
                }
            },
            "url": "https://notion.so/Important"
        });

        let redacted = super::redact_search_result(item);

        assert_eq!(redacted["id"], "pg-3");
        assert_eq!(redacted["url"], "https://notion.so/Important");
        assert_eq!(
            redacted["properties"]["Title"]["title"][0]["text"]["content"],
            "Important"
        );
    }

    #[test]
    fn redact_search_result_handles_no_person_data() {
        let item = json!({
            "object": "database",
            "id": "db-1",
            "properties": {
                "Name": { "type": "title", "title": {} }
            }
        });

        // Should not panic or modify anything
        let redacted = super::redact_search_result(item);
        assert_eq!(redacted["id"], "db-1");
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
