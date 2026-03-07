//! FCP Zendesk Connector implementation.

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

use crate::client::{ZendeskAuth, ZendeskClient};
use crate::error::ZendeskError;

// ── Provisioning configuration ───────────────────────────────────────

/// Parsed and validated Zendesk configuration.
struct ZendeskConfig {
    auth: ZendeskAuth,
    base_url: Option<String>,
}

impl ZendeskConfig {
    /// Parse and validate configuration parameters.
    ///
    /// Requires `subdomain` always. Auth is xor: (`email` + `api_token`) xor `credential_id`.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let subdomain =
            params
                .get("subdomain")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required 'subdomain' in configuration".into(),
                })?;

        let email = params.get("email").and_then(|v| v.as_str());
        let api_token = params.get("api_token").and_then(|v| v.as_str());
        let credential_id_raw = params.get("credential_id").and_then(|v| v.as_str());
        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .map(String::from);

        let auth = match (email, api_token, credential_id_raw) {
            (Some(e), Some(t), None) => ZendeskAuth::Token {
                subdomain: subdomain.into(),
                email: e.into(),
                api_token: t.into(),
            },
            (None, None, Some(raw)) => {
                let cred = CredentialId::parse(raw).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid credential_id: {e}"),
                })?;
                ZendeskAuth::CredentialId {
                    subdomain: subdomain.into(),
                    credential_id: cred,
                }
            }
            (Some(_), None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Incomplete auth: 'email' provided without 'api_token'".into(),
                });
            }
            (None, Some(_), None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Incomplete auth: 'api_token' provided without 'email'".into(),
                });
            }
            (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "Conflicting auth: provide (email + api_token) or credential_id, not both"
                            .into(),
                });
            }
            (None, None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing auth: provide (email + api_token) or credential_id".into(),
                });
            }
        };

        Ok(Self { auth, base_url })
    }
}

// ── Doctor types ─────────────────────────────────────────────────────

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
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

// ── Connector ────────────────────────────────────────────────────────

/// FCP Zendesk Connector.
pub struct ZendeskConnector {
    base: Arc<BaseConnector>,
    config: Option<ZendeskConfig>,
    client: Option<ZendeskClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl ZendeskConnector {
    /// Create a new Zendesk connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("zendesk"))),
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
        let config = ZendeskConfig::from_params(&params)?;

        let mut client =
            ZendeskClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if let Some(ref url) = config.base_url {
            client = client.with_base_url(url);
        }

        let auth_mode = config.auth.redacted_label();
        info!(
            auth_mode,
            subdomain = config.auth.subdomain(),
            "Zendesk connector configured"
        );

        self.client = Some(client);
        self.config = Some(config);
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
            manifest_hash: "sha256:zendesk-connector-v1".into(),
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

        let mut result = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });

        if let Some(ref config) = self.config {
            result["auth_mode"] = json!(config.auth.redacted_label());
            result["api_domain"] = json!(format!("{}.zendesk.com", config.auth.subdomain()));
        }

        Ok(result)
    }

    /// Handle doctor readiness checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. Configuration
        let config_ok = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            status: if config_ok {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if config_ok {
                "Connector is configured".into()
            } else {
                "Connector is not configured — call 'configure' first".into()
            },
        });

        // 2. Client initialized
        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            status: if client_ok {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client not initialized".into()
            },
        });

        // 3. Base URL
        if let Some(ref config) = self.config {
            let subdomain = config.auth.subdomain();
            let default_url = format!("https://{subdomain}.zendesk.com/api/v2");
            let url_info = config.base_url.as_deref().unwrap_or(&default_url);
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Pass,
                message: format!("Subdomain: {subdomain}.zendesk.com (via {url_info})"),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Warn,
                message: "No configuration — cannot determine base URL".into(),
            });
        }

        // 4. Auth mode
        if let Some(ref config) = self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Pass,
                message: format!("Auth: {}", config.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Fail,
                message: "No auth configured".into(),
            });
        }

        // 5. Network constraints
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Pass,
            message: "Egress target: *.zendesk.com (HTTPS)".into(),
        });

        // 6. Credential injection
        if let Some(ref config) = self.config {
            if config.auth.is_secretless() {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Pass,
                    message: "Secretless egress proxy mode — no secrets on disk".into(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Warn,
                    message: "Direct token mode — consider credential_id for production".into(),
                });
            }
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Fail,
                message: "No auth configured".into(),
            });
        }

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Fail) {
            DoctorStatus::Fail
        } else if checks.iter().any(|c| c.status == DoctorStatus::Warn) {
            DoctorStatus::Warn
        } else {
            DoctorStatus::Pass
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle connector self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(ref config) = self.config else {
            let report = SelfCheckReport::failed("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode we cannot verify connectivity without egress proxy
        if config.auth.is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Secretless mode — connectivity check requires egress proxy at runtime",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let Some(ref client) = self.client else {
            let report =
                SelfCheckReport::failed("client_not_initialized", "HTTP client not available");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match client.health_check().await {
            Ok(data) => {
                let mut report = SelfCheckReport::ok();
                if let Some(user) = data.get("user") {
                    report.details = Some(json!({
                        "user_id": user.get("id"),
                        "name": user.get("name"),
                        "email": user.get("email"),
                    }));
                }
                report
            }
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
                    "zendesk.create_ticket",
                    "Create a new support ticket",
                    json!({
                        "type": "object",
                        "required": ["subject"],
                        "properties": {
                            "subject": { "type": "string", "maxLength": 255 },
                            "description": { "type": "string" },
                            "priority": { "type": "string", "enum": ["urgent", "high", "normal", "low"] },
                            "status": { "type": "string", "enum": ["new", "open", "pending", "hold", "solved", "closed"] },
                            "type": { "type": "string", "enum": ["problem", "incident", "question", "task"] },
                            "requester_id": { "type": "integer" },
                            "assignee_id": { "type": "integer" },
                            "group_id": { "type": "integer" },
                            "tags": { "type": "array", "items": { "type": "string" } },
                            "custom_fields": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    json!({ "type": "object", "required": ["ticket"], "properties": { "ticket": { "type": "object" } } }),
                    "zendesk.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new support ticket. At minimum requires a subject.".into(),
                        common_mistakes: vec![
                            "Not providing a description (creates an empty ticket).".into(),
                            "Using group name instead of group_id.".into(),
                        ],
                        examples: vec![
                            r#"{"subject": "Login issue", "description": "Cannot log in since update", "priority": "high", "type": "problem"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("zendesk.get_ticket"),
                            CapabilityId::from_static("zendesk.update_ticket"),
                            CapabilityId::from_static("zendesk.search_tickets"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.get_ticket",
                    "Get a single ticket by ID",
                    json!({
                        "type": "object",
                        "required": ["ticket_id"],
                        "properties": { "ticket_id": { "type": "integer" } }
                    }),
                    json!({ "type": "object", "required": ["ticket"], "properties": { "ticket": { "type": "object" } } }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a specific ticket by its numeric ID.".into(),
                        common_mistakes: vec!["Using ticket subject instead of ticket ID.".into()],
                        examples: vec![r#"{"ticket_id": 12345}"#.into()],
                        related: vec![
                            CapabilityId::from_static("zendesk.update_ticket"),
                            CapabilityId::from_static("zendesk.list_ticket_comments"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.update_ticket",
                    "Update fields on an existing ticket",
                    json!({
                        "type": "object",
                        "required": ["ticket_id"],
                        "properties": {
                            "ticket_id": { "type": "integer" },
                            "status": { "type": "string", "enum": ["new", "open", "pending", "hold", "solved", "closed"] },
                            "priority": { "type": "string", "enum": ["urgent", "high", "normal", "low"] },
                            "assignee_id": { "type": "integer" },
                            "tags": { "type": "array", "items": { "type": "string" } },
                            "comment": { "type": "object" },
                            "custom_fields": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    json!({ "type": "object", "required": ["ticket"], "properties": { "ticket": { "type": "object" } } }),
                    "zendesk.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Modify ticket fields (status, priority, assignee, tags). Can also add a comment in the same call.".into(),
                        common_mistakes: vec![
                            "Setting status to 'closed' directly (must go through 'solved' first in most workflows).".into(),
                            "Not including a comment body when adding a public comment.".into(),
                        ],
                        examples: vec![
                            r#"{"ticket_id": 12345, "status": "solved", "comment": {"body": "Issue resolved.", "public": true}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("zendesk.get_ticket"),
                            CapabilityId::from_static("zendesk.list_ticket_comments"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.delete_ticket",
                    "Permanently delete a ticket (irreversible)",
                    json!({
                        "type": "object",
                        "required": ["ticket_id"],
                        "properties": { "ticket_id": { "type": "integer" } }
                    }),
                    json!({ "type": "object" }),
                    "zendesk.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete a ticket. Cannot be undone.".into(),
                        common_mistakes: vec!["Deleting tickets that should be 'closed' instead.".into()],
                        examples: vec![r#"{"ticket_id": 12345}"#.into()],
                        related: vec![CapabilityId::from_static("zendesk.get_ticket")],
                    },
                ),
                op_info(
                    "zendesk.search_tickets",
                    "Search tickets using Zendesk search syntax with pagination",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "sort_by": { "type": "string", "enum": ["created_at", "updated_at", "priority", "status", "ticket_type"] },
                            "sort_order": { "type": "string", "enum": ["asc", "desc"] },
                            "page": { "type": "integer", "minimum": 1 },
                            "per_page": { "type": "integer", "minimum": 1, "maximum": 100 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["results", "count"],
                        "properties": {
                            "results": { "type": "array", "items": { "type": "object" } },
                            "count": { "type": "integer" },
                            "next_page": { "type": "string" }
                        }
                    }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search tickets using Zendesk query syntax. Supports filtering by status, priority, assignee, tags, and more.".into(),
                        common_mistakes: vec![
                            "Using JQL or SQL syntax instead of Zendesk search syntax.".into(),
                            "Not handling pagination for large result sets.".into(),
                            "Search results are eventually consistent -- may not include very recent tickets.".into(),
                        ],
                        examples: vec![
                            r#"{"query": "status:open priority:urgent", "sort_by": "created_at", "sort_order": "desc"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("zendesk.get_ticket"),
                            CapabilityId::from_static("zendesk.create_ticket"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.list_ticket_comments",
                    "List comments on a ticket",
                    json!({
                        "type": "object",
                        "required": ["ticket_id"],
                        "properties": {
                            "ticket_id": { "type": "integer" },
                            "sort_order": { "type": "string", "enum": ["asc", "desc"] }
                        }
                    }),
                    json!({ "type": "object", "required": ["comments"], "properties": { "comments": { "type": "array", "items": { "type": "object" } } } }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve the comment thread on a ticket.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"ticket_id": 12345, "sort_order": "asc"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("zendesk.get_ticket"),
                            CapabilityId::from_static("zendesk.update_ticket"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.search_articles",
                    "Search Help Center knowledge base articles",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "locale": { "type": "string" },
                            "category_id": { "type": "integer" },
                            "per_page": { "type": "integer", "minimum": 1, "maximum": 100 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["results", "count"],
                        "properties": {
                            "results": { "type": "array", "items": { "type": "object" } },
                            "count": { "type": "integer" }
                        }
                    }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search the Help Center knowledge base for articles matching a query.".into(),
                        common_mistakes: vec!["Not specifying locale for multi-language Help Centers.".into()],
                        examples: vec![r#"{"query": "password reset", "locale": "en-us"}"#.into()],
                        related: vec![CapabilityId::from_static("zendesk.get_article")],
                    },
                ),
                op_info(
                    "zendesk.get_article",
                    "Get a single Help Center article by ID",
                    json!({
                        "type": "object",
                        "required": ["article_id"],
                        "properties": {
                            "article_id": { "type": "integer" },
                            "locale": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "required": ["article"], "properties": { "article": { "type": "object" } } }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a specific Help Center article by its ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"article_id": 360001234567}"#.into()],
                        related: vec![CapabilityId::from_static("zendesk.search_articles")],
                    },
                ),
                op_info(
                    "zendesk.search_users",
                    "Search Zendesk users (customers and agents)",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["users", "count"],
                        "properties": {
                            "users": { "type": "array", "items": { "type": "object" } },
                            "count": { "type": "integer" }
                        }
                    }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for customers or agents by name, email, or other criteria.".into(),
                        common_mistakes: vec!["Not using quotes for exact email matches.".into()],
                        examples: vec![r#"{"query": "email:customer@example.com"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("zendesk.create_ticket"),
                            CapabilityId::from_static("zendesk.get_ticket"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.apply_macro",
                    "Apply a macro to a ticket (predefined set of actions)",
                    json!({
                        "type": "object",
                        "required": ["ticket_id", "macro_id"],
                        "properties": {
                            "ticket_id": { "type": "integer" },
                            "macro_id": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "required": ["result"], "properties": { "result": { "type": "object" } } }),
                    "zendesk.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Apply a predefined macro to a ticket. Macros can change status, add comments, set fields, etc.".into(),
                        common_mistakes: vec!["Using macro name instead of macro_id.".into()],
                        examples: vec![r#"{"ticket_id": 12345, "macro_id": 67890}"#.into()],
                        related: vec![CapabilityId::from_static("zendesk.update_ticket")],
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
            "zendesk.create_ticket" => self.invoke_create_ticket(input).await,
            "zendesk.get_ticket" => self.invoke_get_ticket(input).await,
            "zendesk.update_ticket" => self.invoke_update_ticket(input).await,
            "zendesk.delete_ticket" => self.invoke_delete_ticket(input).await,
            "zendesk.search_tickets" => self.invoke_search_tickets(input).await,
            "zendesk.list_ticket_comments" => self.invoke_list_ticket_comments(input).await,
            "zendesk.search_articles" => self.invoke_search_articles(input).await,
            "zendesk.get_article" => self.invoke_get_article(input).await,
            "zendesk.search_users" => self.invoke_search_users(input).await,
            "zendesk.apply_macro" => self.invoke_apply_macro(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_ticket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        require_str(&input, "subject")?;
        let result = client
            .create_ticket(&input)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_get_ticket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        let result = client
            .get_ticket(ticket_id)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_update_ticket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        // Build the update payload excluding ticket_id
        let mut update_data = input.clone();
        if let Some(obj) = update_data.as_object_mut() {
            obj.remove("ticket_id");
        }
        let result = client
            .update_ticket(ticket_id, &update_data)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_delete_ticket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        let result = client
            .delete_ticket(ticket_id)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_search_tickets(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let sort_by = input.get("sort_by").and_then(|v| v.as_str());
        let sort_order = input.get("sort_order").and_then(|v| v.as_str());
        let page = input.get("page").and_then(|v| v.as_i64());
        let per_page = input.get("per_page").and_then(|v| v.as_i64());
        let result = client
            .search_tickets(query, sort_by, sort_order, page, per_page)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_list_ticket_comments(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        let sort_order = input.get("sort_order").and_then(|v| v.as_str());
        let result = client
            .list_ticket_comments(ticket_id, sort_order)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_search_articles(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let locale = input.get("locale").and_then(|v| v.as_str());
        let category_id = input.get("category_id").and_then(|v| v.as_i64());
        let per_page = input.get("per_page").and_then(|v| v.as_i64());
        let result = client
            .search_articles(query, locale, category_id, per_page)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_get_article(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let article_id = require_i64(&input, "article_id")?;
        let locale = input.get("locale").and_then(|v| v.as_str());
        let result = client
            .get_article(article_id, locale)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_search_users(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let result = client
            .search_users(query)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_apply_macro(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        let macro_id = require_i64(&input, "macro_id")?;
        let result = client
            .apply_macro(ticket_id, macro_id)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Zendesk connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for ZendeskConnector {
    fn default() -> Self {
        Self::new()
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

fn require_i64(input: &serde_json::Value, field: &str) -> FcpResult<i64> {
    input
        .get(field)
        .and_then(|v| v.as_i64())
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
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["zendesk.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = ZendeskConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["zendesk.get_ticket"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "zendesk.get_ticket");
        let result = connector
            .handle_invoke(json!({
                "operation": "zendesk.get_ticket",
                "input": { "ticket_id": 123 },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = ZendeskConnector::new();
        connector
            .handle_configure(json!({
                "subdomain": "test",
                "email": "user@test.com",
                "api_token": "token123",
                "base_url": "http://localhost:9999/api/v2"
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
                "capabilities_requested": ["zendesk.get_ticket"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "zendesk.get_ticket");
        let result = connector
            .handle_invoke(json!({
                "operation": "zendesk.get_ticket",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("ticket_id")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"zendesk.create_ticket"));
        assert!(op_ids.contains(&"zendesk.get_ticket"));
        assert!(op_ids.contains(&"zendesk.update_ticket"));
        assert!(op_ids.contains(&"zendesk.delete_ticket"));
        assert!(op_ids.contains(&"zendesk.search_tickets"));
        assert!(op_ids.contains(&"zendesk.list_ticket_comments"));
        assert!(op_ids.contains(&"zendesk.search_articles"));
        assert!(op_ids.contains(&"zendesk.get_article"));
        assert!(op_ids.contains(&"zendesk.search_users"));
        assert!(op_ids.contains(&"zendesk.apply_macro"));
        assert_eq!(ops.len(), 10);
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

    // ── Provisioning tests ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_token_auth() {
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_configure(json!({
                "subdomain": "mycompany",
                "email": "agent@mycompany.com",
                "api_token": "secret_token"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert!(!connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = ZendeskConnector::new();
        let cred_id = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "subdomain": "mycompany",
                "credential_id": cred_id
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_subdomain() {
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_configure(json!({
                "email": "user@example.com",
                "api_token": "token"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("subdomain")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth() {
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_configure(json!({ "subdomain": "mycompany" }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("Missing auth")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_conflicting_auth() {
        let mut connector = ZendeskConnector::new();
        let cred_id = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "subdomain": "mycompany",
                "email": "user@example.com",
                "api_token": "token",
                "credential_id": cred_id
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Conflicting auth"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_email_without_api_token() {
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_configure(json!({
                "subdomain": "mycompany",
                "email": "user@example.com"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("email") && message.contains("api_token"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_api_token_without_email() {
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_configure(json!({
                "subdomain": "mycompany",
                "api_token": "token"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("api_token") && message.contains("email"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "fail");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.len() >= 6);
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "fail");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_token() {
        let mut connector = ZendeskConnector::new();
        connector
            .handle_configure(json!({
                "subdomain": "testco",
                "email": "user@testco.com",
                "api_token": "tok123"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "warn"); // warn because direct token mode
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "warn");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = ZendeskConnector::new();
        let cred_id = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({
                "subdomain": "testco",
                "credential_id": cred_id
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "pass");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = ZendeskConnector::new();
        let cred_id = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({
                "subdomain": "testco",
                "credential_id": cred_id
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_mode() {
        let mut connector = ZendeskConnector::new();
        connector
            .handle_configure(json!({
                "subdomain": "testco",
                "email": "user@testco.com",
                "api_token": "tok123"
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert!(result["auth_mode"].as_str().unwrap().contains("token"));
        assert!(
            result["api_domain"]
                .as_str()
                .unwrap()
                .contains("testco.zendesk.com")
        );
    }

    // ─── DoctorStatus serde tests ─────────────────────────────────

    #[test]
    fn test_doctor_status_pass_serde() {
        let val = serde_json::to_value(DoctorStatus::Pass).unwrap();
        assert_eq!(val, "pass");
        let back: DoctorStatus = serde_json::from_value(val).unwrap();
        assert_eq!(back, DoctorStatus::Pass);
    }

    #[test]
    fn test_doctor_status_warn_serde() {
        let val = serde_json::to_value(DoctorStatus::Warn).unwrap();
        assert_eq!(val, "warn");
        let back: DoctorStatus = serde_json::from_value(val).unwrap();
        assert_eq!(back, DoctorStatus::Warn);
    }

    #[test]
    fn test_doctor_status_fail_serde() {
        let val = serde_json::to_value(DoctorStatus::Fail).unwrap();
        assert_eq!(val, "fail");
        let back: DoctorStatus = serde_json::from_value(val).unwrap();
        assert_eq!(back, DoctorStatus::Fail);
    }

    #[test]
    fn test_doctor_status_clone() {
        let original = DoctorStatus::Warn;
        let cloned = original;
        assert_eq!(cloned, DoctorStatus::Warn);
    }

    #[test]
    fn test_doctor_status_debug() {
        let s = format!("{:?}", DoctorStatus::Pass);
        assert!(s.contains("Pass"));
    }

    #[test]
    fn test_doctor_status_eq() {
        assert_eq!(DoctorStatus::Pass, DoctorStatus::Pass);
        assert_ne!(DoctorStatus::Pass, DoctorStatus::Fail);
        assert_ne!(DoctorStatus::Warn, DoctorStatus::Fail);
    }

    // ─── DoctorCheck serde tests ──────────────────────────────────

    #[test]
    fn test_doctor_check_serde_roundtrip() {
        let check = DoctorCheck {
            name: "test_check".into(),
            status: DoctorStatus::Pass,
            message: "All good".into(),
        };
        let val = serde_json::to_value(&check).unwrap();
        assert_eq!(val["name"], "test_check");
        assert_eq!(val["status"], "pass");
        assert_eq!(val["message"], "All good");
    }

    #[test]
    fn test_doctor_check_debug() {
        let check = DoctorCheck {
            name: "config".into(),
            status: DoctorStatus::Fail,
            message: "Not configured".into(),
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
        assert!(dbg.contains("config"));
    }

    // ─── DoctorResult serde tests ─────────────────────────────────

    #[test]
    fn test_doctor_result_serde_roundtrip() {
        let result = DoctorResult {
            status: DoctorStatus::Warn,
            checks: vec![
                DoctorCheck {
                    name: "config".into(),
                    status: DoctorStatus::Pass,
                    message: "ok".into(),
                },
                DoctorCheck {
                    name: "auth".into(),
                    status: DoctorStatus::Warn,
                    message: "direct token".into(),
                },
            ],
        };
        let val = serde_json::to_value(&result).unwrap();
        assert_eq!(val["status"], "warn");
        assert_eq!(val["checks"].as_array().unwrap().len(), 2);
        assert_eq!(val["checks"][0]["name"], "config");
        assert_eq!(val["checks"][1]["status"], "warn");
    }

    #[test]
    fn test_doctor_result_empty_checks() {
        let result = DoctorResult {
            status: DoctorStatus::Pass,
            checks: vec![],
        };
        let val = serde_json::to_value(&result).unwrap();
        assert_eq!(val["status"], "pass");
        assert!(val["checks"].as_array().unwrap().is_empty());
    }

    // ─── Introspect metadata tests ────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_required_metadata() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            assert!(op["id"].is_string(), "op missing id: {op}");
            assert!(op["summary"].is_string(), "op missing summary");
            assert!(op["input_schema"].is_object(), "op missing input_schema");
            assert!(op["output_schema"].is_object(), "op missing output_schema");
            assert!(op["capability"].is_string(), "op missing capability");
            assert!(op["risk_level"].is_string(), "op missing risk_level");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels_valid() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid_levels = ["low", "medium", "high", "critical"];
        for op in ops {
            let level = op["risk_level"].as_str().unwrap();
            assert!(
                valid_levels.contains(&level),
                "Invalid risk_level for {}: {level}",
                op["id"]
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_read_ops_are_safe() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "zendesk.get_ticket",
            "zendesk.search_tickets",
            "zendesk.list_ticket_comments",
            "zendesk.search_articles",
            "zendesk.get_article",
            "zendesk.search_users",
        ];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(op["risk_level"], "low", "Read op {id} should be low risk");
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_delete_op_is_high_risk() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let delete_op = ops
            .iter()
            .find(|o| o["id"] == "zendesk.delete_ticket")
            .unwrap();
        assert_eq!(delete_op["risk_level"], "high");
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_deterministic() {
        let connector = ZendeskConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        assert_eq!(a, b);
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_input_schemas_are_object_type() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert_eq!(
                op["input_schema"]["type"], "object",
                "Input schema for {id} must be type=object"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_create_ticket_requires_subject() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "zendesk.create_ticket")
            .unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "subject"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_get_ticket_requires_ticket_id() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "zendesk.get_ticket")
            .unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "ticket_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_search_tickets_requires_query() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "zendesk.search_tickets")
            .unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "query"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_apply_macro_requires_ticket_id_and_macro_id() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "zendesk.apply_macro")
            .unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "ticket_id"));
        assert!(required.iter().any(|v| v == "macro_id"));
    }

    // ─── Connector new/default ────────────────────────────────────

    #[test]
    fn test_connector_new_has_no_config() {
        let connector = ZendeskConnector::new();
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
    }

    #[test]
    fn test_connector_default_equals_new() {
        let a = ZendeskConnector::new();
        let b = ZendeskConnector::default();
        assert!(a.config.is_none());
        assert!(b.config.is_none());
        assert!(a.client.is_none());
        assert!(b.client.is_none());
    }

    // ─── ZendeskConfig from_params edge cases ─────────────────────

    #[test]
    fn test_config_from_params_missing_subdomain() {
        let params = json!({ "email": "a@b.com", "api_token": "t" });
        let result = ZendeskConfig::from_params(&params);
        match result {
            Err(FcpError::InvalidRequest { message, .. }) => {
                assert!(message.contains("subdomain"));
            }
            Err(e) => panic!("Expected InvalidRequest, got: {e:?}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn test_config_from_params_token_auth() {
        let params = json!({
            "subdomain": "acme",
            "email": "user@acme.com",
            "api_token": "secret"
        });
        match ZendeskConfig::from_params(&params) {
            Ok(config) => {
                assert!(!config.auth.is_secretless());
                assert_eq!(config.auth.subdomain(), "acme");
                assert!(config.base_url.is_none());
            }
            Err(e) => panic!("Expected Ok, got: {e:?}"),
        }
    }

    #[test]
    fn test_config_from_params_credential_id_auth() {
        let cred_id = uuid::Uuid::new_v4().to_string();
        let params = json!({
            "subdomain": "corp",
            "credential_id": cred_id
        });
        match ZendeskConfig::from_params(&params) {
            Ok(config) => {
                assert!(config.auth.is_secretless());
                assert_eq!(config.auth.subdomain(), "corp");
            }
            Err(e) => panic!("Expected Ok, got: {e:?}"),
        }
    }

    #[test]
    fn test_config_from_params_with_base_url() {
        let params = json!({
            "subdomain": "test",
            "email": "u@t.com",
            "api_token": "t",
            "base_url": "http://localhost:9999/api/v2"
        });
        match ZendeskConfig::from_params(&params) {
            Ok(config) => {
                assert_eq!(
                    config.base_url.as_deref(),
                    Some("http://localhost:9999/api/v2")
                );
            }
            Err(e) => panic!("Expected Ok, got: {e:?}"),
        }
    }

    #[test]
    fn test_config_from_params_no_auth() {
        let params = json!({ "subdomain": "x" });
        let result = ZendeskConfig::from_params(&params);
        match result {
            Err(FcpError::InvalidRequest { message, .. }) => {
                assert!(message.contains("Missing auth"));
            }
            Err(e) => panic!("Expected InvalidRequest, got: {e:?}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn test_config_from_params_conflicting_auth() {
        let cred_id = uuid::Uuid::new_v4().to_string();
        let params = json!({
            "subdomain": "x",
            "email": "u@t.com",
            "api_token": "t",
            "credential_id": cred_id
        });
        let result = ZendeskConfig::from_params(&params);
        match result {
            Err(FcpError::InvalidRequest { message, .. }) => {
                assert!(message.contains("Conflicting auth"));
            }
            Err(e) => panic!("Expected InvalidRequest, got: {e:?}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn test_config_from_params_email_only() {
        let params = json!({ "subdomain": "x", "email": "u@t.com" });
        let result = ZendeskConfig::from_params(&params);
        match result {
            Err(FcpError::InvalidRequest { message, .. }) => {
                assert!(message.contains("email") || message.contains("api_token"));
            }
            Err(e) => panic!("Expected InvalidRequest, got: {e:?}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn test_config_from_params_api_token_only() {
        let params = json!({ "subdomain": "x", "api_token": "t" });
        let result = ZendeskConfig::from_params(&params);
        match result {
            Err(FcpError::InvalidRequest { message, .. }) => {
                assert!(message.contains("api_token") || message.contains("email"));
            }
            Err(e) => panic!("Expected InvalidRequest, got: {e:?}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn test_config_from_params_invalid_credential_id() {
        let params = json!({ "subdomain": "x", "credential_id": "not-a-uuid" });
        let result = ZendeskConfig::from_params(&params);
        match result {
            Err(FcpError::InvalidRequest { message, .. }) => {
                assert!(message.contains("credential_id"));
            }
            Err(e) => panic!("Expected InvalidRequest, got: {e:?}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    // ─── Handshake details ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_requested_capabilities() {
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["zendesk.read", "zendesk.write"]
            }))
            .await
            .unwrap();
        let grants = result["capabilities_granted"].as_array().unwrap();
        assert_eq!(grants.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_has_session_id() {
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["zendesk.read"]
            }))
            .await
            .unwrap();
        assert!(result["session_id"].is_string());
        assert!(connector.session_id.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_event_caps() {
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": []
            }))
            .await
            .unwrap();
        let event_caps = &result["event_caps"];
        assert_eq!(event_caps["streaming"], true);
        assert_eq!(event_caps["replay"], false);
        assert_eq!(event_caps["min_buffer_events"], 50);
        assert_eq!(event_caps["requires_ack"], false);
    }

    // ─── Health check details ─────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured_no_auth_mode() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
        assert!(result.get("auth_mode").is_none());
        assert!(result.get("api_domain").is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_metrics_zero_initially() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["metrics"]["requests_total"], 0);
        assert_eq!(result["metrics"]["requests_error"], 0);
    }
}
