//! FCP Gmail Connector implementation.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::GmailClient, error::GmailError};

const DEFAULT_BASE_URL: &str = "https://gmail.googleapis.com/gmail/v1";
const DEFAULT_OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_HISTORY_CURSOR_FILE: &str = "fcp-gmail-history-cursor.json";

#[derive(Debug, Clone)]
enum GmailAuthMode {
    AccessToken,
    CredentialId(CredentialId),
    OAuthRefresh {
        client_id: String,
        token_url: String,
    },
}

impl GmailAuthMode {
    const fn label(&self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::CredentialId(_) => "credential_id",
            Self::OAuthRefresh { .. } => "oauth_refresh",
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::AccessToken => "access_token".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
            Self::OAuthRefresh {
                client_id,
                token_url,
            } => format!("oauth_refresh:{client_id}@{token_url}"),
        }
    }
}

#[derive(Debug, Clone)]
struct GmailConfig {
    auth_mode: GmailAuthMode,
    base_url: String,
    required_scopes: Vec<String>,
    granted_scopes: Vec<String>,
    history_cursor_path: PathBuf,
}

#[derive(Debug, Clone)]
struct GmailOAuthRefreshCredentials {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    token_url: String,
}

#[derive(Debug, Deserialize)]
struct GmailOAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GmailHistoryCursorState {
    next_history_id: String,
    lease_seq: u64,
    #[serde(default)]
    lease_object_id: Option<String>,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP Gmail Connector.
pub struct GmailConnector {
    base: Arc<BaseConnector>,
    config: Option<GmailConfig>,
    client: Option<GmailClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GmailConnector {
    /// Create a new Gmail connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("gmail"))),
            config: None,
            client: None,
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
        let base_url = parse_base_url(&params)?;
        let required_scopes = parse_required_scopes(&params)?;
        let history_cursor_path = parse_history_cursor_path(&params)?;
        let access_token = parse_access_token(&params);
        let credential_id = parse_credential_id(&params)?;
        let oauth_refresh = parse_oauth_refresh(&params)?;

        let selected_sources = [
            access_token.is_some(),
            credential_id.is_some(),
            oauth_refresh.is_some(),
        ]
        .into_iter()
        .filter(|selected| *selected)
        .count();
        if selected_sources != 1 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide exactly one auth source: token, credential_id, or oauth_refresh"
                    .into(),
            });
        }

        let mut status = "configured";
        let mut details = json!({
            "base_url": base_url,
            "required_scopes": required_scopes,
            "history_cursor_path": history_cursor_path.to_string_lossy().to_string(),
        });

        let (auth_mode, granted_scopes, client) = if let Some(token) = access_token {
            let client = GmailClient::new(token)
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to create HTTP client: {e}"),
                })?
                .with_base_url(base_url.clone());
            (GmailAuthMode::AccessToken, Vec::new(), Some(client))
        } else if let Some(id) = credential_id {
            status = "configured_pending_token_materialization";
            details["credential_id"] = json!(id.to_string());
            details["note"] = json!(
                "credential_id configured; live calls require egress proxy token materialization"
            );
            (GmailAuthMode::CredentialId(id), Vec::new(), None)
        } else if let Some(oauth) = oauth_refresh {
            let (token, granted_scopes) = exchange_refresh_token(&oauth, &required_scopes).await?;
            details["granted_scopes"] = json!(granted_scopes);
            let client = GmailClient::new(token)
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to create HTTP client: {e}"),
                })?
                .with_base_url(base_url.clone());
            (
                GmailAuthMode::OAuthRefresh {
                    client_id: oauth.client_id,
                    token_url: oauth.token_url,
                },
                granted_scopes,
                Some(client),
            )
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "No supported auth mode selected".into(),
            });
        };

        self.config = Some(GmailConfig {
            auth_mode,
            base_url: base_url.clone(),
            required_scopes,
            granted_scopes,
            history_cursor_path,
        });
        self.client = client;
        self.base.set_configured(true);
        info!(
            auth_mode = %self.config.as_ref().map_or_else(|| "unknown".to_string(), |config| config.auth_mode.summary()),
            status,
            "Gmail connector configured"
        );

        Ok(json!({ "status": status, "details": details }))
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
            manifest_hash: "sha256:gmail-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
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
        let metrics = self.base.metrics();
        let status = if self.client.is_some() {
            "healthy"
        } else if self.config.is_some() {
            "degraded_pending_credential_materialization"
        } else {
            "not_configured"
        };
        let auth_mode = self
            .config
            .as_ref()
            .map_or("unconfigured", |config| config.auth_mode.label());
        Ok(json!({
            "status": status,
            "auth_mode": auth_mode,
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "history_cursor_path": self.config.as_ref().map(|config| config.history_cursor_path.to_string_lossy().to_string()),
            "required_scopes": self.config.as_ref().map(|config| config.required_scopes.clone()).unwrap_or_default(),
            "granted_scopes": self.config.as_ref().map(|config| config.granted_scopes.clone()).unwrap_or_default(),
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result().await;
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    async fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - call configure first".into()
            },
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: format!("Auth mode: {}", config.auth_mode.label()),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: endpoint_allowed_by_policy(&config.base_url),
            message: if endpoint_allowed_by_policy(&config.base_url) {
                format!("Endpoint accepted by policy checks: {}", config.base_url)
            } else {
                format!(
                    "Endpoint must use https or localhost/127.0.0.1 for tests: {}",
                    config.base_url
                )
            },
            critical: true,
        });

        match (&config.auth_mode, &self.client) {
            (GmailAuthMode::CredentialId(id), _) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: false,
                    message: format!(
                        "credential_id {id} configured; token materialization required by egress proxy"
                    ),
                    critical: false,
                });
                checks.push(DoctorCheck {
                    name: "read_only_connectivity".into(),
                    passed: false,
                    message: "Skipping live connectivity check in credential_id mode".into(),
                    critical: false,
                });
            }
            (GmailAuthMode::AccessToken | GmailAuthMode::OAuthRefresh { .. }, Some(client)) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: true,
                    message: "Access token materialized in-memory".into(),
                    critical: false,
                });

                match client.health_check().await {
                    Ok(()) => checks.push(DoctorCheck {
                        name: "read_only_connectivity".into(),
                        passed: true,
                        message: "Read-only list_labels check succeeded".into(),
                        critical: true,
                    }),
                    Err(error) => checks.push(DoctorCheck {
                        name: "read_only_connectivity".into(),
                        passed: false,
                        message: format!("Read-only list_labels check failed: {error}"),
                        critical: true,
                    }),
                }
            }
            (_, None) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: false,
                    message: "Auth mode configured but HTTP client not initialized".into(),
                    critical: true,
                });
            }
        }

        if !config.required_scopes.is_empty() {
            let granted: BTreeSet<&str> =
                config.granted_scopes.iter().map(String::as_str).collect();
            let missing: Vec<String> = config
                .required_scopes
                .iter()
                .filter(|scope| !granted.contains(scope.as_str()))
                .cloned()
                .collect();
            checks.push(DoctorCheck {
                name: "scope_validation".into(),
                passed: missing.is_empty(),
                message: if missing.is_empty() {
                    "All required scopes are present".into()
                } else {
                    format!("Missing required scopes: {}", missing.join(", "))
                },
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check for host doctor/readiness.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if matches!(config.auth_mode, GmailAuthMode::CredentialId(_)) {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; readiness depends on egress proxy token injection",
            );
            report.details = Some(json!({
                "auth_mode": config.auth_mode.summary(),
                "base_url": config.base_url,
            }));
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let Some(client) = &self.client else {
            let report = SelfCheckReport::failed(
                "client_not_initialized",
                "Connector is configured but HTTP client is unavailable",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let mut report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };
        report.details = Some(json!({
            "auth_mode": config.auth_mode.summary(),
            "base_url": config.base_url,
            "history_cursor_path": config.history_cursor_path.to_string_lossy().to_string(),
            "required_scopes": config.required_scopes,
            "granted_scopes": config.granted_scopes,
        }));

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "gmail.send_message",
                    "Send an email message",
                    json!({
                        "type": "object",
                        "required": ["raw"],
                        "properties": {
                            "raw": { "type": "string", "description": "Base64url-encoded RFC 2822 message" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.send",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a new email. The raw field must be a base64url-encoded RFC 2822 message.".into(),
                        common_mistakes: vec!["Using standard base64 instead of base64url encoding".into()],
                        examples: vec![
                            r#"{"raw": "RnJvbTogc2VuZGVyQGV4YW1wbGUuY29tClRvOiByZWNpcGllbnRAZXhhbXBsZS5jb20KU3ViamVjdDogVGVzdAoKSGVsbG8h"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.get_message"),
                            CapabilityId::from_static("gmail.list_messages"),
                        ],
                    },
                ),
                op_info(
                    "gmail.get_message",
                    "Get a single email message by ID",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve full details of a specific email message.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"message_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.list_messages"),
                            CapabilityId::from_static("gmail.get_thread"),
                        ],
                    },
                ),
                op_info(
                    "gmail.list_messages",
                    "List email messages with optional search query",
                    json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string", "description": "Gmail search query (same syntax as web UI)" },
                            "max_results": { "type": "integer", "description": "Max messages to return" },
                            "page_token": { "type": "string", "description": "Pagination token" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" },
                            "next_page_token": { "type": "string" },
                            "result_size_estimate": { "type": "integer" }
                        }
                    }),
                    "gmail.messages.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List or search email messages. Uses Gmail search syntax.".into(),
                        common_mistakes: vec!["Expecting full message bodies; list returns only IDs and thread IDs".into()],
                        examples: vec![
                            r#"{"query": "from:notifications@github.com is:unread", "max_results": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.get_message"),
                        ],
                    },
                ),
                op_info(
                    "gmail.sync_history",
                    "Incrementally fetch mailbox history changes using historyId cursor state",
                    json!({
                        "type": "object",
                        "required": ["lease_seq"],
                        "properties": {
                            "start_history_id": { "type": "string", "description": "Optional historyId override for first sync or explicit reset" },
                            "max_results": { "type": "integer", "description": "Optional page size passed to Gmail History API" },
                            "history_types": { "type": "array", "items": { "type": "string" }, "description": "Optional history type filters (messageAdded, messageDeleted, labelAdded, labelRemoved)" },
                            "lease_seq": { "type": "integer", "description": "Singleton-writer fencing token; must not regress" },
                            "lease_object_id": { "type": "string", "description": "Optional lease object reference for diagnostics/audit" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["history", "latest_history_id", "effective_start_history_id", "lease_seq"],
                        "properties": {
                            "history": { "type": "array", "items": { "type": "object" } },
                            "history_count": { "type": "integer" },
                            "latest_history_id": { "type": "string" },
                            "effective_start_history_id": { "type": "string" },
                            "dedup_applied": { "type": "boolean" },
                            "used_persisted_cursor": { "type": "boolean" },
                            "lease_seq": { "type": "integer" },
                            "cursor_state_path": { "type": "string" }
                        }
                    }),
                    "gmail.history.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Perform incremental mailbox sync with persisted historyId cursor and restart-safe dedup semantics.".into(),
                        common_mistakes: vec![
                            "Not persisting or reusing historyId between runs, causing duplicate processing".into(),
                            "Sending stale lease_seq from an old writer after failover".into(),
                        ],
                        examples: vec![
                            r#"{"start_history_id":"1000","lease_seq":1,"lease_object_id":"lease-a"}"#.into(),
                            r#"{"history_types":["messageAdded","labelRemoved"],"lease_seq":2}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.list_messages"),
                            CapabilityId::from_static("gmail.get_message"),
                        ],
                    },
                ),
                op_info(
                    "gmail.modify_message",
                    "Modify message labels (add or remove)",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" },
                            "add_label_ids": { "type": "array", "items": { "type": "string" }, "description": "Label IDs to add" },
                            "remove_label_ids": { "type": "array", "items": { "type": "string" }, "description": "Label IDs to remove" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.modify",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Add or remove labels from a message (e.g., mark as read, archive).".into(),
                        common_mistakes: vec!["Using label names instead of label IDs".into()],
                        examples: vec![
                            r#"{"message_id": "18d1234abc", "remove_label_ids": ["UNREAD"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.list_labels"),
                            CapabilityId::from_static("gmail.get_message"),
                        ],
                    },
                ),
                op_info(
                    "gmail.trash_message",
                    "Move a message to trash",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.modify",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Move an email message to the trash.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"message_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gmail.get_message")],
                    },
                ),
                op_info(
                    "gmail.get_thread",
                    "Get an email thread with all messages",
                    json!({
                        "type": "object",
                        "required": ["thread_id"],
                        "properties": {
                            "thread_id": { "type": "string", "description": "Gmail thread ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "thread": { "type": "object" } } }),
                    "gmail.threads.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve all messages in an email thread/conversation.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"thread_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.get_message"),
                            CapabilityId::from_static("gmail.list_messages"),
                        ],
                    },
                ),
                op_info(
                    "gmail.list_labels",
                    "List all Gmail labels",
                    json!({ "type": "object", "properties": {} }),
                    json!({
                        "type": "object",
                        "properties": { "labels": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "gmail.labels.manage",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all labels in the Gmail account (system and user-created).".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("gmail.modify_message")],
                    },
                ),
                op_info(
                    "gmail.get_draft",
                    "Get a draft by ID",
                    json!({
                        "type": "object",
                        "required": ["draft_id"],
                        "properties": {
                            "draft_id": { "type": "string", "description": "Gmail draft ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "draft": { "type": "object" } } }),
                    "gmail.messages.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a saved email draft.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"draft_id": "r1234567890"}"#.into()],
                        related: vec![CapabilityId::from_static("gmail.send_draft")],
                    },
                ),
                op_info(
                    "gmail.send_draft",
                    "Send a previously saved draft",
                    json!({
                        "type": "object",
                        "required": ["draft_id"],
                        "properties": {
                            "draft_id": { "type": "string", "description": "Gmail draft ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.send",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a draft that was previously created and saved.".into(),
                        common_mistakes: vec!["The draft is deleted after sending".into()],
                        examples: vec![r#"{"draft_id": "r1234567890"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("gmail.get_draft"),
                            CapabilityId::from_static("gmail.send_message"),
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
            "gmail.send_message" => self.invoke_send_message(input).await,
            "gmail.get_message" => self.invoke_get_message(input).await,
            "gmail.list_messages" => self.invoke_list_messages(input).await,
            "gmail.sync_history" => self.invoke_sync_history(input).await,
            "gmail.modify_message" => self.invoke_modify_message(input).await,
            "gmail.trash_message" => self.invoke_trash_message(input).await,
            "gmail.get_thread" => self.invoke_get_thread(input).await,
            "gmail.list_labels" => self.invoke_list_labels().await,
            "gmail.get_draft" => self.invoke_get_draft(input).await,
            "gmail.send_draft" => self.invoke_send_draft(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let raw = require_str(&input, "raw")?;

        let message = client
            .send_message(raw)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_get_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let message = client
            .get_message(message_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_list_messages(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = input.get("query").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_messages(query, max_results, page_token)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({
            "messages": result.messages,
            "next_page_token": result.next_page_token,
            "result_size_estimate": result.result_size_estimate
        }))
    }

    async fn invoke_sync_history(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;

        let requested_start = parse_optional_string_field(&input, "start_history_id")?;
        let max_results = input
            .get("max_results")
            .and_then(|value| value.as_u64())
            .map(|value| value as u32);
        let history_types = parse_history_types(&input)?;
        let provided_lease_seq = parse_optional_u64_field(&input, "lease_seq")?;
        let provided_lease_object_id = parse_optional_string_field(&input, "lease_object_id")?;
        let lease_seq = provided_lease_seq.ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "lease_seq is required for singleton_writer cursor advancement".into(),
        })?;

        let previous = load_history_cursor_state(&config.history_cursor_path)?;
        let (effective_start_history_id, dedup_applied, used_persisted_cursor) =
            determine_effective_start_history_id(requested_start, previous.as_ref())?;

        if let Some(previous_state) = previous.as_ref()
            && lease_seq < previous_state.lease_seq
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "stale lease_seq for gmail history cursor: current={}, incoming={lease_seq}",
                    previous_state.lease_seq,
                ),
            });
        }

        let mut page_token: Option<String> = None;
        let mut history: Vec<serde_json::Value> = Vec::new();
        let mut latest_history_id = effective_start_history_id.clone();

        loop {
            let page = client
                .list_history(
                    &effective_start_history_id,
                    max_results,
                    page_token.as_deref(),
                    history_types.as_deref(),
                )
                .await
                .map_err(|error: GmailError| error.to_fcp_error())?;

            if let Some(history_id) = page.history_id {
                if compare_history_ids(&history_id, &latest_history_id) == Ordering::Greater {
                    latest_history_id = history_id;
                }
            }

            history.extend(page.history);

            if let Some(next) = page.next_page_token {
                page_token = Some(next);
            } else {
                break;
            }
        }

        if let Some(previous_state) = previous.as_ref()
            && compare_history_ids(&latest_history_id, &previous_state.next_history_id)
                == Ordering::Less
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "history cursor regression detected: current={}, incoming={latest_history_id}",
                    previous_state.next_history_id
                ),
            });
        }

        let cursor_state = GmailHistoryCursorState {
            next_history_id: latest_history_id.clone(),
            lease_seq,
            lease_object_id: provided_lease_object_id.or_else(|| {
                previous
                    .as_ref()
                    .and_then(|state| state.lease_object_id.clone())
            }),
            updated_at: current_unix_timestamp_secs(),
        };
        persist_history_cursor_state(&config.history_cursor_path, &cursor_state)?;
        let history_count = history.len();

        Ok(json!({
            "history": history,
            "history_count": history_count,
            "latest_history_id": latest_history_id,
            "effective_start_history_id": effective_start_history_id,
            "dedup_applied": dedup_applied,
            "used_persisted_cursor": used_persisted_cursor,
            "lease_seq": lease_seq,
            "cursor_state_path": config.history_cursor_path.to_string_lossy().to_string(),
        }))
    }

    async fn invoke_modify_message(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let add_labels: Vec<String> = input
            .get("add_label_ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let remove_labels: Vec<String> = input
            .get("remove_label_ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let message = client
            .modify_message(message_id, &add_labels, &remove_labels)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_trash_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let message = client
            .trash_message(message_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_get_thread(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let thread_id = require_str(&input, "thread_id")?;

        let thread = client
            .get_thread(thread_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "thread": thread }))
    }

    async fn invoke_list_labels(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let labels = client
            .list_labels()
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "labels": labels }))
    }

    async fn invoke_get_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let draft_id = require_str(&input, "draft_id")?;

        let draft = client
            .get_draft(draft_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "draft": draft }))
    }

    async fn invoke_send_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let draft_id = require_str(&input, "draft_id")?;

        let message = client
            .send_draft(draft_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Gmail connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GmailConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn parse_base_url(params: &serde_json::Value) -> FcpResult<String> {
    let raw = params
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_BASE_URL);

    let parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    if parsed.host_str().is_none() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must include a host".into(),
        });
    }
    if parsed.scheme() == "http" && !parsed.host_str().is_some_and(is_local_test_host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1 for tests"
                .into(),
        });
    }

    Ok(raw.trim_end_matches('/').to_string())
}

fn parse_required_scopes(params: &serde_json::Value) -> FcpResult<Vec<String>> {
    let Some(value) = params.get("required_scopes") else {
        return Ok(Vec::new());
    };

    let scopes: Vec<String> =
        serde_json::from_value(value.clone()).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "required_scopes must be an array of non-empty strings".into(),
        })?;

    let mut normalized = Vec::new();
    for scope in scopes {
        let scope = scope.trim();
        if scope.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "required_scopes entries must not be empty".into(),
            });
        }
        normalized.push(scope.to_string());
    }

    Ok(normalized)
}

fn parse_history_cursor_path(params: &serde_json::Value) -> FcpResult<PathBuf> {
    if let Some(path) = params.get("history_cursor_path") {
        let raw = path.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "history_cursor_path must be a string".into(),
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "history_cursor_path must not be empty".into(),
            });
        }
        return Ok(PathBuf::from(trimmed));
    }

    let default_dir =
        std::env::var_os("FCP_CONNECTOR_STATE_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    Ok(default_dir.join(DEFAULT_HISTORY_CURSOR_FILE))
}

fn parse_optional_string_field(
    input: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<String>> {
    match input.get(field) {
        None => Ok(None),
        Some(value) => {
            let value = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be a string"),
            })?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field} must not be empty"),
                });
            }
            Ok(Some(trimmed.to_string()))
        }
    }
}

fn parse_optional_u64_field(input: &serde_json::Value, field: &str) -> FcpResult<Option<u64>> {
    match input.get(field) {
        None => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an unsigned integer"),
        }),
    }
}

fn parse_history_types(input: &serde_json::Value) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = input.get("history_types") else {
        return Ok(None);
    };
    let values: Vec<String> =
        serde_json::from_value(value.clone()).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "history_types must be an array of non-empty strings".into(),
        })?;

    let mut normalized = Vec::with_capacity(values.len());
    for history_type in values {
        let trimmed = history_type.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "history_types entries must not be empty".into(),
            });
        }
        normalized.push(trimmed.to_string());
    }
    if normalized.is_empty() {
        return Ok(None);
    }
    Ok(Some(normalized))
}

fn parse_access_token(params: &serde_json::Value) -> Option<String> {
    params
        .get("token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn parse_credential_id(params: &serde_json::Value) -> FcpResult<Option<CredentialId>> {
    match params.get("credential_id") {
        None => Ok(None),
        Some(value) => {
            let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "credential_id must be a string".into(),
            })?;
            let credential_id = CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "credential_id must be a valid UUID".into(),
            })?;
            Ok(Some(credential_id))
        }
    }
}

fn parse_oauth_refresh(
    params: &serde_json::Value,
) -> FcpResult<Option<GmailOAuthRefreshCredentials>> {
    let Some(value) = params.get("oauth_refresh") else {
        return Ok(None);
    };
    let obj = value.as_object().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "oauth_refresh must be an object".into(),
    })?;

    let required_string = |key: &str| -> FcpResult<String> {
        let value = obj
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("oauth_refresh.{key} is required"),
            })?;
        Ok(value.to_string())
    };

    let token_url = obj
        .get("token_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_OAUTH_TOKEN_URL);
    let parsed_token_url = Url::parse(token_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("oauth_refresh.token_url is invalid: {error}"),
    })?;
    if parsed_token_url.scheme() != "https"
        && !parsed_token_url.host_str().is_some_and(is_local_test_host)
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "oauth_refresh.token_url must use https unless targeting localhost for tests"
                .into(),
        });
    }

    Ok(Some(GmailOAuthRefreshCredentials {
        client_id: required_string("client_id")?,
        client_secret: required_string("client_secret")?,
        refresh_token: required_string("refresh_token")?,
        token_url: token_url.to_string(),
    }))
}

async fn exchange_refresh_token(
    oauth: &GmailOAuthRefreshCredentials,
    required_scopes: &[String],
) -> FcpResult<(String, Vec<String>)> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("fcp-gmail/0.1.0")
        .build()
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to initialize OAuth HTTP client: {error}"),
        })?;

    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("client_id", oauth.client_id.clone()),
        ("client_secret", oauth.client_secret.clone()),
        ("refresh_token", oauth.refresh_token.clone()),
    ];
    if !required_scopes.is_empty() {
        form.push(("scope", required_scopes.join(" ")));
    }

    let response = client
        .post(&oauth.token_url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(encode_form_body(&form))
        .send()
        .await
        .map_err(|error| FcpError::External {
            service: "gmail_oauth".into(),
            message: error.to_string(),
            status_code: error.status().map(|status| status.as_u16()),
            retryable: error.is_timeout() || error.is_connect(),
            retry_after: None,
        })?;

    if !response.status().is_success() {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: format!(
                "OAuth token refresh failed with status {}",
                response.status()
            ),
        });
    }

    let payload: GmailOAuthTokenResponse =
        response.json().await.map_err(|error| FcpError::Internal {
            message: format!("Failed to parse OAuth token response: {error}"),
        })?;
    let granted_scopes = parse_scope_string(payload.scope.as_deref().unwrap_or_default());

    if !required_scopes.is_empty() {
        let granted: BTreeSet<&str> = granted_scopes.iter().map(String::as_str).collect();
        let missing: Vec<String> = required_scopes
            .iter()
            .filter(|scope| !granted.contains(scope.as_str()))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: format!(
                    "OAuth token is missing required scopes: {}",
                    missing.join(", ")
                ),
            });
        }
    }

    Ok((payload.access_token, granted_scopes))
}

fn endpoint_allowed_by_policy(endpoint: &str) -> bool {
    let Ok(parsed) = Url::parse(endpoint) else {
        return false;
    };
    if parsed.scheme() == "https" {
        return true;
    }
    parsed.host_str().is_some_and(is_local_test_host)
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn parse_scope_string(scope: &str) -> Vec<String> {
    scope
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn encode_form_body(params: &[(&str, String)]) -> String {
    let mut body = String::new();
    for (index, (key, value)) in params.iter().enumerate() {
        if index > 0 {
            body.push('&');
        }
        append_form_component(&mut body, key);
        body.push('=');
        append_form_component(&mut body, value);
    }
    body
}

fn append_form_component(target: &mut String, value: &str) {
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                target.push(byte as char);
            }
            b' ' => target.push('+'),
            _ => {
                let _ = std::fmt::Write::write_fmt(target, format_args!("%{byte:02X}"));
            }
        }
    }
}

fn determine_effective_start_history_id(
    requested_start: Option<String>,
    previous_state: Option<&GmailHistoryCursorState>,
) -> FcpResult<(String, bool, bool)> {
    match (requested_start, previous_state) {
        (Some(requested), Some(previous)) => {
            if compare_history_ids(&requested, &previous.next_history_id) == Ordering::Less {
                Ok((previous.next_history_id.clone(), true, true))
            } else {
                Ok((requested, false, false))
            }
        }
        (Some(requested), None) => Ok((requested, false, false)),
        (None, Some(previous)) => Ok((previous.next_history_id.clone(), false, true)),
        (None, None) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing start_history_id and no persisted history cursor is available".into(),
        }),
    }
}

fn load_history_cursor_state(path: &Path) -> FcpResult<Option<GmailHistoryCursorState>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path).map_err(|error| FcpError::Internal {
        message: format!(
            "Failed to read history cursor state {}: {error}",
            path.display()
        ),
    })?;

    let state = serde_json::from_slice(&bytes).map_err(|error| FcpError::Internal {
        message: format!(
            "Failed to parse history cursor state {}: {error}",
            path.display()
        ),
    })?;
    Ok(Some(state))
}

fn persist_history_cursor_state(path: &Path, state: &GmailHistoryCursorState) -> FcpResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to create history cursor directory {}: {error}",
                parent.display()
            ),
        })?;
    }

    let data = serde_json::to_vec_pretty(state).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize history cursor state: {error}"),
    })?;

    let tmp_name = format!(
        ".{}-{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("gmail-history-cursor"),
        uuid::Uuid::new_v4()
    );
    let tmp_path = path.with_file_name(tmp_name);
    fs::write(&tmp_path, data).map_err(|error| FcpError::Internal {
        message: format!(
            "Failed to write temporary history cursor state {}: {error}",
            tmp_path.display()
        ),
    })?;
    fs::rename(&tmp_path, path).map_err(|error| FcpError::Internal {
        message: format!(
            "Failed to persist history cursor state {}: {error}",
            path.display()
        ),
    })?;

    Ok(())
}

fn compare_history_ids(lhs: &str, rhs: &str) -> Ordering {
    if lhs.bytes().all(|byte| byte.is_ascii_digit())
        && rhs.bytes().all(|byte| byte.is_ascii_digit())
    {
        let lhs = lhs.trim_start_matches('0');
        let rhs = rhs.trim_start_matches('0');
        let lhs = if lhs.is_empty() { "0" } else { lhs };
        let rhs = if rhs.is_empty() { "0" } else { rhs };

        match lhs.len().cmp(&rhs.len()) {
            Ordering::Equal => lhs.cmp(rhs),
            other => other,
        }
    } else {
        lhs.cmp(rhs)
    }
}

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

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
        let mut connector = GmailConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.messages.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = GmailConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id_sets_pending_status() {
        let mut connector = GmailConnector::new();
        let credential_id = CredentialId::new();

        let result = connector
            .handle_configure(json!({
                "credential_id": credential_id.to_string(),
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured_pending_token_materialization");
        let health = connector.handle_health().await.unwrap();
        assert_eq!(
            health["status"],
            "degraded_pending_credential_materialization"
        );
        assert_eq!(health["auth_mode"], "credential_id");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_multiple_auth_sources() {
        let mut connector = GmailConnector::new();
        let credential_id = CredentialId::new();

        let result = connector
            .handle_configure(json!({
                "token": "ya29.token",
                "credential_id": credential_id.to_string(),
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one auth source"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_oauth_refresh_materializes_access_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "ya29.oauth-access-token",
                "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.labels"
            })))
            .mount(&mock_server)
            .await;

        let mut connector = GmailConnector::new();
        let result = connector
            .handle_configure(json!({
                "base_url": mock_server.uri(),
                "required_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "oauth_refresh": {
                    "client_id": "client-id",
                    "client_secret": "client-secret",
                    "refresh_token": "refresh-token",
                    "token_url": format!("{}/token", mock_server.uri())
                }
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["auth_mode"], "oauth_refresh");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_degraded_for_credential_mode() {
        let mut connector = GmailConnector::new();
        let credential_id = CredentialId::new();

        connector
            .handle_configure(json!({
                "credential_id": credential_id.to_string(),
            }))
            .await
            .unwrap();

        let report = connector.handle_self_check().await.unwrap();
        assert_eq!(report["status"], "degraded");
        assert_eq!(report["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = GmailConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.list_labels"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "gmail.list_labels");

        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.list_labels",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = GmailConnector::new();
        connector.client = Some(
            GmailClient::new("fake_key")
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
                "capabilities_requested": ["gmail.get_message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "gmail.get_message");

        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.get_message",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("message_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_sync_history_resumes_from_persisted_cursor() {
        let state_path =
            std::env::temp_dir().join(format!("fcp-gmail-history-{}.json", uuid::Uuid::new_v4()));

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/me/history"))
            .and(query_param("startHistoryId", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "history": [
                    { "id": "101", "messagesAdded": [{ "message": { "id": "m1" } }] }
                ],
                "historyId": "101"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/users/me/history"))
            .and(query_param("startHistoryId", "101"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "history": [],
                "historyId": "101"
            })))
            .mount(&mock_server)
            .await;

        let mut connector = GmailConnector::new();
        connector
            .handle_configure(json!({
                "token": "ya29.history-token",
                "base_url": mock_server.uri(),
                "history_cursor_path": state_path.to_string_lossy().to_string()
            }))
            .await
            .unwrap();

        let first = connector
            .invoke_sync_history(json!({
                "start_history_id": "100",
                "lease_seq": 1,
                "lease_object_id": "lease-a"
            }))
            .await
            .unwrap();

        assert_eq!(first["effective_start_history_id"], "100");
        assert_eq!(first["latest_history_id"], "101");
        assert_eq!(first["history_count"], 1);
        assert_eq!(first["used_persisted_cursor"], false);

        let mut restarted = GmailConnector::new();
        restarted
            .handle_configure(json!({
                "token": "ya29.history-token",
                "base_url": mock_server.uri(),
                "history_cursor_path": state_path.to_string_lossy().to_string()
            }))
            .await
            .unwrap();

        let resumed = restarted
            .invoke_sync_history(json!({
                "lease_seq": 2,
                "lease_object_id": "lease-b"
            }))
            .await
            .unwrap();

        assert_eq!(resumed["effective_start_history_id"], "101");
        assert_eq!(resumed["latest_history_id"], "101");
        assert_eq!(resumed["history_count"], 0);
        assert_eq!(resumed["used_persisted_cursor"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_sync_history_rejects_stale_lease_seq() {
        let state_path =
            std::env::temp_dir().join(format!("fcp-gmail-history-{}.json", uuid::Uuid::new_v4()));

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/me/history"))
            .and(query_param("startHistoryId", "200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "history": [],
                "historyId": "200"
            })))
            .mount(&mock_server)
            .await;

        let mut connector = GmailConnector::new();
        connector
            .handle_configure(json!({
                "token": "ya29.history-token",
                "base_url": mock_server.uri(),
                "history_cursor_path": state_path.to_string_lossy().to_string()
            }))
            .await
            .unwrap();

        connector
            .invoke_sync_history(json!({
                "start_history_id": "200",
                "lease_seq": 5,
                "lease_object_id": "lease-current"
            }))
            .await
            .unwrap();

        let err = connector
            .invoke_sync_history(json!({
                "start_history_id": "200",
                "lease_seq": 4,
                "lease_object_id": "lease-stale"
            }))
            .await
            .unwrap_err();

        match err {
            FcpError::Conflict { message } => {
                assert!(message.contains("stale lease_seq"));
            }
            other => panic!("Expected conflict for stale lease, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = GmailConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"gmail.send_message"));
        assert!(op_ids.contains(&"gmail.get_message"));
        assert!(op_ids.contains(&"gmail.list_messages"));
        assert!(op_ids.contains(&"gmail.modify_message"));
        assert!(op_ids.contains(&"gmail.trash_message"));
        assert!(op_ids.contains(&"gmail.get_thread"));
        assert!(op_ids.contains(&"gmail.list_labels"));
        assert!(op_ids.contains(&"gmail.sync_history"));
        assert!(op_ids.contains(&"gmail.get_draft"));
        assert!(op_ids.contains(&"gmail.send_draft"));
        assert_eq!(ops.len(), 10);
    }
}
