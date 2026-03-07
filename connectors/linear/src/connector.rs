//! FCP Linear Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_API_URL, LinearAuth, LinearClient},
    error::LinearError,
};

/// Parsed and validated Linear connector configuration.
#[derive(Debug, Clone)]
struct LinearConfig {
    auth: LinearAuth,
    api_url: String,
}

impl LinearConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

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

        let auth = match (api_key, credential_id) {
            (Some(key), None) => LinearAuth::ApiKey(key),
            (None, Some(cred_id)) => LinearAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_URL)
            .to_string();

        Ok(Self { auth, api_url })
    }
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    /// Overall status.
    status: DoctorStatus,
    /// Individual check results.
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    /// All checks passed.
    Healthy,
    /// Some non-critical checks failed.
    Degraded,
    /// Critical checks failed.
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    /// Check name.
    name: String,
    /// Check passed.
    passed: bool,
    /// Check message.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Whether this check is critical.
    critical: bool,
}

impl DoctorResult {
    /// Create a new doctor result from checks.
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        Self { status, checks }
    }
}

/// FCP Linear Connector.
pub struct LinearConnector {
    base: Arc<BaseConnector>,
    config: Option<LinearConfig>,
    client: Option<LinearClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl LinearConnector {
    /// Create a new Linear connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("linear"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    ///
    /// Accepts either `api_key` (direct) or `credential_id` (secretless via
    /// egress proxy injection). Exactly one must be provided.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = LinearConfig::from_params(&params)?;

        let client =
            LinearClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_api_url(&config.api_url);

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);
        info!("Linear connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle doctor diagnostics.
    ///
    /// Validates configuration, HTTP client, API URL, auth mode, network
    /// constraints, and credential injection status without making API calls.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // Check 1: Configuration loaded
        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        // Check 2: HTTP client initialized
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        // Check 3: API URL scheme
        let scheme = if config.api_url.starts_with("https://") {
            "https"
        } else if config.api_url.starts_with("http://") {
            "http"
        } else {
            "unknown"
        };

        checks.push(DoctorCheck {
            name: "api_url".into(),
            passed: true,
            message: Some(format!("API URL ({scheme}): {}", config.api_url)),
            critical: false,
        });

        // Check 4: Auth mode
        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth: {}", config.auth.redacted_label())),
            critical: false,
        });

        // Check 5: Network constraints - host must be api.linear.app (or test override)
        let allowed_hosts = ["api.linear.app"];
        let host_ok = config.api_url.starts_with("http://localhost")
            || config.api_url.starts_with("http://127.0.0.1")
            || allowed_hosts.iter().any(|h| config.api_url.contains(h));
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: host_ok,
            message: Some(if host_ok {
                "API URL matches allowed host (api.linear.app)".into()
            } else {
                format!(
                    "API URL {} does not match allowed hosts: {:?}",
                    config.api_url, allowed_hosts
                )
            }),
            critical: true,
        });

        // Check 6: Credential injection status
        let secretless = config.auth.is_secretless();
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !secretless,
            message: Some(if secretless {
                "Credential injection required via egress proxy".into()
            } else {
                "Direct API key configured".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
    ///
    /// Performs a safe, read-only GraphQL query (viewer) to validate the API key
    /// is valid and the Linear API is reachable. Does not leak secrets in the report.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // If using credential_id, we can't validate directly
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
            manifest_hash: "sha256:linear-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
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
                    "linear.create_issue",
                    "Create an issue in Linear",
                    json!({
                        "type": "object",
                        "required": ["title", "team_id"],
                        "properties": {
                            "title": { "type": "string" },
                            "team_id": { "type": "string" },
                            "description": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new issue in Linear.".into(),
                        common_mistakes: vec!["Not specifying the team ID".into()],
                        examples: vec![
                            r#"{"title": "Fix login bug", "team_id": "TEAM-123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("linear.get_issue"),
                            CapabilityId::from_static("linear.search_issues"),
                        ],
                    },
                ),
                op_info(
                    "linear.get_issue",
                    "Get a Linear issue by ID",
                    json!({
                        "type": "object",
                        "required": ["issue_id"],
                        "properties": {
                            "issue_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Look up a specific issue by ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"issue_id": "LIN-123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("linear.create_issue"),
                            CapabilityId::from_static("linear.update_issue"),
                        ],
                    },
                ),
                op_info(
                    "linear.update_issue",
                    "Update an issue's properties",
                    json!({
                        "type": "object",
                        "required": ["issue_id"],
                        "properties": {
                            "issue_id": { "type": "string" },
                            "title": { "type": "string" },
                            "state_id": { "type": "string" },
                            "description": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Update issue title, status, assignee, or other fields."
                            .into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"issue_id": "LIN-123", "state_id": "done-state-id"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.search_issues",
                    "Search issues with text query",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "issues": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for issues matching a text query.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"query": "login bug"}"#.into()],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.list_teams",
                    "List all teams in the workspace",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "teams": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List available teams in the workspace.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("linear.create_issue")],
                    },
                ),
                op_info(
                    "linear.list_cycles",
                    "List cycles for a team",
                    json!({
                        "type": "object",
                        "required": ["team_id"],
                        "properties": {
                            "team_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "cycles": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List sprints/cycles for a team.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"team_id": "TEAM-123"}"#.into()],
                        related: vec![CapabilityId::from_static("linear.list_teams")],
                    },
                ),
                op_info(
                    "linear.add_comment",
                    "Add a comment to an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_id", "body"],
                        "properties": {
                            "issue_id": { "type": "string" },
                            "body": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "comment": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Comment on an issue.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"issue_id": "LIN-123", "body": "Working on this now."}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.list_projects",
                    "List projects in the workspace",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "projects": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List projects.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("linear.list_teams")],
                    },
                ),
                op_info(
                    "linear.process_webhook",
                    "Process an inbound Linear webhook payload forwarded by fcp-host",
                    json!({
                        "type": "object",
                        "required": ["payload"],
                        "properties": {
                            "payload": {
                                "type": "object",
                                "description": "Raw Linear webhook payload"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "event": {
                                "type": "object",
                                "properties": {
                                    "topic": { "type": "string" },
                                    "resource_type": { "type": "string" },
                                    "action": { "type": "string" },
                                    "resource_uri": { "type": "string" },
                                    "data": { "type": "object" }
                                }
                            }
                        }
                    }),
                    "linear.process_webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Process a webhook event forwarded by fcp-host.".into(),
                        common_mistakes: vec![
                            "Sending the payload without the wrapper object".into(),
                        ],
                        examples: vec![
                            r#"{"payload": {"action": "create", "type": "Issue", "createdAt": "2026-03-07T00:00:00Z", "data": {"id": "i1"}}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("linear.get_issue"),
                        ],
                    },
                ),
            ],
            events: vec![
                EventInfo {
                    topic: "linear.issue.create".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Issue"] },
                            "action": { "type": "string", "enum": ["create"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.issue.update".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Issue"] },
                            "action": { "type": "string", "enum": ["update"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.issue.remove".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Issue"] },
                            "action": { "type": "string", "enum": ["remove"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.comment.create".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Comment"] },
                            "action": { "type": "string", "enum": ["create"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.comment.update".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Comment"] },
                            "action": { "type": "string", "enum": ["update"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.comment.remove".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Comment"] },
                            "action": { "type": "string", "enum": ["remove"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.project.create".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Project"] },
                            "action": { "type": "string", "enum": ["create"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.project.update".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Project"] },
                            "action": { "type": "string", "enum": ["update"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.project.remove".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Project"] },
                            "action": { "type": "string", "enum": ["remove"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.cycle.create".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Cycle"] },
                            "action": { "type": "string", "enum": ["create"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.cycle.update".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Cycle"] },
                            "action": { "type": "string", "enum": ["update"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.cycle.remove".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Cycle"] },
                            "action": { "type": "string", "enum": ["remove"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
            ],
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
            "linear.create_issue" => self.invoke_create_issue(input).await,
            "linear.get_issue" => self.invoke_get_issue(input).await,
            "linear.update_issue" => self.invoke_update_issue(input).await,
            "linear.search_issues" => self.invoke_search_issues(input).await,
            "linear.list_teams" => self.invoke_list_teams().await,
            "linear.list_cycles" => self.invoke_list_cycles(input).await,
            "linear.add_comment" => self.invoke_add_comment(input).await,
            "linear.list_projects" => self.invoke_list_projects().await,
            "linear.process_webhook" => self.invoke_process_webhook(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let title = require_str(&input, "title")?;
        let team_id = require_str(&input, "team_id")?;
        let description = input.get("description").and_then(|v| v.as_str());

        let issue = client
            .create_issue(title, team_id, description)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_get_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;

        let issue = client
            .get_issue(issue_id)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_update_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;
        let title = input.get("title").and_then(|v| v.as_str());
        let state_id = input.get("state_id").and_then(|v| v.as_str());
        let description = input.get("description").and_then(|v| v.as_str());

        let issue = client
            .update_issue(issue_id, title, state_id, description)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_search_issues(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let issues = client
            .search_issues(query)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issues": issues }))
    }

    async fn invoke_list_teams(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let teams = client
            .list_teams()
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "teams": teams }))
    }

    async fn invoke_list_cycles(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let team_id = require_str(&input, "team_id")?;

        let cycles = client
            .list_cycles(team_id)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "cycles": cycles }))
    }

    async fn invoke_add_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;
        let body = require_str(&input, "body")?;

        let comment = client
            .add_comment(issue_id, body)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "comment": comment }))
    }

    async fn invoke_list_projects(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let projects = client
            .list_projects()
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "projects": projects }))
    }

    async fn invoke_process_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use crate::types::{WebhookPayload, WebhookResourceType};

        let payload_value = input.get("payload").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: payload".into(),
        })?;

        let payload: WebhookPayload =
            serde_json::from_value(payload_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid webhook payload: {e}"),
                }
            })?;

        let topic = payload.resource_type.to_topic(payload.action);

        info!(
            event = "linear.webhook.processed",
            topic = %topic,
            resource_type = %payload.resource_type,
            action = %payload.action,
            webhook_id = ?payload.webhook_id,
            "Linear webhook event processed"
        );

        // Extract resource ID from data if available
        let resource_id = payload
            .data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let resource_uri = match payload.resource_type {
            WebhookResourceType::Issue => format!("linear://issue/{resource_id}"),
            WebhookResourceType::Comment => format!("linear://comment/{resource_id}"),
            WebhookResourceType::Project => format!("linear://project/{resource_id}"),
            WebhookResourceType::Cycle => format!("linear://cycle/{resource_id}"),
            WebhookResourceType::IssueLabel => format!("linear://label/{resource_id}"),
            WebhookResourceType::Reaction => format!("linear://reaction/{resource_id}"),
        };

        Ok(json!({
            "event": {
                "topic": topic,
                "resource_type": payload.resource_type.to_string(),
                "action": payload.action.to_string(),
                "resource_uri": resource_uri,
                "resource_id": resource_id,
                "actor": payload.actor,
                "timestamp": payload.created_at,
                "data": payload.data,
                "webhook_id": payload.webhook_id,
            }
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Linear connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for LinearConnector {
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
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = LinearConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = LinearConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.get_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "linear.get_issue");

        let result = connector
            .handle_invoke(json!({
                "operation": "linear.get_issue",
                "input": { "issue_id": "LIN-123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = LinearConnector::new();
        connector.client = Some(
            LinearClient::new("fake_key")
                .unwrap()
                .with_api_url("http://localhost:9999/graphql"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.create_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "linear.create_issue");

        let result = connector
            .handle_invoke(json!({
                "operation": "linear.create_issue",
                "input": { "title": "Bug" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("team_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = LinearConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"linear.create_issue"));
        assert!(op_ids.contains(&"linear.get_issue"));
        assert!(op_ids.contains(&"linear.update_issue"));
        assert!(op_ids.contains(&"linear.search_issues"));
        assert!(op_ids.contains(&"linear.list_teams"));
        assert!(op_ids.contains(&"linear.list_cycles"));
        assert!(op_ids.contains(&"linear.add_comment"));
        assert!(op_ids.contains(&"linear.list_projects"));
        assert!(op_ids.contains(&"linear.process_webhook"));
        assert_eq!(ops.len(), 9);

        // Verify event descriptors are present
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 12);
        let topics: Vec<&str> = events
            .iter()
            .map(|e| e["topic"].as_str().unwrap())
            .collect();
        assert!(topics.contains(&"linear.issue.create"));
        assert!(topics.contains(&"linear.issue.update"));
        assert!(topics.contains(&"linear.issue.remove"));
        assert!(topics.contains(&"linear.comment.create"));
        assert!(topics.contains(&"linear.project.update"));
        assert!(topics.contains(&"linear.cycle.remove"));
    }

    // ── Doctor tests ──────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = LinearConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        let config_check = &checks[0];
        assert_eq!(config_check["name"], "configuration");
        assert!(!config_check["passed"].as_bool().unwrap());
        assert!(config_check["critical"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_api_key() {
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "lin_api_test123"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();

        // All critical checks should pass
        for check in checks {
            if check["critical"].as_bool().unwrap() {
                assert!(
                    check["passed"].as_bool().unwrap(),
                    "Critical check '{}' should pass",
                    check["name"]
                );
            }
        }

        // Auth mode should show redacted
        let auth_check = checks.iter().find(|c| c["name"] == "auth_mode").unwrap();
        assert!(
            auth_check["message"]
                .as_str()
                .unwrap()
                .contains("api_key:redacted")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        // Should be degraded because credential_injection check fails (not passed)
        // but it's not critical, so status depends on other checks
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert!(!cred_check["passed"].as_bool().unwrap());
        assert!(!cred_check["critical"].as_bool().unwrap());

        let auth_check = checks.iter().find(|c| c["name"] == "auth_mode").unwrap();
        assert!(
            auth_check["message"]
                .as_str()
                .unwrap()
                .contains("credential_id:")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_bad_network_host() {
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test",
                "api_url": "https://evil.example.com/graphql"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        let net_check = checks
            .iter()
            .find(|c| c["name"] == "network_constraints")
            .unwrap();
        assert!(!net_check["passed"].as_bool().unwrap());
        assert!(net_check["critical"].as_bool().unwrap());
    }

    // ── Self-check tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        use fcp_core::SelfCheckStatus;
        let connector = LinearConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_mode() {
        use fcp_core::SelfCheckStatus;
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unreachable_api() {
        use fcp_core::SelfCheckStatus;
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "bad-key",
                "api_url": "http://127.0.0.1:1/graphql"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        // Should be degraded (retryable) since connection refused is an HTTP error
        assert!(
            report.status == SelfCheckStatus::Degraded || report.status == SelfCheckStatus::Failed
        );
    }

    // ── Configure multi-auth tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_api_key() {
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "lin_api_test" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id() {
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_both_rejected() {
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "test",
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
    async fn test_configure_none_rejected() {
        let mut connector = LinearConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
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

    // ── Sync unit tests: config, helpers ──────────────────────────

    #[test]
    fn config_from_api_key() {
        let cfg = LinearConfig::from_params(&json!({ "api_key": "lin_api_test" })).unwrap();
        assert!(!cfg.auth.is_secretless());
        assert_eq!(cfg.api_url, DEFAULT_API_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let cfg = LinearConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .unwrap();
        assert!(cfg.auth.is_secretless());
    }

    #[test]
    fn config_custom_api_url() {
        let cfg = LinearConfig::from_params(&json!({
            "api_key": "test",
            "api_url": "https://linear.example.com/graphql"
        }))
        .unwrap();
        assert_eq!(cfg.api_url, "https://linear.example.com/graphql");
    }

    #[test]
    fn config_trims_api_key() {
        let cfg = LinearConfig::from_params(&json!({ "api_key": "  lin_api_test  " })).unwrap();
        match &cfg.auth {
            LinearAuth::ApiKey(k) => assert_eq!(k, "lin_api_test"),
            LinearAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn config_rejects_empty_api_key() {
        assert!(LinearConfig::from_params(&json!({ "api_key": "" })).is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        assert!(LinearConfig::from_params(&json!({ "api_key": "   " })).is_err());
    }

    #[test]
    fn config_rejects_both_auth() {
        let result = LinearConfig::from_params(&json!({
            "api_key": "test",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        assert!(LinearConfig::from_params(&json!({})).is_err());
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        assert!(LinearConfig::from_params(&json!({ "credential_id": "bad" })).is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        assert!(LinearConfig::from_params(&json!({ "credential_id": 12345 })).is_err());
    }

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"issue_id": "LIN-1"});
        assert_eq!(require_str(&input, "issue_id").unwrap(), "LIN-1");
    }

    #[test]
    fn require_str_missing() {
        assert!(require_str(&json!({}), "x").is_err());
    }

    #[test]
    fn require_str_non_string() {
        assert!(require_str(&json!({"x": 42}), "x").is_err());
    }

    #[test]
    fn require_str_null() {
        assert!(require_str(&json!({"x": null}), "x").is_err());
    }

    #[test]
    fn connector_default() {
        let c = LinearConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }
}
