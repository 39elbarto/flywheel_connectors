//! FCP GitHub Connector implementation.

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

use crate::client::{DEFAULT_BASE_URL, GitHubAuth, GitHubClient};
use crate::error::GitHubError;
use crate::types::{CreateIssueRequest, CreatePullRequestRequest, MergePullRequestRequest};

/// Parsed configuration for the GitHub connector.
struct GitHubConfig {
    auth: GitHubAuth,
    base_url: String,
}

impl GitHubConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let token = params.get("token").and_then(|v| v.as_str());
        let credential_id = params.get("credential_id").and_then(|v| v.as_str());
        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let auth = match (token, credential_id) {
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either token or credential_id, not both".into(),
                });
            }
            (Some(t), None) => GitHubAuth::Token(t.to_string()),
            (None, Some(raw)) => {
                let cid = CredentialId::parse(raw).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid credential_id: {e}"),
                })?;
                GitHubAuth::CredentialId(cid)
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
            base_url: base_url.map_or_else(|| DEFAULT_BASE_URL.to_string(), String::from),
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

/// FCP GitHub Connector.
pub struct GitHubConnector {
    base: Arc<BaseConnector>,
    client: Option<GitHubClient>,
    config: Option<GitHubConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GitHubConnector {
    /// Create a new GitHub connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("github"))),
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
        let cfg = GitHubConfig::from_params(&params)?;

        let client =
            GitHubClient::new_with_auth(cfg.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_base_url(&cfg.base_url);

        self.client = Some(client);
        self.config = Some(cfg);
        self.base.set_configured(true);
        info!("GitHub connector configured");

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
            manifest_hash: "sha256:github-connector-v1".into(),
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
            .map_or("not_configured", |c| c.base_url.as_str());
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
            .map_or("not_configured", |c| c.base_url.as_str());
        checks.push(DoctorCheck {
            name: "base_url".into(),
            status: DoctorStatus::Pass,
            message: format!("API URL: {base_url}"),
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
            message: format!("Egress target: api.github.com (via {base_url})"),
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
                "Direct Bearer auth — no proxy required".into()
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
                "Secretless mode — cannot verify connectivity without egress proxy",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        }

        let Some(client) = &self.client else {
            let report = SelfCheckReport::failed("client_missing", "HTTP client not initialized");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        match client.health_check().await {
            Ok(_) => {
                let report = SelfCheckReport::ok();
                serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check: {e}"),
                })
            }
            Err(e) => {
                let report =
                    SelfCheckReport::failed("connectivity_failed", format!("API call failed: {e}"));
                serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check: {e}"),
                })
            }
        }
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "github.create_issue",
                    "Create an issue in a repository",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "title"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "title": { "type": "string" },
                            "body": { "type": "string" },
                            "assignees": { "type": "array", "items": { "type": "string" } },
                            "labels": { "type": "array", "items": { "type": "string" } }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "github.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new issue in a GitHub repository.".into(),
                        common_mistakes: vec!["Forgetting to specify both owner and repo".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "title": "Bug report"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_issue"), CapabilityId::from_static("github.search_issues")],
                    },
                ),
                op_info(
                    "github.get_issue",
                    "Get a single issue by number",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "issue_number"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "issue_number": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve details about a specific issue.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "issue_number": 42}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.create_issue"), CapabilityId::from_static("github.search_issues")],
                    },
                ),
                op_info(
                    "github.search_issues",
                    "Search issues and pull requests",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": { "query": { "type": "string" } }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" },
                            "total_count": { "type": "integer" }
                        }
                    }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for issues or PRs matching a query.".into(),
                        common_mistakes: vec!["Using non-GitHub search syntax".into()],
                        examples: vec![
                            r#"{"query": "is:open is:issue repo:octocat/hello-world"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_issue")],
                    },
                ),
                op_info(
                    "github.create_pull_request",
                    "Create a pull request",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "title", "head", "base"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "title": { "type": "string" },
                            "head": { "type": "string" },
                            "base": { "type": "string" },
                            "body": { "type": "string" },
                            "draft": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "pull_request": { "type": "object" } } }),
                    "github.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Open a new pull request.".into(),
                        common_mistakes: vec!["Mixing up head (source) and base (target) branches".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "title": "Fix typo", "head": "fix-typo", "base": "main"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_pull_request"), CapabilityId::from_static("github.merge_pull_request")],
                    },
                ),
                op_info(
                    "github.get_pull_request",
                    "Get a single pull request by number",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "pull_number"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "pull_number": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "pull_request": { "type": "object" } } }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve details about a specific pull request.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "pull_number": 1}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.create_pull_request")],
                    },
                ),
                op_info(
                    "github.merge_pull_request",
                    "Merge a pull request",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "pull_number"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "pull_number": { "type": "integer" },
                            "merge_method": { "type": "string", "enum": ["merge", "squash", "rebase"] }
                        }
                    }),
                    json!({ "type": "object", "properties": { "merged": { "type": "boolean" } } }),
                    "github.admin",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Merge an approved pull request into the base branch.".into(),
                        common_mistakes: vec!["Merging without checking CI status or reviews".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "pull_number": 1, "merge_method": "squash"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_pull_request")],
                    },
                ),
                op_info(
                    "github.get_repo",
                    "Get repository metadata",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "repository": { "type": "object" } } }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve metadata about a repository.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"owner": "octocat", "repo": "hello-world"}"#.into()],
                        related: vec![CapabilityId::from_static("github.search_repos")],
                    },
                ),
                op_info(
                    "github.search_repos",
                    "Search repositories",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": { "query": { "type": "string" } }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" },
                            "total_count": { "type": "integer" }
                        }
                    }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for repositories matching a query.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"query": "language:rust stars:>1000"}"#.into()],
                        related: vec![CapabilityId::from_static("github.get_repo")],
                    },
                ),
                op_info(
                    "github.list_workflows",
                    "List GitHub Actions workflows",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "workflows": { "type": "array" },
                            "total_count": { "type": "integer" }
                        }
                    }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List CI/CD workflows in a repository.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"owner": "octocat", "repo": "hello-world"}"#.into()],
                        related: vec![CapabilityId::from_static("github.trigger_workflow")],
                    },
                ),
                op_info(
                    "github.trigger_workflow",
                    "Trigger a GitHub Actions workflow dispatch",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "workflow_id", "ref"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "workflow_id": { "type": "string" },
                            "ref": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "triggered": { "type": "boolean" } } }),
                    "github.admin",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Manually trigger a GitHub Actions workflow.".into(),
                        common_mistakes: vec!["Using workflow file name instead of ID".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "workflow_id": "ci.yml", "ref": "main"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.list_workflows")],
                    },
                ),
                op_info(
                    "github.get_file_content",
                    "Get file or directory content",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "path"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "path": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "content": { "type": "object" } } }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read file content from a repository.".into(),
                        common_mistakes: vec!["Not specifying a ref for a specific branch".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "path": "README.md"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.search_code")],
                    },
                ),
                op_info(
                    "github.search_code",
                    "Search code across repositories",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": { "query": { "type": "string" } }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" },
                            "total_count": { "type": "integer" }
                        }
                    }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for code matching a query across GitHub.".into(),
                        common_mistakes: vec!["Not scoping to a repo or org".into()],
                        examples: vec![
                            r#"{"query": "addClass repo:octocat/hello-world"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_file_content")],
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
            "github.create_issue" => self.invoke_create_issue(input).await,
            "github.get_issue" => self.invoke_get_issue(input).await,
            "github.search_issues" => self.invoke_search_issues(input).await,
            "github.create_pull_request" => self.invoke_create_pull_request(input).await,
            "github.get_pull_request" => self.invoke_get_pull_request(input).await,
            "github.merge_pull_request" => self.invoke_merge_pull_request(input).await,
            "github.get_repo" => self.invoke_get_repo(input).await,
            "github.search_repos" => self.invoke_search_repos(input).await,
            "github.list_workflows" => self.invoke_list_workflows(input).await,
            "github.trigger_workflow" => self.invoke_trigger_workflow(input).await,
            "github.get_file_content" => self.invoke_get_file_content(input).await,
            "github.search_code" => self.invoke_search_code(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let title = require_str(&input, "title")?;

        let req = CreateIssueRequest {
            title: title.into(),
            body: input.get("body").and_then(|v| v.as_str()).map(Into::into),
            assignees: input
                .get("assignees")
                .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok()),
            labels: input
                .get("labels")
                .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok()),
            milestone: input
                .get("milestone")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
        };

        let issue = client
            .create_issue(owner, repo, &req)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_get_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let issue_number = require_u32(&input, "issue_number")?;

        let issue = client
            .get_issue(owner, repo, issue_number)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_search_issues(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let results = client
            .search_issues(query)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({
            "items": results.items,
            "total_count": results.total_count
        }))
    }

    async fn invoke_create_pull_request(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let title = require_str(&input, "title")?;
        let head = require_str(&input, "head")?;
        let base = require_str(&input, "base")?;

        let req = CreatePullRequestRequest {
            title: title.into(),
            head: head.into(),
            base: base.into(),
            body: input.get("body").and_then(|v| v.as_str()).map(Into::into),
            draft: input.get("draft").and_then(|v| v.as_bool()),
        };

        let pr = client
            .create_pull_request(owner, repo, &req)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "pull_request": pr }))
    }

    async fn invoke_get_pull_request(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let pull_number = require_u32(&input, "pull_number")?;

        let pr = client
            .get_pull_request(owner, repo, pull_number)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "pull_request": pr }))
    }

    async fn invoke_merge_pull_request(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let pull_number = require_u32(&input, "pull_number")?;

        let req = MergePullRequestRequest {
            commit_title: input
                .get("commit_title")
                .and_then(|v| v.as_str())
                .map(Into::into),
            commit_message: input
                .get("commit_message")
                .and_then(|v| v.as_str())
                .map(Into::into),
            merge_method: input
                .get("merge_method")
                .and_then(|v| v.as_str())
                .map(Into::into),
            sha: input.get("sha").and_then(|v| v.as_str()).map(Into::into),
        };

        let result = client
            .merge_pull_request(owner, repo, pull_number, &req)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "merged": result.merged, "sha": result.sha, "message": result.message }))
    }

    async fn invoke_get_repo(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;

        let repository = client
            .get_repo(owner, repo)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "repository": repository }))
    }

    async fn invoke_search_repos(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let results = client
            .search_repos(query)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({
            "items": results.items,
            "total_count": results.total_count
        }))
    }

    async fn invoke_list_workflows(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;

        let result = client
            .list_workflows(owner, repo)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({
            "workflows": result.workflows,
            "total_count": result.total_count
        }))
    }

    async fn invoke_trigger_workflow(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let workflow_id = require_str(&input, "workflow_id")?;
        let git_ref = require_str(&input, "ref")?;

        client
            .trigger_workflow(owner, repo, workflow_id, git_ref)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "triggered": true }))
    }

    async fn invoke_get_file_content(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let path = require_str(&input, "path")?;

        let content = client
            .get_file_content(owner, repo, path)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "content": content }))
    }

    async fn invoke_search_code(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let results = client
            .search_code(query)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({
            "items": results.items,
            "total_count": results.total_count
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
        info!("GitHub connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GitHubConnector {
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

fn require_u32(input: &serde_json::Value, field: &str) -> FcpResult<u32> {
    input
        .get(field)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
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
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = GitHubConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = GitHubConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.get_repo"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "github.get_repo");

        let result = connector
            .handle_invoke(json!({
                "operation": "github.get_repo",
                "input": { "owner": "octocat", "repo": "hello-world" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = GitHubConnector::new();
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
                "capabilities_requested": ["github.get_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "github.get_issue");

        let result = connector
            .handle_invoke(json!({
                "operation": "github.get_issue",
                "input": { "owner": "octocat" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("repo") || message.contains("issue_number"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"github.create_issue"));
        assert!(op_ids.contains(&"github.get_issue"));
        assert!(op_ids.contains(&"github.search_issues"));
        assert!(op_ids.contains(&"github.create_pull_request"));
        assert!(op_ids.contains(&"github.get_pull_request"));
        assert!(op_ids.contains(&"github.merge_pull_request"));
        assert!(op_ids.contains(&"github.get_repo"));
        assert!(op_ids.contains(&"github.search_repos"));
        assert!(op_ids.contains(&"github.list_workflows"));
        assert!(op_ids.contains(&"github.trigger_workflow"));
        assert!(op_ids.contains(&"github.get_file_content"));
        assert!(op_ids.contains(&"github.search_code"));
        assert_eq!(ops.len(), 12);
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

    // ── Provisioning automation tests ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_token_auth() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ghp_test_token"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
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
    async fn test_configure_rejects_both_token_and_credential_id() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "token": "ghp_test",
                "credential_id": cid
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_auth() {
        let mut connector = GitHubConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_base_url() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ghp_test",
                "base_url": "https://github.example.com/api/v3"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_mode() {
        let mut connector = GitHubConnector::new();
        connector
            .handle_configure(json!({ "token": "ghp_test" }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert_eq!(result["auth_mode"], "token");
        assert_eq!(result["api_url"], DEFAULT_BASE_URL);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured() {
        let mut connector = GitHubConnector::new();
        connector
            .handle_configure(json!({ "token": "ghp_test" }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|c| c["status"] == "pass"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = GitHubConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.iter().any(|c| c["status"] == "fail"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_warns() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
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
        let connector = GitHubConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    // ─── Introspection metadata tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_required_metadata() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(op["capability"].as_str().is_some(), "Op {id} missing capability");
            assert!(op["risk_level"].as_str().is_some(), "Op {id} missing risk_level");
            assert!(op["safety_tier"].as_str().is_some(), "Op {id} missing safety_tier");
            assert!(op["idempotency"].as_str().is_some(), "Op {id} missing idempotency");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels_valid() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let valid_risk = ["low", "medium", "high", "critical"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(valid_risk.contains(&risk), "Op {id} has invalid risk_level: {risk}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_read_ops_are_safe() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let read_ops = ["github.get_issue", "github.get_pull_request", "github.get_repo",
                        "github.get_file_content", "github.search_issues", "github.search_repos",
                        "github.search_code", "github.list_workflows"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(), "safe",
                    "Read op {id} should be safe"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_deterministic() {
        let connector = GitHubConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        assert_eq!(a, b, "Introspection should be deterministic");
    }

    // ─── Schema completeness tests ─────────────────────────────────

    const ALL_GITHUB_OPERATIONS: &[&str] = &[
        "github.create_issue",
        "github.get_issue",
        "github.search_issues",
        "github.create_pull_request",
        "github.get_pull_request",
        "github.merge_pull_request",
        "github.get_repo",
        "github.search_repos",
        "github.list_workflows",
        "github.trigger_workflow",
        "github.get_file_content",
        "github.search_code",
    ];

    /// Helper: extract `input_schema` for a named op from introspection result.
    fn input_schema_from_introspect(
        result: &serde_json::Value,
        op_name: &str,
    ) -> Option<serde_json::Value> {
        let ops = result["operations"].as_array()?;
        ops.iter()
            .find(|o| o["id"].as_str() == Some(op_name))
            .map(|o| o["input_schema"].clone())
    }

    /// Helper: extract `output_schema` for a named op from introspection result.
    fn output_schema_from_introspect(
        result: &serde_json::Value,
        op_name: &str,
    ) -> Option<serde_json::Value> {
        let ops = result["operations"].as_array()?;
        ops.iter()
            .find(|o| o["id"].as_str() == Some(op_name))
            .map(|o| o["output_schema"].clone())
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_input_schema() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        for op in ALL_GITHUB_OPERATIONS {
            assert!(
                input_schema_from_introspect(&result, op).is_some(),
                "Missing input schema for {op}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_output_schema() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        for op in ALL_GITHUB_OPERATIONS {
            assert!(
                output_schema_from_introspect(&result, op).is_some(),
                "Missing output schema for {op}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_unknown_operation_returns_none_schema() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        assert!(input_schema_from_introspect(&result, "github.nonexistent").is_none());
        assert!(output_schema_from_introspect(&result, "github.nonexistent").is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_input_schemas_are_object_type() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        for op in ALL_GITHUB_OPERATIONS {
            let schema = input_schema_from_introspect(&result, op).unwrap();
            assert_eq!(
                schema["type"], "object",
                "Input schema for {op} must be type=object"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_schemas_deterministic_across_calls() {
        let connector = GitHubConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        for op in ALL_GITHUB_OPERATIONS {
            let a_in = input_schema_from_introspect(&a, op).unwrap();
            let b_in = input_schema_from_introspect(&b, op).unwrap();
            assert_eq!(a_in, b_in, "Input schema for {op} not deterministic");

            let a_out = output_schema_from_introspect(&a, op).unwrap();
            let b_out = output_schema_from_introspect(&b, op).unwrap();
            assert_eq!(a_out, b_out, "Output schema for {op} not deterministic");
        }
    }

    // ─── Schema required fields tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_create_issue_requires_owner_repo_title() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let schema = input_schema_from_introspect(&result, "github.create_issue").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"owner"));
        assert!(required_strs.contains(&"repo"));
        assert!(required_strs.contains(&"title"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_issue_requires_owner_repo_issue_number() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let schema = input_schema_from_introspect(&result, "github.get_issue").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"owner"));
        assert!(required_strs.contains(&"repo"));
        assert!(required_strs.contains(&"issue_number"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_repo_requires_owner_repo() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let schema = input_schema_from_introspect(&result, "github.get_repo").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"owner"));
        assert!(required_strs.contains(&"repo"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_issues_requires_query() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let schema = input_schema_from_introspect(&result, "github.search_issues").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("query")));
    }

    // ─── Connector default / new ───────────────────────────────────

    #[test]
    fn test_connector_new_has_no_config() {
        let connector = GitHubConnector::new();
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
    }

    #[test]
    fn test_connector_default_equals_new() {
        let a = GitHubConnector::new();
        let b = GitHubConnector::default();
        assert!(a.config.is_none());
        assert!(b.config.is_none());
    }

    // ─── Additional introspect metadata tests ─────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_delete_op_is_not_present() {
        // GitHub connector currently has no delete operations
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(!id.contains("delete"), "GitHub should not have delete ops: {id}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_write_ops_are_medium_or_high_risk() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let write_ops = ["github.create_issue", "github.create_pull_request",
                         "github.merge_pull_request", "github.trigger_workflow"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if write_ops.contains(&id) {
                let risk = op["risk_level"].as_str().unwrap();
                assert!(risk == "medium" || risk == "high",
                    "Write op {id} should be medium or high risk, got {risk}");
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_ai_hints() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(op["ai_hints"].is_object(), "Op {id} missing ai_hints");
            assert!(
                op["ai_hints"]["when_to_use"].is_string(),
                "Op {id} missing ai_hints.when_to_use"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_op_count() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 12, "Expected 12 operations");
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_search_code_requires_query() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops.iter().find(|o| o["id"] == "github.search_code").unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "query"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_get_file_content_requires_owner_repo_path() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops.iter().find(|o| o["id"] == "github.get_file_content").unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "owner"));
        assert!(required.iter().any(|v| v == "repo"));
        assert!(required.iter().any(|v| v == "path"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_merge_pull_request_requires_owner_repo_pull_number() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops.iter().find(|o| o["id"] == "github.merge_pull_request").unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "owner"));
        assert!(required.iter().any(|v| v == "repo"));
        assert!(required.iter().any(|v| v == "pull_number"));
    }

    // ─── Handshake tests ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_requested_capabilities() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.read", "github.write"]
            }))
            .await
            .unwrap();
        let grants = result["capabilities_granted"].as_array().unwrap();
        assert_eq!(grants.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_has_session_id() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.read"]
            }))
            .await
            .unwrap();
        assert!(result["session_id"].is_string());
        assert!(connector.session_id.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_event_caps() {
        let mut connector = GitHubConnector::new();
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
    }

    // ─── Health check tests ───────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured_status() {
        let connector = GitHubConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_metrics_start_at_zero() {
        let connector = GitHubConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["metrics"]["requests_total"], 0);
        assert_eq!(result["metrics"]["requests_error"], 0);
    }
}
