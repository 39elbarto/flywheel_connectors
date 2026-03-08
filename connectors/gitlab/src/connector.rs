//! FCP `GitLab` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, GitLabAuth, GitLabClient},
    error::GitLabError,
};

/// Parsed and validated `GitLab` connector configuration.
#[derive(Debug, Clone)]
struct GitLabConfig {
    auth: GitLabAuth,
    base_url: String,
}

impl GitLabConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let private_token = params
            .get("private_token")
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

        let auth = match (private_token, credential_id) {
            (Some(token), None) => GitLabAuth::PrivateToken(token),
            (None, Some(cred_id)) => GitLabAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of private_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing private_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
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

/// FCP `GitLab` Connector.
pub struct GitLabConnector {
    base: Arc<BaseConnector>,
    config: Option<GitLabConfig>,
    client: Option<Arc<GitLabClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl GitLabConnector {
    /// Create a new `GitLab` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("gitlab"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for GitLabConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl GitLabConnector {
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = GitLabConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring GitLab connector");
        let client = GitLabClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }
        self.session_id = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        self.base.set_handshaken(true);
        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.gitlab",
            "connector_version": "0.1.0",
            "capabilities": ["gitlab.projects.read", "gitlab.issues.read", "gitlab.issues.write", "gitlab.merge_requests.read", "gitlab.pipelines.read"]
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };
        Ok(
            json!({ "status": status, "configured": configured, "handshaken": handshaken, "requests": self.request_count.load(Ordering::Relaxed), "errors": self.error_count.load(Ordering::Relaxed) }),
        )
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured".into())
            } else {
                None
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("API client not initialized".into())
            } else {
                None
            },
            critical: true,
        });
        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });
        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(
            json!({ "connector_id": "fcp.gitlab", "version": "0.1.0", "status": if self.config.is_some() { "ready" } else { "unconfigured" } }),
        )
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(
            json!({ "connector_id": "fcp.gitlab", "version": "0.1.0", "operations": serde_json::to_value(operations_info()).unwrap_or_default() }),
        )
    }

    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let operation = params.get("operation_id").and_then(|v| v.as_str()).ok_or(
            FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            },
        )?;
        let input = params.get("input").cloned().unwrap_or(json!({}));
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "gitlab.projects.list" => self.invoke_projects_list(client, &input).await,
            "gitlab.issues.list" => self.invoke_issues_list(client, &input).await,
            "gitlab.issues.create" => self.invoke_issues_create(client, &input).await,
            "gitlab.merge_requests.list" => self.invoke_merge_requests_list(client, &input).await,
            "gitlab.pipelines.list" => self.invoke_pipelines_list(client, &input).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);
        Ok(
            json!({ "allowed": allowed, "reason": if allowed { "Operation supported" } else { "Unknown operation" } }),
        )
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("GitLab connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // ── Operations ────────────────────────────────────────────────────

    async fn invoke_projects_list(
        &self,
        client: &GitLabClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GitLabError> {
        let per_page = input.get("per_page").and_then(|v| v.as_i64());
        let data = client.list_projects(per_page).await?;
        Ok(json!({ "projects": data }))
    }

    async fn invoke_issues_list(
        &self,
        client: &GitLabClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GitLabError> {
        let project_id = require_str(input, "project_id")?;
        let data = client.list_issues(project_id).await?;
        Ok(json!({ "issues": data }))
    }

    async fn invoke_issues_create(
        &self,
        client: &GitLabClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GitLabError> {
        let project_id = require_str(input, "project_id")?;
        let title = require_str(input, "title")?;
        let mut body = json!({ "title": title });
        if let Some(desc) = input.get("description") {
            body["description"] = desc.clone();
        }
        client.create_issue(project_id, &body).await
    }

    async fn invoke_merge_requests_list(
        &self,
        client: &GitLabClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GitLabError> {
        let project_id = require_str(input, "project_id")?;
        let data = client.list_merge_requests(project_id).await?;
        Ok(json!({ "merge_requests": data }))
    }

    async fn invoke_pipelines_list(
        &self,
        client: &GitLabClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GitLabError> {
        let project_id = require_str(input, "project_id")?;
        let data = client.list_pipelines(project_id).await?;
        Ok(json!({ "pipelines": data }))
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, GitLabError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| GitLabError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("gitlab.projects.list"),
            summary: "List projects".into(),
            input_schema: json!({
                "type": "object",
                "required": [],
                "properties": {
                    "per_page": { "type": "integer", "maximum": 100 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["projects"],
                "properties": {
                    "projects": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("gitlab.projects.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List GitLab projects.".into(),
                common_mistakes: vec![],
                examples: vec![r"{}".into()],
                related: vec![
                    CapabilityId::from_static("gitlab.issues.list"),
                    CapabilityId::from_static("gitlab.merge_requests.list"),
                ],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("gitlab.issues.list"),
            summary: "List issues in a project".into(),
            input_schema: json!({
                "type": "object",
                "required": ["project_id"],
                "properties": {
                    "project_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["issues"],
                "properties": {
                    "issues": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("gitlab.issues.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List issues in a project.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"project_id": "12345"}"#.into()],
                related: vec![
                    CapabilityId::from_static("gitlab.issues.create"),
                    CapabilityId::from_static("gitlab.projects.list"),
                ],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("gitlab.issues.create"),
            summary: "Create an issue".into(),
            input_schema: json!({
                "type": "object",
                "required": ["project_id", "title"],
                "properties": {
                    "project_id": { "type": "string" },
                    "title": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["iid"],
                "properties": {
                    "iid": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("gitlab.issues.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Create a new issue.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"project_id": "12345", "title": "Fix login timeout", "description": "Users report timeouts after 30s"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("gitlab.issues.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("gitlab.merge_requests.list"),
            summary: "List merge requests".into(),
            input_schema: json!({
                "type": "object",
                "required": ["project_id"],
                "properties": {
                    "project_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["merge_requests"],
                "properties": {
                    "merge_requests": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("gitlab.merge_requests.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List merge requests in a project.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"project_id": "12345"}"#.into()],
                related: vec![
                    CapabilityId::from_static("gitlab.projects.list"),
                    CapabilityId::from_static("gitlab.pipelines.list"),
                ],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("gitlab.pipelines.list"),
            summary: "List pipelines".into(),
            input_schema: json!({
                "type": "object",
                "required": ["project_id"],
                "properties": {
                    "project_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["pipelines"],
                "properties": {
                    "pipelines": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("gitlab.pipelines.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List CI/CD pipelines.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"project_id": "12345"}"#.into()],
                related: vec![CapabilityId::from_static("gitlab.merge_requests.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── GitLabConfig::from_params ────────────────────────────────────

    #[test]
    fn config_from_private_token() {
        let config = GitLabConfig::from_params(&json!({ "private_token": "glpat-test" })).unwrap();
        assert!(matches!(config.auth, GitLabAuth::PrivateToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = GitLabConfig::from_params(
            &json!({ "credential_id": "550e8400-e29b-41d4-a716-446655440000" }),
        )
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_rejects_both() {
        let result = GitLabConfig::from_params(
            &json!({ "private_token": "tok", "credential_id": "550e8400-e29b-41d4-a716-446655440000" }),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_none() {
        let result = GitLabConfig::from_params(&json!({}));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_empty_token() {
        assert!(GitLabConfig::from_params(&json!({ "private_token": "" })).is_err());
    }

    #[test]
    fn config_rejects_whitespace_only_token() {
        assert!(GitLabConfig::from_params(&json!({ "private_token": "   " })).is_err());
    }

    #[test]
    fn config_trims_token() {
        let config =
            GitLabConfig::from_params(&json!({ "private_token": "  glpat-test  " })).unwrap();
        match &config.auth {
            GitLabAuth::PrivateToken(t) => assert_eq!(t, "glpat-test"),
            GitLabAuth::CredentialId(_) => panic!("expected PrivateToken"),
        }
    }

    #[test]
    fn config_custom_base_url() {
        let config = GitLabConfig::from_params(&json!({
            "private_token": "glpat-test",
            "base_url": "https://gitlab.example.com/api/v4"
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://gitlab.example.com/api/v4");
    }

    #[test]
    fn config_default_base_url() {
        let config = GitLabConfig::from_params(&json!({ "private_token": "glpat-test" })).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        let result = GitLabConfig::from_params(&json!({ "credential_id": "not-a-uuid" }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("UUID"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = GitLabConfig::from_params(&json!({ "credential_id": 42 }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("string"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── DoctorResult ─────────────────────────────────────────────────

    #[test]
    fn doctor_result_healthy() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_non_critical_fails() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_critical_fails() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: Some("down".into()),
            critical: true,
        }]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_empty_checks_is_healthy() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "config".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    // ── require_str ──────────────────────────────────────────────────

    #[test]
    fn require_str_present() {
        let input = json!({ "project_id": "123" });
        assert_eq!(require_str(&input, "project_id").unwrap(), "123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        let err = require_str(&input, "project_id").unwrap_err();
        match err {
            GitLabError::Api {
                status_code,
                message,
            } => {
                assert_eq!(status_code, 400);
                assert!(message.contains("project_id"));
            }
            _ => panic!("expected Api error"),
        }
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({ "project_id": 42 });
        assert!(require_str(&input, "project_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({ "project_id": null });
        assert!(require_str(&input, "project_id").is_err());
    }

    // ── operations_info ──────────────────────────────────────────────

    #[test]
    fn operations_info_has_5_operations() {
        assert_eq!(operations_info().len(), 5);
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            if cap.to_ascii_lowercase().ends_with(".read") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "read op {} should be safe",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn all_operations_have_summaries() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {:?} has empty summary",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_have_valid_risk_levels() {
        let ops = operations_info();
        for op in &ops {
            // All RiskLevel enum variants are valid by construction
            let _ = op.risk_level;
        }
    }

    #[test]
    fn operations_have_valid_safety_tiers() {
        let ops = operations_info();
        for op in &ops {
            // All SafetyTier enum variants are valid by construction
            let _ = op.safety_tier;
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let expected = [
            "gitlab.projects.list",
            "gitlab.issues.list",
            "gitlab.issues.create",
            "gitlab.merge_requests.list",
            "gitlab.pipelines.list",
        ];
        for e in &expected {
            assert!(ids.contains(e), "missing expected operation {e}");
        }
    }

    // ── Connector default ────────────────────────────────────────────

    #[test]
    fn connector_default() {
        let c = GitLabConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_new_counters_zero() {
        let c = GitLabConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
        assert!(c.config.is_none());
    }

    #[test]
    fn doctor_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn doctor_status_deserializes_lowercase() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_eq() {
        let s = DoctorStatus::Healthy;
        let s2 = s; // Copy
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "c1".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "c2".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "degraded");
        let back: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(back.status, DoctorStatus::Degraded);
        assert_eq!(back.checks.len(), 2);
    }

    #[test]
    fn doctor_check_message_none_omitted() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_message_some_present() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("err".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "err");
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"f": ""});
        assert_eq!(require_str(&input, "f").unwrap(), "");
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"f": true});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"f": [1, 2, 3]});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"f": {"nested": true}});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn operations_list_ops_are_strict_idempotent() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            if id.contains("list") {
                assert_eq!(
                    op.idempotency,
                    IdempotencyClass::Strict,
                    "list op {id} should be strict idempotent"
                );
            }
        }
    }

    #[test]
    fn operations_create_is_not_idempotent() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            if id.contains("create") {
                assert_eq!(
                    op.idempotency,
                    IdempotencyClass::None,
                    "create op {id} should not be idempotent"
                );
            }
        }
    }

    #[test]
    fn operations_all_summaries_non_empty() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {:?} has empty summary",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                cap.starts_with("gitlab."),
                "capability {cap} should start with gitlab."
            );
        }
    }

    #[test]
    fn doctor_result_debug_and_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_clone_and_debug() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("fail".into()),
            critical: true,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "test");
        assert_eq!(cloned.message.as_deref(), Some("fail"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn config_debug_and_clone() {
        let config = GitLabConfig::from_params(&json!({"private_token": "glpat-test"})).unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(cloned.base_url, DEFAULT_BASE_URL);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("GitLabConfig"));
    }

    #[test]
    fn doctor_multiple_critical_failures() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: true,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_write_ops_have_correct_capability() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            let cap = op.capability.as_ref();
            if id.contains("create") {
                assert!(cap.ends_with(".write"), "write op {id} has cap {cap}");
            }
        }
    }

    #[test]
    fn operations_create_is_risky() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            if id.contains("create") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Risky,
                    "create op {id} should be risky"
                );
            }
        }
    }
}
