//! FCP `Roam Research` Connector implementation.

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
    client::{DEFAULT_BASE_URL, RoamAuth, RoamClient},
    error::RoamError,
};

/// Default graph name when none is provided.
const DEFAULT_GRAPH_NAME: &str = "default";

/// Parsed and validated `Roam Research` connector configuration.
#[derive(Debug, Clone)]
struct RoamConfig {
    auth: RoamAuth,
    base_url: String,
    graph_name: String,
}

impl RoamConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
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

        let auth = match (access_token, credential_id) {
            (Some(token), None) => RoamAuth::BearerToken(token),
            (None, Some(cred_id)) => RoamAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of access_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        let graph_name = params
            .get("graph_name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(DEFAULT_GRAPH_NAME)
            .to_string();

        Ok(Self {
            auth,
            base_url,
            graph_name,
        })
    }
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
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

/// FCP `Roam Research` Connector.
pub struct RoamConnector {
    base: Arc<BaseConnector>,
    config: Option<RoamConfig>,
    client: Option<Arc<RoamClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl RoamConnector {
    /// Create a new `Roam Research` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("roam"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for RoamConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl RoamConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = RoamConfig::from_params(&params)?;
        info!(
            auth = %config.auth.redacted_label(),
            base_url = %config.base_url,
            graph = %config.graph_name,
            "Configuring Roam Research connector"
        );

        let client = RoamClient::new(
            config.auth.clone(),
            &config.graph_name,
            Some(&config.base_url),
        )
        .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
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

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.roam",
            "connector_version": "0.1.0",
            "capabilities": [
                "roam.pages.read",
                "roam.blocks.read",
                "roam.blocks.write"
            ]
        }))
    }

    /// Handle the `health` method.
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

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured — call configure first".into())
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
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.roam",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.roam",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "roam.pages.list" => self.invoke_pages_list(client).await,
            "roam.pages.get" => self.invoke_pages_get(client, &input).await,
            "roam.blocks.list" => self.invoke_blocks_list(client, &input).await,
            "roam.blocks.create" => self.invoke_blocks_create(client, &input).await,
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

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Roam Research connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_pages_list(&self, client: &RoamClient) -> Result<serde_json::Value, RoamError> {
        let data = client.list_pages().await?;
        Ok(data)
    }

    async fn invoke_pages_get(
        &self,
        client: &RoamClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RoamError> {
        let title = require_str(input, "title")?;
        let data = client.get_page(title).await?;
        Ok(data)
    }

    async fn invoke_blocks_list(
        &self,
        client: &RoamClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RoamError> {
        let page_uid = require_str(input, "page_uid")?;
        let data = client.list_blocks(page_uid).await?;
        Ok(data)
    }

    async fn invoke_blocks_create(
        &self,
        client: &RoamClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RoamError> {
        let page_uid = require_str(input, "page_uid")?;
        let content = require_str(input, "content")?;
        let data = client.create_block(page_uid, content).await?;
        Ok(data)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, RoamError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RoamError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Helper to build a single `OperationInfo`.
#[allow(clippy::too_many_arguments)]
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

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "roam.pages.list",
            "List all pages in the graph",
            json!({"type": "object", "required": []}),
            json!({"type": "object", "required": ["pages"], "properties": {"pages": {"type": "array"}}}),
            "roam.pages.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all pages in the Roam Research graph.".into(),
                common_mistakes: vec!["Daily note pages are included in results; filter by title format (e.g. 'March 7th, 2026') if you only want user-created pages.".into()],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("roam.pages.get"),
                    CapabilityId::from_static("roam.blocks.list"),
                ],
            },
        ),
        op_info(
            "roam.pages.get",
            "Get a page by title",
            json!({"type": "object", "required": ["title"], "properties": {"title": {"type": "string", "description": "Page title"}}}),
            json!({"type": "object", "required": ["title", "uid"], "properties": {"title": {"type": "string"}, "uid": {"type": "string"}}}),
            "roam.pages.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get a specific page by title.".into(),
                common_mistakes: vec!["Page titles are case-sensitive; 'Daily Notes' and 'daily notes' are treated as different pages.".into()],
                examples: vec![r#"{"title": "Daily Notes"}"#.into()],
                related: vec![
                    CapabilityId::from_static("roam.pages.list"),
                    CapabilityId::from_static("roam.blocks.list"),
                ],
            },
        ),
        op_info(
            "roam.blocks.list",
            "List blocks on a page",
            json!({"type": "object", "required": ["page_uid"], "properties": {"page_uid": {"type": "string", "description": "Page UID"}}}),
            json!({"type": "object", "required": ["blocks"], "properties": {"blocks": {"type": "array"}}}),
            "roam.blocks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List blocks on a Roam Research page.".into(),
                common_mistakes: vec!["Blocks are returned in a nested tree structure; child blocks are inside their parent's children array, not flattened at the top level.".into()],
                examples: vec![r#"{"page_uid": "abc123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("roam.pages.get"),
                    CapabilityId::from_static("roam.blocks.create"),
                ],
            },
        ),
        op_info(
            "roam.blocks.create",
            "Create a block on a page",
            json!({"type": "object", "required": ["page_uid", "content"], "properties": {"page_uid": {"type": "string", "description": "Page UID to add block to"}, "content": {"type": "string"}}}),
            json!({"type": "object", "required": ["uid"], "properties": {"uid": {"type": "string"}}}),
            "roam.blocks.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new block on a page.".into(),
                common_mistakes: vec!["Content uses Roam double-bracket syntax for page references ([[Page]]); using Markdown-style links will create plain text instead of links.".into()],
                examples: vec![r#"{"page_uid": "abc123", "content": "TODO: Review architecture"}"#.into()],
                related: vec![CapabilityId::from_static("roam.blocks.list")],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize `operations_info` to JSON for backward-compatible assertions.
    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn config_from_access_token() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, RoamAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.graph_name, DEFAULT_GRAPH_NAME);
    }

    #[test]
    fn config_from_credential_id() {
        let config = RoamConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://localhost:12345",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://localhost:12345");
    }

    #[test]
    fn config_custom_graph_name() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "my-research",
        }))
        .unwrap();
        assert_eq!(config.graph_name, "my-research");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = RoamConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = RoamConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = RoamConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = RoamConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = RoamConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = RoamConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            RoamAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            RoamAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn config_empty_graph_name_uses_default() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "",
        }))
        .unwrap();
        assert_eq!(config.graph_name, DEFAULT_GRAPH_NAME);
    }

    #[test]
    fn config_whitespace_graph_name_uses_default() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "   ",
        }))
        .unwrap();
        assert_eq!(config.graph_name, DEFAULT_GRAPH_NAME);
    }

    #[test]
    fn require_str_present() {
        let input = json!({"title": "Daily Notes"});
        assert_eq!(require_str(&input, "title").unwrap(), "Daily Notes");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"title": 42});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"title": null});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"title": true});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"title": ["a", "b"]});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"title": ""});
        assert_eq!(require_str(&input, "title").unwrap(), "");
    }

    #[test]
    fn operations_info_has_4_operations() {
        let ops = ops_json();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 4);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"roam.pages.list"));
        assert!(ids.contains(&"roam.pages.get"));
        assert!(ids.contains(&"roam.blocks.list"));
        assert!(ids.contains(&"roam.blocks.create"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_write_ops_are_not_safe() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".write") {
                assert_ne!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "write op {} should not be safe",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_pages_list_capability() {
        let ops = ops_json();
        let pages_list = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.pages.list")
            .unwrap();
        assert_eq!(pages_list["capability"], "roam.pages.read");
    }

    #[test]
    fn operations_blocks_create_capability() {
        let ops = ops_json();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.blocks.create")
            .unwrap();
        assert_eq!(bc["capability"], "roam.blocks.write");
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
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
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
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
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
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
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_serializes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("failed"));
    }

    #[test]
    fn connector_default() {
        let c = RoamConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = RoamConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn default_graph_name_value() {
        assert_eq!(DEFAULT_GRAPH_NAME, "default");
    }

    #[test]
    fn config_graph_name_trimmed() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "  my-graph  ",
        }))
        .unwrap();
        assert_eq!(config.graph_name, "my-graph");
    }

    #[test]
    fn config_debug_shows_auth() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok123",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("RoamConfig"));
        assert!(!dbg.contains("tok123"));
    }

    #[test]
    fn config_clone() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "my-graph",
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(cloned.graph_name, "my-graph");
        assert_eq!(cloned.base_url, config.base_url);
    }

    #[test]
    fn require_str_empty_object() {
        let input = json!({});
        assert!(require_str(&input, "page_uid").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"title": {"nested": true}});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"title": 9.876});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn operations_blocks_list_capability() {
        let ops = ops_json();
        let bl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.blocks.list")
            .unwrap();
        assert_eq!(bl["capability"], "roam.blocks.read");
    }

    #[test]
    fn operations_pages_get_capability() {
        let ops = ops_json();
        let pg = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.pages.get")
            .unwrap();
        assert_eq!(pg["capability"], "roam.pages.read");
    }

    #[test]
    fn operations_all_have_summary() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_blocks_create_is_not_strict_idempotent() {
        let ops = ops_json();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.blocks.create")
            .unwrap();
        assert_eq!(bc["idempotency"], "none");
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let healthy = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(healthy, "healthy");
        let degraded = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(degraded, "degraded");
        let unhealthy = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize() {
        let h: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_preserves_check_count() {
        let checks = vec![
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
            DoctorCheck {
                name: "c".into(),
                passed: false,
                message: Some("x".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.checks.len(), 3);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }
}
