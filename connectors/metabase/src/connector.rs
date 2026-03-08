//! FCP `Metabase` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{MetabaseAuth, MetabaseClient},
    error::MetabaseError,
};

/// Parsed and validated `Metabase` connector configuration.
#[derive(Debug, Clone)]
struct MetabaseConfig {
    auth: MetabaseAuth,
    base_url: String,
}

impl MetabaseConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let session_token = params
            .get("session_token")
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

        let auth = match (session_token, credential_id) {
            (Some(key), None) => MetabaseAuth::SessionToken(key),
            (None, Some(cred_id)) => MetabaseAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of session_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing session_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required base_url (Metabase is self-hosted)".into(),
            })?;

        Ok(Self { auth, base_url })
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

/// FCP `Metabase` Connector.
pub struct MetabaseConnector {
    base: Arc<BaseConnector>,
    config: Option<MetabaseConfig>,
    client: Option<Arc<MetabaseClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MetabaseConnector {
    /// Create a new `Metabase` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("metabase"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for MetabaseConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetabaseConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MetabaseConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Metabase connector");

        let client = MetabaseClient::new(config.auth.clone(), &config.base_url)
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
            "connector_id": "fcp.metabase",
            "connector_version": "0.1.0",
            "capabilities": [
                "metabase.dashboards.read",
                "metabase.questions.read"
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
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.metabase",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("metabase.dashboards.list"),
                    summary: "List dashboards".into(),
                    input_schema: json!({"type": "object", "required": []}),
                    output_schema: json!({
                        "type": "object",
                        "required": ["dashboards"],
                        "properties": {"dashboards": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("metabase.dashboards.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List all dashboards in Metabase.".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("metabase.questions.list")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("metabase.questions.list"),
                    summary: "List saved questions (cards)".into(),
                    input_schema: json!({"type": "object", "required": []}),
                    output_schema: json!({
                        "type": "object",
                        "required": ["questions"],
                        "properties": {"questions": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("metabase.questions.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List saved questions (cards) in Metabase.".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![
                            CapabilityId::from_static("metabase.questions.run"),
                            CapabilityId::from_static("metabase.dashboards.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("metabase.questions.run"),
                    summary: "Run a saved question and get results".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["card_id"],
                        "properties": {
                            "card_id": {"type": "string", "description": "Card (question) ID to run"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["data"],
                        "properties": {"data": {"type": "object"}}
                    }),
                    capability: CapabilityId::from_static("metabase.questions.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Run a saved Metabase question and get results.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"card_id": "42"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("metabase.questions.list"),
                            CapabilityId::from_static("metabase.dashboards.list"),
                        ],
                    },
                },
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

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "metabase.dashboards.list" => self.invoke_dashboards_list(client).await,
            "metabase.questions.list" => self.invoke_questions_list(client).await,
            "metabase.questions.run" => self.invoke_questions_run(client, &input).await,
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

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });

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
        info!("Metabase connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_dashboards_list(
        &self,
        client: &MetabaseClient,
    ) -> Result<serde_json::Value, MetabaseError> {
        let resp = client.list_dashboards().await?;
        // Metabase GET /dashboard returns a JSON array directly.
        let dashboards = if resp.is_array() {
            resp
        } else {
            resp.get("dashboards").cloned().unwrap_or(json!([]))
        };
        Ok(json!({ "dashboards": dashboards }))
    }

    async fn invoke_questions_list(
        &self,
        client: &MetabaseClient,
    ) -> Result<serde_json::Value, MetabaseError> {
        let resp = client.list_cards().await?;
        // Metabase GET /card returns a JSON array directly.
        let questions = if resp.is_array() {
            resp
        } else {
            resp.get("questions").cloned().unwrap_or(json!([]))
        };
        Ok(json!({ "questions": questions }))
    }

    async fn invoke_questions_run(
        &self,
        client: &MetabaseClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MetabaseError> {
        let card_id = require_str(input, "card_id")?;
        let resp = client.run_card(card_id).await?;
        let data = resp.get("data").cloned().unwrap_or(json!({}));
        let status = resp
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        Ok(json!({ "data": data, "status": status }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, MetabaseError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MetabaseError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "metabase.dashboards.list",
            "summary": "List dashboards",
            "capability": "metabase.dashboards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "metabase.questions.list",
            "summary": "List saved questions (cards)",
            "capability": "metabase.questions.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "metabase.questions.run",
            "summary": "Run a saved question and get results",
            "capability": "metabase.questions.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_session_token() {
        let config = MetabaseConfig::from_params(&json!({
            "session_token": "tok123",
            "base_url": "http://localhost:3000/api",
        }))
        .unwrap();
        assert!(matches!(config.auth, MetabaseAuth::SessionToken(_)));
        assert_eq!(config.base_url, "http://localhost:3000/api");
    }

    #[test]
    fn config_from_credential_id() {
        let config = MetabaseConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "http://localhost:3000/api",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
            "base_url": "https://metabase.example.com/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://metabase.example.com/api");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = MetabaseConfig::from_params(&json!({
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_session_token() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": "",
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_session_token() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": "   ",
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_base_url() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = MetabaseConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = MetabaseConfig::from_params(&json!({
            "credential_id": 12345,
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = MetabaseConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_session_token() {
        let config = MetabaseConfig::from_params(&json!({
            "session_token": "  tok_test  ",
            "base_url": "http://localhost:3000/api",
        }))
        .unwrap();
        match &config.auth {
            MetabaseAuth::SessionToken(t) => assert_eq!(t, "tok_test"),
            MetabaseAuth::CredentialId(_) => panic!("expected SessionToken"),
        }
    }

    #[test]
    fn config_rejects_null_session_token() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": null,
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"card_id": "42"});
        assert_eq!(require_str(&input, "card_id").unwrap(), "42");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"card_id": 42});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"card_id": null});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"card_id": true});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"card_id": ["42"]});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn operations_info_has_3_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
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
        let ops = operations_info();
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
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
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
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"metabase.dashboards.list"));
        assert!(ids.contains(&"metabase.questions.list"));
        assert!(ids.contains(&"metabase.questions.run"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_all_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(op["safety_tier"], "safe");
            assert_eq!(op["risk_level"], "low");
        }
    }

    #[test]
    fn operations_dashboards_list_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "metabase.dashboards.list")
            .unwrap();
        assert_eq!(op["capability"], "metabase.dashboards.read");
    }

    #[test]
    fn operations_questions_list_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "metabase.questions.list")
            .unwrap();
        assert_eq!(op["capability"], "metabase.questions.read");
    }

    #[test]
    fn operations_questions_run_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "metabase.questions.run")
            .unwrap();
        assert_eq!(op["capability"], "metabase.questions.read");
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
                message: Some("fail a".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail b".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn connector_default() {
        let c = MetabaseConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = MetabaseConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn config_rejects_boolean_session_token() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": true,
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_array_base_url() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
            "base_url": ["http://localhost:3000/api"],
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_object_session_token() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": {"value": "tok"},
            "base_url": "http://localhost:3000/api",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_numeric_base_url() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
            "base_url": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_base_url() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
            "base_url": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_boolean_base_url() {
        let result = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
            "base_url": true,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_debug_format() {
        let config = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
            "base_url": "http://localhost:3000/api",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MetabaseConfig"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn config_clone() {
        let config = MetabaseConfig::from_params(&json!({
            "session_token": "tok",
            "base_url": "http://localhost:3000/api",
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(cloned.base_url, "http://localhost:3000/api");
    }

    #[test]
    fn doctor_check_serializes_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("error".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "error");
    }

    #[test]
    fn doctor_check_skips_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(v.get("message").is_none());
    }

    #[test]
    fn doctor_status_serialize_lowercase() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize_lowercase() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn require_str_with_float_value() {
        let input = json!({"card_id": 1.23});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"card_id": {"nested": "value"}});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("metabase."),
                "capability {cap} should start with metabase."
            );
        }
    }

    #[test]
    fn operations_all_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    fn doctor_status_copy_eq() {
        let a = DoctorStatus::Degraded;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "check".into(),
            passed: false,
            message: Some("msg".into()),
            critical: true,
        };
        let cloned = c.clone();
        assert_eq!(cloned.name, "check");
        assert_eq!(cloned.message, Some("msg".into()));
    }
}
