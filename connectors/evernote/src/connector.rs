//! FCP `Evernote` Connector implementation.

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
    client::{DEFAULT_BASE_URL, EvernoteAuth, EvernoteClient},
    error::EvernoteError,
};

/// Parsed and validated `Evernote` connector configuration.
#[derive(Debug, Clone)]
struct EvernoteConfig {
    auth: EvernoteAuth,
    base_url: String,
}

impl EvernoteConfig {
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
            (Some(token), None) => EvernoteAuth::BearerToken(token),
            (None, Some(cred_id)) => EvernoteAuth::CredentialId(cred_id),
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

/// FCP `Evernote` Connector.
pub struct EvernoteConnector {
    base: Arc<BaseConnector>,
    config: Option<EvernoteConfig>,
    client: Option<Arc<EvernoteClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl EvernoteConnector {
    /// Create a new `Evernote` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("evernote"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for EvernoteConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl EvernoteConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = EvernoteConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Evernote connector");

        let client = EvernoteClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.evernote",
            "connector_version": "0.1.0",
            "capabilities": [
                "evernote.notebooks.read",
                "evernote.notes.read",
                "evernote.notes.write"
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
            "connector_id": "fcp.evernote",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        Ok(json!({
            "connector_id": "fcp.evernote",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
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
            "evernote.notebooks.list" => self.invoke_notebooks_list(client).await,
            "evernote.notes.list" => self.invoke_notes_list(client, &input).await,
            "evernote.notes.get" => self.invoke_notes_get(client, &input).await,
            "evernote.notes.create" => self.invoke_notes_create(client, &input).await,
            "evernote.notes.delete" => self.invoke_notes_delete(client, &input).await,
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
        info!("Evernote connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_notebooks_list(
        &self,
        client: &EvernoteClient,
    ) -> Result<serde_json::Value, EvernoteError> {
        let data = client.list_notebooks().await?;
        Ok(data)
    }

    async fn invoke_notes_list(
        &self,
        client: &EvernoteClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, EvernoteError> {
        let notebook_id = require_str(input, "notebook_id")?;
        let data = client.list_notes(notebook_id).await?;
        Ok(data)
    }

    async fn invoke_notes_get(
        &self,
        client: &EvernoteClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, EvernoteError> {
        let note_id = require_str(input, "note_id")?;
        let data = client.get_note(note_id).await?;
        Ok(data)
    }

    async fn invoke_notes_create(
        &self,
        client: &EvernoteClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, EvernoteError> {
        let _ = require_str(input, "notebook_id")?;
        let _ = require_str(input, "title")?;
        let data = client.create_note(input).await?;
        Ok(data)
    }

    async fn invoke_notes_delete(
        &self,
        client: &EvernoteClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, EvernoteError> {
        let note_id = require_str(input, "note_id")?;
        client.delete_note(note_id).await?;
        Ok(json!({ "deleted": true }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, EvernoteError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| EvernoteError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build typed operations info for introspection.
fn typed_operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("evernote.notebooks.list"),
            summary: "List all notebooks for the authenticated user".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: json!({"type": "object", "properties": {"notebooks": {"type": "array"}}}),
            capability: CapabilityId::from_static("evernote.notebooks.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover available notebooks before listing notes".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("evernote.notebooks.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("evernote.notes.list"),
            summary: "List notes in a notebook".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"notebook_id": {"type": "string"}}, "required": ["notebook_id"]}),
            output_schema: json!({"type": "object", "properties": {"notes": {"type": "array"}}}),
            capability: CapabilityId::from_static("evernote.notes.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to list notes in a specific notebook".into(),
                common_mistakes: vec!["Forgetting to provide notebook_id".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("evernote.notes.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("evernote.notes.get"),
            summary: "Retrieve a note by ID".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"note_id": {"type": "string"}}, "required": ["note_id"]}),
            output_schema: json!({"type": "object", "properties": {"note": {"type": "object"}}}),
            capability: CapabilityId::from_static("evernote.notes.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to retrieve the full content of a specific note".into(),
                common_mistakes: vec!["Using an invalid note_id".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("evernote.notes.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("evernote.notes.create"),
            summary: "Create a new note in a notebook".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"notebook_id": {"type": "string"}, "title": {"type": "string"}, "content": {"type": "string"}}, "required": ["notebook_id", "title"]}),
            output_schema: json!({"type": "object", "properties": {"note": {"type": "object"}}}),
            capability: CapabilityId::from_static("evernote.notes.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use to create a new note with title and content in a notebook".into(),
                common_mistakes: vec!["Not providing both notebook_id and title".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("evernote.notes.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("evernote.notes.delete"),
            summary: "Delete a note".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"note_id": {"type": "string"}}, "required": ["note_id"]}),
            output_schema: json!({"type": "object", "properties": {"deleted": {"type": "boolean"}}}),
            capability: CapabilityId::from_static("evernote.notes.write"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to permanently delete a note — this action cannot be undone"
                    .into(),
                common_mistakes: vec!["Deleting without confirming the correct note_id".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("evernote.notes.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

/// Build the operations info for introspection (JSON format for simulate).
fn operations_info() -> serde_json::Value {
    serde_json::to_value(typed_operations_info()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = EvernoteConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, EvernoteAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = EvernoteConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = EvernoteConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://sandbox.evernote.com/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://sandbox.evernote.com/v1");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = EvernoteConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = EvernoteConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = EvernoteConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = EvernoteConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = EvernoteConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = EvernoteConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config =
            EvernoteConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            EvernoteAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            EvernoteAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn config_rejects_null_access_token() {
        let result = EvernoteConfig::from_params(&json!({ "access_token": null }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_boolean_credential_id() {
        let result = EvernoteConfig::from_params(&json!({ "credential_id": true }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"notebook_id": "nb-123"});
        assert_eq!(require_str(&input, "notebook_id").unwrap(), "nb-123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "notebook_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"notebook_id": 42});
        assert!(require_str(&input, "notebook_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"notebook_id": null});
        assert!(require_str(&input, "notebook_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"notebook_id": false});
        assert!(require_str(&input, "notebook_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"notebook_id": ["a"]});
        assert!(require_str(&input, "notebook_id").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 5);
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
        assert!(ids.contains(&"evernote.notebooks.list"));
        assert!(ids.contains(&"evernote.notes.list"));
        assert!(ids.contains(&"evernote.notes.get"));
        assert!(ids.contains(&"evernote.notes.create"));
        assert!(ids.contains(&"evernote.notes.delete"));
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
    fn operations_notebooks_list_capability() {
        let ops = operations_info();
        let nb_list = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "evernote.notebooks.list")
            .unwrap();
        assert_eq!(nb_list["capability"], "evernote.notebooks.read");
    }

    #[test]
    fn operations_notes_create_capability() {
        let ops = operations_info();
        let nc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "evernote.notes.create")
            .unwrap();
        assert_eq!(nc["capability"], "evernote.notes.write");
    }

    #[test]
    fn operations_notes_delete_is_dangerous() {
        let ops = operations_info();
        let nd = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "evernote.notes.delete")
            .unwrap();
        assert_eq!(nd["safety_tier"], "dangerous");
        assert_eq!(nd["risk_level"], "high");
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
    fn doctor_check_skip_none_message() {
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
    fn doctor_check_include_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("oops".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "oops");
    }

    #[test]
    fn connector_default() {
        let c = EvernoteConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = EvernoteConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip_healthy() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_roundtrip_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_serde_roundtrip_unhealthy() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg.contains("Degraded"));
    }

    #[test]
    fn doctor_result_deserializes() {
        let v = json!({
            "status": "unhealthy",
            "checks": [
                {"name": "config", "passed": false, "message": "fail", "critical": true}
            ]
        });
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn doctor_check_deserializes() {
        let v = json!({"name": "test", "passed": true, "critical": false});
        let c: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c.name, "test");
        assert!(c.passed);
        assert!(c.message.is_none());
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = DoctorCheck::clone(&c);
        assert_eq!(cloned.name, "cfg");
        assert_eq!(cloned.message, Some("ok".into()));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = DoctorResult::clone(&r);
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn config_rejects_boolean_access_token() {
        let result = EvernoteConfig::from_params(&json!({ "access_token": true }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"notebook_id": ""});
        assert_eq!(require_str(&input, "notebook_id").unwrap(), "");
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"notebook_id": {"nested": true}});
        assert!(require_str(&input, "notebook_id").is_err());
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_write_ops_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
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
    fn config_default_base_url_used_when_missing() {
        let config = EvernoteConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn require_str_with_float_value() {
        let input = json!({"notebook_id": 1.23});
        assert!(require_str(&input, "notebook_id").is_err());
    }

    #[test]
    fn operations_all_capabilities_prefixed_with_evernote() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("evernote."),
                "capability {cap} should be prefixed with evernote."
            );
        }
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"), "got: {dbg}");
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DoctorCheck"), "got: {dbg}");
        assert!(dbg.contains("test_check"), "got: {dbg}");
    }

    #[test]
    fn doctor_status_copy_eq() {
        let s1 = DoctorStatus::Healthy;
        let s2 = s1;
        assert_eq!(s1, s2);
        let s3 = DoctorStatus::Unhealthy;
        assert_ne!(s1, s3);
    }

    #[test]
    fn config_debug_and_clone() {
        let config = EvernoteConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("EvernoteConfig"), "got: {dbg}");
        let cloned = config.clone();
        assert_eq!(cloned.base_url, config.base_url);
    }
}
