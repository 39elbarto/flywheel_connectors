//! FCP `1Password` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, StepId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};


use crate::{
    client::{DEFAULT_BASE_URL, OnePasswordAuth, OnePasswordClient},
    error::OnePasswordError,
};

/// Parsed and validated `1Password` connector configuration.
#[derive(Debug, Clone)]
struct OnePasswordConfig {
    auth: OnePasswordAuth,
    base_url: String,
}

impl OnePasswordConfig {
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
            (Some(token), None) => OnePasswordAuth::BearerToken(token),
            (None, Some(cred_id)) => OnePasswordAuth::CredentialId(cred_id),
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

/// FCP `1Password` Connector.
pub struct OnePasswordConnector {
    base: Arc<BaseConnector>,
    config: Option<OnePasswordConfig>,
    client: Option<Arc<OnePasswordClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl OnePasswordConnector {
    /// Create a new `1Password` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("1password"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for OnePasswordConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl OnePasswordConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = OnePasswordConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring 1Password connector");

        let client = OnePasswordClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.1password",
            "connector_version": "0.1.0",
            "capabilities": [
                "1password.vaults.read",
                "1password.items.read",
                "1password.items.write"
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

    /// Return provisioning readiness information.
    #[must_use]
    pub fn provisioning_readiness(&self) -> serde_json::Value {
        let (auth_mode, token_configured, credential_id_configured) = match &self.config {
            Some(cfg) => match &cfg.auth {
                OnePasswordAuth::BearerToken(_) => ("bearer_token", true, false),
                OnePasswordAuth::CredentialId(_) => ("credential_id", false, true),
            },
            None => ("unconfigured", false, false),
        };

        let base_url = self
            .config
            .as_ref()
            .map_or(DEFAULT_BASE_URL, |c| &c.base_url);

        json!({
            "auth_mode": auth_mode,
            "token_configured": token_configured,
            "credential_id_configured": credential_id_configured,
            "base_url": base_url,
        })
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.1password",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ok" } else { "degraded" },
            "provisioning": self.provisioning_readiness(),
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.1password",
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
            "1password.vaults.list" => self.invoke_vaults_list(client).await,
            "1password.items.list" => self.invoke_items_list(client, &input).await,
            "1password.items.get" => self.invoke_items_get(client, &input).await,
            "1password.items.create" => self.invoke_items_create(client, &input).await,
            "1password.items.delete" => self.invoke_items_delete(client, &input).await,
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
        info!("1Password connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --------------------------------------------------

    async fn invoke_vaults_list(
        &self,
        client: &OnePasswordClient,
    ) -> Result<serde_json::Value, OnePasswordError> {
        let data = client.list_vaults().await?;
        Ok(json!({ "vaults": data }))
    }

    async fn invoke_items_list(
        &self,
        client: &OnePasswordClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, OnePasswordError> {
        let vault_id = require_str(input, "vault_id")?;
        let data = client.list_items(vault_id).await?;
        Ok(json!({ "items": data }))
    }

    async fn invoke_items_get(
        &self,
        client: &OnePasswordClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, OnePasswordError> {
        let vault_id = require_str(input, "vault_id")?;
        let item_id = require_str(input, "item_id")?;
        let data = client.get_item(vault_id, item_id).await?;
        Ok(json!({ "item": data }))
    }

    async fn invoke_items_create(
        &self,
        client: &OnePasswordClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, OnePasswordError> {
        let vault_id = require_str(input, "vault_id")?;
        let _ = require_str(input, "category")?;
        let _ = require_str(input, "title")?;

        let body = json!({
            "vault": { "id": vault_id },
            "category": input["category"],
            "title": input["title"],
            "fields": input.get("fields").cloned().unwrap_or_else(|| json!([])),
            "tags": input.get("tags").cloned().unwrap_or_else(|| json!([])),
        });

        let data = client.create_item(vault_id, &body).await?;
        Ok(data)
    }

    async fn invoke_items_delete(
        &self,
        client: &OnePasswordClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, OnePasswordError> {
        let vault_id = require_str(input, "vault_id")?;
        let item_id = require_str(input, "item_id")?;
        client.delete_item(vault_id, item_id).await?;
        Ok(json!({ "deleted": true }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, OnePasswordError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| OnePasswordError::Api {
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

/// Build the provisioning recipe for the `1Password` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("1password-setup"),
        "1",
        "Provision 1Password Connect Server access for the FCP connector",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_auth_mode"),
        ProvisioningStepType::PromptUser {
            message:
                "Choose authentication mode: (1) Service account token or (2) Credential injection"
                    .into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("prompt_access_token"),
            ProvisioningStepType::PromptSecret {
                message: "Enter your 1Password Connect Server access token".into(),
            },
        )
        .depends_on(StepId::new("prompt_auth_mode")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_access_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("prompt_access_token"),
                scope: "connector:fcp.1password".into(),
            },
        )
        .depends_on(StepId::new("prompt_access_token")),
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_base_url"),
        ProvisioningStepType::PromptUser {
            message: format!(
                "Enter the 1Password Connect Server URL (default: {DEFAULT_BASE_URL})"
            ),
        },
    ))
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "1password.vaults.list",
            "List vaults accessible to the service account",
            json!({"type": "object", "required": []}),
            json!({"type": "object", "required": ["vaults"], "properties": {"vaults": {"type": "array"}}}),
            "1password.vaults.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List available vaults.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("1password.items.list")],
            },
        ),
        op_info(
            "1password.items.list",
            "List items in a vault",
            json!({"type": "object", "required": ["vault_id"], "properties": {"vault_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["items"], "properties": {"items": {"type": "array"}}}),
            "1password.items.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List items in a 1Password vault (without revealing secrets).".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"vault_id": "abc123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("1password.vaults.list"),
                    CapabilityId::from_static("1password.items.get"),
                ],
            },
        ),
        op_info(
            "1password.items.get",
            "Get a single item with field values",
            json!({"type": "object", "required": ["vault_id", "item_id"], "properties": {"vault_id": {"type": "string"}, "item_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["item"], "properties": {"item": {"type": "object"}}}),
            "1password.items.read",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a specific item including secret field values. Use with caution.".into(),
                common_mistakes: vec![
                    "Logging or caching secret values \u{2014} treat all field values as sensitive.".into(),
                ],
                examples: vec![r#"{"vault_id": "abc123", "item_id": "def456"}"#.into()],
                related: vec![CapabilityId::from_static("1password.items.list")],
            },
        ),
        op_info(
            "1password.items.create",
            "Create a new item in a vault",
            json!({"type": "object", "required": ["vault_id", "category", "title"], "properties": {"vault_id": {"type": "string"}, "category": {"type": "string", "description": "LOGIN, PASSWORD, SECURE_NOTE, API_CREDENTIAL, etc."}, "title": {"type": "string"}, "fields": {"type": "array"}}}),
            json!({"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}),
            "1password.items.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new secret item in 1Password.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"vault_id": "abc123", "category": "API_CREDENTIAL", "title": "Stripe Key", "fields": [{"label": "api_key", "value": "sk_live_..."}]}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("1password.items.list"),
                    CapabilityId::from_static("1password.items.delete"),
                ],
            },
        ),
        op_info(
            "1password.items.delete",
            "Delete an item from a vault",
            json!({"type": "object", "required": ["vault_id", "item_id"], "properties": {"vault_id": {"type": "string"}, "item_id": {"type": "string"}}}),
            json!({"type": "object"}),
            "1password.items.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Delete a secret item. Cannot be undone.".into(),
                common_mistakes: vec![
                    "Deleting items that other services depend on for credentials.".into(),
                ],
                examples: vec![r#"{"vault_id": "abc123", "item_id": "def456"}"#.into()],
                related: vec![CapabilityId::from_static("1password.items.get")],
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
        let config = OnePasswordConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, OnePasswordAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = OnePasswordConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = OnePasswordConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://connect.example.com",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://connect.example.com");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = OnePasswordConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = OnePasswordConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = OnePasswordConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = OnePasswordConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = OnePasswordConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = OnePasswordConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config =
            OnePasswordConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            OnePasswordAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            OnePasswordAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"vault_id": "v123"});
        assert_eq!(require_str(&input, "vault_id").unwrap(), "v123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"vault_id": 42});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"vault_id": null});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"vault_id": true});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"vault_id": ["a", "b"]});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_ref().is_empty(), "missing id");
            assert!(!op.summary.is_empty(), "missing summary");
            assert!(!op.capability.as_ref().is_empty(), "missing capability");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.risk_level).unwrap();
            let rl = v.as_str().unwrap();
            assert!(
                ["low", "medium", "high", "critical"].contains(&rl),
                "invalid risk_level: {rl}"
            );
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.safety_tier).unwrap();
            let st = v.as_str().unwrap();
            assert!(
                ["safe", "risky", "dangerous"].contains(&st),
                "invalid safety_tier: {st}"
            );
        }
    }

    #[test]
    fn read_operations_are_safe_or_risky() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".read") {
                assert!(
                    op.safety_tier == SafetyTier::Safe || op.safety_tier == SafetyTier::Risky,
                    "read op {} has unexpected safety_tier: {:?}",
                    op.id.as_ref(),
                    op.safety_tier
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"1password.vaults.list"));
        assert!(ids.contains(&"1password.items.list"));
        assert!(ids.contains(&"1password.items.get"));
        assert!(ids.contains(&"1password.items.create"));
        assert!(ids.contains(&"1password.items.delete"));
    }

    #[test]
    fn operations_vaults_list_is_safe() {
        let ops = operations_info();
        let vaults_list = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.vaults.list")
            .unwrap();
        assert_eq!(vaults_list.safety_tier, SafetyTier::Safe);
        assert_eq!(vaults_list.risk_level, RiskLevel::Low);
    }

    #[test]
    fn operations_items_list_is_safe() {
        let ops = operations_info();
        let items_list = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.items.list")
            .unwrap();
        assert_eq!(items_list.safety_tier, SafetyTier::Safe);
        assert_eq!(items_list.risk_level, RiskLevel::Low);
    }

    #[test]
    fn operations_items_get_is_risky() {
        let ops = operations_info();
        let items_get = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.items.get")
            .unwrap();
        assert_eq!(items_get.safety_tier, SafetyTier::Risky);
        assert_eq!(items_get.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn operations_items_create_is_risky() {
        let ops = operations_info();
        let items_create = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.items.create")
            .unwrap();
        assert_eq!(items_create.safety_tier, SafetyTier::Risky);
        assert_eq!(items_create.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn operations_items_delete_is_dangerous() {
        let ops = operations_info();
        let items_delete = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.items.delete")
            .unwrap();
        assert_eq!(items_delete.safety_tier, SafetyTier::Dangerous);
        assert_eq!(items_delete.risk_level, RiskLevel::High);
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.idempotency).unwrap();
            assert!(
                v.is_string(),
                "op {} idempotency should serialize",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_write_ops_have_correct_capability() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            let cap = op.capability.as_ref();
            if id.contains("create") || id.contains("delete") {
                #[allow(clippy::case_sensitive_file_extension_comparisons)]
                let is_write = cap.ends_with(".write");
                assert!(is_write, "write op {id} should have .write capability");
            }
        }
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
    fn connector_default() {
        let c = OnePasswordConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = OnePasswordConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn operations_items_create_has_none_idempotency() {
        let ops = operations_info();
        let create = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.items.create")
            .unwrap();
        assert_eq!(create.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn operations_items_delete_has_strict_idempotency() {
        let ops = operations_info();
        let delete = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.items.delete")
            .unwrap();
        assert_eq!(delete.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn operations_vaults_list_has_correct_capability() {
        let ops = operations_info();
        let vl = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.vaults.list")
            .unwrap();
        assert_eq!(vl.capability.as_ref(), "1password.vaults.read");
    }

    #[test]
    fn operations_items_get_has_correct_capability() {
        let ops = operations_info();
        let ig = ops
            .iter()
            .find(|o| o.id.as_ref() == "1password.items.get")
            .unwrap();
        assert_eq!(ig.capability.as_ref(), "1password.items.read");
    }

    #[test]
    fn operations_all_have_summary() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {} has empty summary",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail 1".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail 2".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn doctor_check_skip_serializing_none_message() {
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
    fn doctor_check_serializes_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("warning".into()),
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "warning");
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    #[test]
    fn doctor_status_deserializes() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        let input = json!({"vault_id": ""});
        assert_eq!(require_str(&input, "vault_id").unwrap(), "");
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"vault_id": {"nested": "val"}});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"vault_id": 9.876});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn require_str_integer_value() {
        let input = json!({"vault_id": 42});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn require_str_nested_deep_object() {
        let input = json!({"vault_id": {"deep": {"nested": "val"}}});
        assert!(require_str(&input, "vault_id").is_err());
    }

    #[test]
    fn operations_all_have_capabilities() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                !cap.is_empty(),
                "op {} has empty capability",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_ids_all_start_with_1password() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            assert!(
                id.starts_with("1password."),
                "op {id} should start with 1password."
            );
        }
    }

    #[test]
    fn operations_serializes_to_json() {
        let json = ops_json();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 5);
        for op in arr {
            assert!(op.get("id").is_some(), "missing id in JSON");
            assert!(op.get("summary").is_some(), "missing summary in JSON");
        }
    }

    #[test]
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_clone_preserves_critical() {
        let c = DoctorCheck {
            name: "test_check".into(),
            passed: false,
            message: Some("failure reason".into()),
            critical: true,
        };
        let cloned = c.clone();
        assert_eq!(c.name, cloned.name);
        assert_eq!(c.passed, cloned.passed);
        assert_eq!(c.message, cloned.message);
        assert!(cloned.critical);
    }

    #[test]
    fn doctor_status_debug_all_variants() {
        assert_eq!(format!("{:?}", DoctorStatus::Healthy), "Healthy");
        assert_eq!(format!("{:?}", DoctorStatus::Degraded), "Degraded");
        assert_eq!(format!("{:?}", DoctorStatus::Unhealthy), "Unhealthy");
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let status = DoctorStatus::Degraded;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn doctor_check_debug_format() {
        let c = DoctorCheck {
            name: "connectivity".into(),
            passed: false,
            message: Some("unreachable".into()),
            critical: true,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("connectivity"));
        assert!(dbg.contains("unreachable"));
    }

    // -- Provisioning tests --

    #[test]
    fn provisioning_recipe_has_expected_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps.len(), 4);
        assert_eq!(recipe.id.as_str(), "1password-setup");
        assert_eq!(recipe.version, "1");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        let ids: Vec<&str> = recipe.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            &[
                "prompt_auth_mode",
                "prompt_access_token",
                "store_access_token",
                "prompt_base_url",
            ]
        );

        // prompt_auth_mode has no dependencies
        assert!(recipe.steps[0].depends_on.is_empty());

        // prompt_access_token depends on prompt_auth_mode
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "prompt_auth_mode");

        // store_access_token depends on prompt_access_token
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(
            recipe.steps[2].depends_on[0].as_str(),
            "prompt_access_token"
        );

        // prompt_base_url has no dependencies
        assert!(recipe.steps[3].depends_on.is_empty());
    }

    #[test]
    fn provisioning_recipe_store_secret_scope() {
        let recipe = provisioning_recipe();
        let store_step = recipe
            .steps
            .iter()
            .find(|s| s.id.as_str() == "store_access_token")
            .expect("store_access_token step not found");

        match &store_step.kind {
            ProvisioningStepType::StoreSecret {
                scope,
                key,
                value_from,
            } => {
                assert_eq!(scope, "connector:fcp.1password");
                assert_eq!(key, "access_token");
                assert_eq!(value_from.as_str(), "prompt_access_token");
            }
            other => panic!("expected StoreSecret, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_readiness_unconfigured() {
        let c = OnePasswordConnector::new();
        let readiness = c.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "unconfigured");
        assert_eq!(readiness["token_configured"], false);
        assert_eq!(readiness["credential_id_configured"], false);
        assert_eq!(readiness["base_url"], DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_bearer_token() {
        let mut c = OnePasswordConnector::new();
        c.config = Some(OnePasswordConfig {
            auth: OnePasswordAuth::BearerToken("test-token".into()),
            base_url: "https://connect.example.com".into(),
        });
        let readiness = c.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "bearer_token");
        assert_eq!(readiness["token_configured"], true);
        assert_eq!(readiness["credential_id_configured"], false);
        assert_eq!(readiness["base_url"], "https://connect.example.com");
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let mut c = OnePasswordConnector::new();
        c.config = Some(OnePasswordConfig {
            auth: OnePasswordAuth::CredentialId(
                CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            ),
            base_url: DEFAULT_BASE_URL.into(),
        });
        let readiness = c.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "credential_id");
        assert_eq!(readiness["token_configured"], false);
        assert_eq!(readiness["credential_id_configured"], true);
        assert_eq!(readiness["base_url"], DEFAULT_BASE_URL);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_includes_provisioning() {
        let c = OnePasswordConnector::new();
        let result = c.handle_self_check().await.unwrap();
        assert!(result.get("provisioning").is_some());
        let prov = &result["provisioning"];
        assert_eq!(prov["auth_mode"], "unconfigured");
        assert_eq!(prov["token_configured"], false);
        assert_eq!(prov["credential_id_configured"], false);
    }
}
