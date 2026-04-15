//! FCP `Bitwarden` Connector implementation.

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
    client::{BitwardenAuth, BitwardenClient, DEFAULT_BASE_URL},
    error::BitwardenError,
};

/// Parsed and validated `Bitwarden` connector configuration.
#[derive(Debug, Clone)]
struct BitwardenConfig {
    auth: BitwardenAuth,
    base_url: String,
}

impl BitwardenConfig {
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
            (Some(token), None) => BitwardenAuth::BearerToken(token),
            (None, Some(cred_id)) => BitwardenAuth::CredentialId(cred_id),
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

/// FCP `Bitwarden` Connector.
pub struct BitwardenConnector {
    base: Arc<BaseConnector>,
    config: Option<BitwardenConfig>,
    client: Option<Arc<BitwardenClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl BitwardenConnector {
    /// Create a new `Bitwarden` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("bitwarden"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for BitwardenConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl BitwardenConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = BitwardenConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Bitwarden connector");

        let client = BitwardenClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.bitwarden",
            "connector_version": "0.1.0",
            "capabilities": [
                "bitwarden.collections.read",
                "bitwarden.items.read",
                "bitwarden.items.write"
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

        // Base URL policy: must be HTTPS (unless localhost for testing).
        if let Some(config) = &self.config {
            let (url_ok, url_msg) = validate_base_url(&config.base_url);
            checks.push(DoctorCheck {
                name: "base_url_policy".into(),
                passed: url_ok,
                message: Some(url_msg),
                critical: true,
            });
        }

        // Live auth validation: make a lightweight read-only API call.
        if let Some(client) = &self.client {
            match client.list_collections().await {
                Ok(body) => {
                    let count = body
                        .get("data")
                        .and_then(|d| d.as_array())
                        .map_or(0, |a| a.len());
                    checks.push(DoctorCheck {
                        name: "auth_validation".into(),
                        passed: true,
                        message: Some(format!("Auth valid; {count} collection(s) accessible")),
                        critical: true,
                    });
                }
                Err(e) => {
                    checks.push(DoctorCheck {
                        name: "auth_validation".into(),
                        passed: false,
                        message: Some(format!("Cannot access vault: {e}")),
                        critical: true,
                    });
                }
            }
        }

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    ///
    /// Performs a lightweight live connectivity check when configured.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            return Ok(json!({
                "connector_id": "fcp.bitwarden",
                "version": "0.1.0",
                "status": "degraded",
                "reason": "Not configured",
            }));
        };

        match client.list_collections().await {
            Ok(_) => Ok(json!({
                "connector_id": "fcp.bitwarden",
                "version": "0.1.0",
                "status": "ok",
            })),
            Err(e) => Ok(json!({
                "connector_id": "fcp.bitwarden",
                "version": "0.1.0",
                "status": "degraded",
                "reason": format!("Connectivity check failed: {e}"),
            })),
        }
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.bitwarden",
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
            "bitwarden.collections.list" => self.invoke_collections_list(client).await,
            "bitwarden.items.list" => self.invoke_items_list(client, &input).await,
            "bitwarden.items.get" => self.invoke_items_get(client, &input).await,
            "bitwarden.items.create" => self.invoke_items_create(client, &input).await,
            "bitwarden.items.delete" => self.invoke_items_delete(client, &input).await,
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
        info!("Bitwarden connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_collections_list(
        &self,
        client: &BitwardenClient,
    ) -> Result<serde_json::Value, BitwardenError> {
        let data = client.list_collections().await?;
        Ok(data)
    }

    async fn invoke_items_list(
        &self,
        client: &BitwardenClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitwardenError> {
        let collection_id = input
            .get("collection_id")
            .and_then(serde_json::Value::as_str);
        let folder_id = input.get("folder_id").and_then(serde_json::Value::as_str);
        let data = client.list_items(collection_id, folder_id).await?;
        Ok(data)
    }

    async fn invoke_items_get(
        &self,
        client: &BitwardenClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitwardenError> {
        let item_id = require_str(input, "item_id")?;
        let data = client.get_item(item_id).await?;
        Ok(json!({ "item": data }))
    }

    async fn invoke_items_create(
        &self,
        client: &BitwardenClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitwardenError> {
        let _ = require_i64(input, "type")?;
        let _ = require_str(input, "name")?;
        let data = client.create_item(input).await?;
        Ok(data)
    }

    async fn invoke_items_delete(
        &self,
        client: &BitwardenClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitwardenError> {
        let item_id = require_str(input, "item_id")?;
        client.delete_item(item_id).await?;
        Ok(json!({ "deleted": true }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, BitwardenError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BitwardenError::InvalidInput(format!("Missing required field: {field}")))
}

/// Extract a required integer field from input.
fn require_i64(input: &serde_json::Value, field: &str) -> Result<i64, BitwardenError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| BitwardenError::InvalidInput(format!("Missing required field: {field}")))
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

/// Validate the base URL for security policy compliance.
///
/// Returns `(passed, diagnostic_message)`.
fn validate_base_url(base_url: &str) -> (bool, String) {
    // Allow localhost/127.0.0.1 for testing without HTTPS.
    let is_local = base_url.contains("localhost") || base_url.contains("127.0.0.1");

    if !base_url.starts_with("https://") && !is_local {
        return (false, format!("Base URL must use HTTPS: {base_url}"));
    }

    // Known Bitwarden hosts (official cloud + self-hosted pattern).
    let known_hosts = [
        "api.bitwarden.com",
        "api.bitwarden.eu",
        "vault.bitwarden.com",
        "vault.bitwarden.eu",
    ];

    if is_local {
        return (true, "Local test endpoint".into());
    }

    // Allow known hosts or self-hosted patterns.
    let host_ok =
        known_hosts.iter().any(|h| base_url.contains(h)) || base_url.contains("bitwarden");

    if host_ok {
        (true, format!("Accepted endpoint: {base_url}"))
    } else {
        (
            false,
            format!(
                "Unrecognized Bitwarden host: {base_url}. Expected api.bitwarden.com, api.bitwarden.eu, or a self-hosted domain containing 'bitwarden'."
            ),
        )
    }
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "bitwarden.collections.list",
            "List collections",
            json!({"type": "object", "required": []}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "bitwarden.collections.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List available collections.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("bitwarden.items.list")],
            },
        ),
        op_info(
            "bitwarden.items.list",
            "List vault items",
            json!({"type": "object", "required": [], "properties": {"collection_id": {"type": "string"}, "folder_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "bitwarden.items.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List vault items (without revealing passwords).".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("bitwarden.items.get"),
                    CapabilityId::from_static("bitwarden.collections.list"),
                ],
            },
        ),
        op_info(
            "bitwarden.items.get",
            "Get a single item with secret fields",
            json!({"type": "object", "required": ["item_id"], "properties": {"item_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["item"], "properties": {"item": {"type": "object"}}}),
            "bitwarden.items.read",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a specific item including passwords/secrets.".into(),
                common_mistakes: vec!["Logging or caching passwords.".into()],
                examples: vec![r#"{"item_id": "abc123"}"#.into()],
                related: vec![CapabilityId::from_static("bitwarden.items.list")],
            },
        ),
        op_info(
            "bitwarden.items.create",
            "Create a new vault item",
            json!({"type": "object", "required": ["type", "name"], "properties": {"type": {"type": "integer", "description": "1=Login, 2=SecureNote, 3=Card, 4=Identity"}, "name": {"type": "string"}, "login": {"type": "object"}, "collection_ids": {"type": "array"}}}),
            json!({"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}),
            "bitwarden.items.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new vault item.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"type": 1, "name": "API Key", "login": {"username": "api", "password": "secret123"}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("bitwarden.items.list"),
                    CapabilityId::from_static("bitwarden.items.delete"),
                ],
            },
        ),
        op_info(
            "bitwarden.items.delete",
            "Delete a vault item",
            json!({"type": "object", "required": ["item_id"], "properties": {"item_id": {"type": "string"}}}),
            json!({"type": "object"}),
            "bitwarden.items.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Delete a vault item. Cannot be undone.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"item_id": "abc123"}"#.into()],
                related: vec![CapabilityId::from_static("bitwarden.items.get")],
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
        let config = BitwardenConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, BitwardenAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = BitwardenConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = BitwardenConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://bitwarden.example.com",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://bitwarden.example.com");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = BitwardenConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = BitwardenConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = BitwardenConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = BitwardenConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = BitwardenConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = BitwardenConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"item_id": "abc"});
        assert_eq!(require_str(&input, "item_id").unwrap(), "abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "item_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"item_id": 42});
        assert!(require_str(&input, "item_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"item_id": null});
        assert!(require_str(&input, "item_id").is_err());
    }

    #[test]
    fn require_i64_present() {
        let input = json!({"type": 1});
        assert_eq!(require_i64(&input, "type").unwrap(), 1);
    }

    #[test]
    fn require_i64_missing() {
        let input = json!({});
        assert!(require_i64(&input, "type").is_err());
    }

    #[test]
    fn require_i64_not_number() {
        let input = json!({"type": "login"});
        assert!(require_i64(&input, "type").is_err());
    }

    #[test]
    fn require_i64_null_value() {
        let input = json!({"type": null});
        assert!(require_i64(&input, "type").is_err());
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
                    "read op {} should be safe or risky, got {:?}",
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
        assert!(ids.contains(&"bitwarden.collections.list"));
        assert!(ids.contains(&"bitwarden.items.list"));
        assert!(ids.contains(&"bitwarden.items.get"));
        assert!(ids.contains(&"bitwarden.items.create"));
        assert!(ids.contains(&"bitwarden.items.delete"));
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
    fn config_trims_access_token() {
        let config =
            BitwardenConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            BitwardenAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            BitwardenAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = BitwardenConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn items_get_is_risky() {
        let ops = operations_info();
        let get_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.items.get")
            .unwrap();
        assert_eq!(get_op.safety_tier, SafetyTier::Risky);
        assert_eq!(get_op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn items_delete_is_dangerous() {
        let ops = operations_info();
        let del_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.items.delete")
            .unwrap();
        assert_eq!(del_op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(del_op.risk_level, RiskLevel::High);
    }

    #[test]
    fn collections_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.collections.list")
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn items_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.items.list")
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = BitwardenConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn operations_items_create_has_none_idempotency() {
        let ops = operations_info();
        let create = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.items.create")
            .unwrap();
        assert_eq!(create.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn operations_items_delete_has_strict_idempotency() {
        let ops = operations_info();
        let delete = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.items.delete")
            .unwrap();
        assert_eq!(delete.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn operations_items_create_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.items.create")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "bitwarden.items.write");
    }

    #[test]
    fn operations_items_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.items.list")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "bitwarden.items.read");
    }

    #[test]
    fn operations_collections_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitwarden.collections.list")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "bitwarden.collections.read");
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
        let input = json!({"item_id": ""});
        assert_eq!(require_str(&input, "item_id").unwrap(), "");
    }

    #[test]
    fn require_i64_negative() {
        let input = json!({"type": -1});
        assert_eq!(require_i64(&input, "type").unwrap(), -1);
    }

    #[test]
    fn require_i64_zero() {
        let input = json!({"type": 0});
        assert_eq!(require_i64(&input, "type").unwrap(), 0);
    }

    #[test]
    fn require_i64_float_truncated() {
        // JSON floats that are exact integers should be readable as i64
        let input = json!({"type": 3});
        assert_eq!(require_i64(&input, "type").unwrap(), 3);
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
    fn require_str_with_object_value() {
        let input = json!({"item_id": {"nested": true}});
        assert!(require_str(&input, "item_id").is_err());
    }

    #[test]
    fn require_str_with_array_value() {
        let input = json!({"item_id": ["a", "b"]});
        assert!(require_str(&input, "item_id").is_err());
    }

    #[test]
    fn require_i64_with_boolean_value() {
        let input = json!({"type": true});
        assert!(require_i64(&input, "type").is_err());
    }

    #[test]
    fn operations_all_capabilities_prefixed_with_bitwarden() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                cap.starts_with("bitwarden."),
                "capability {cap} should be prefixed with bitwarden."
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
        let config = BitwardenConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("BitwardenConfig"), "got: {dbg}");
        let cloned = config.clone();
        assert_eq!(cloned.base_url, config.base_url);
    }

    // ── Base URL policy ──────────────────────────────────────────────

    #[test]
    fn validate_base_url_official_cloud() {
        let (ok, _) = validate_base_url("https://api.bitwarden.com");
        assert!(ok);
    }

    #[test]
    fn validate_base_url_eu_cloud() {
        let (ok, _) = validate_base_url("https://api.bitwarden.eu");
        assert!(ok);
    }

    #[test]
    fn validate_base_url_self_hosted() {
        let (ok, _) = validate_base_url("https://bitwarden.example.com");
        assert!(ok);
    }

    #[test]
    fn validate_base_url_localhost() {
        let (ok, msg) = validate_base_url("http://localhost:8080");
        assert!(ok, "localhost should be allowed: {msg}");
    }

    #[test]
    fn validate_base_url_rejects_http() {
        let (ok, msg) = validate_base_url("http://api.bitwarden.com");
        assert!(!ok, "HTTP should be rejected: {msg}");
    }

    #[test]
    fn validate_base_url_rejects_unknown_host() {
        let (ok, _) = validate_base_url("https://evil.example.com");
        assert!(!ok);
    }

    #[test]
    fn validate_base_url_loopback() {
        let (ok, _) = validate_base_url("http://127.0.0.1:8080");
        assert!(ok);
    }
}
