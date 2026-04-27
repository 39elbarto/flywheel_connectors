//! FCP `Algolia` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    Introspection, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{AlgoliaAuth, AlgoliaClient, DEFAULT_BASE_URL_TEMPLATE},
    error::AlgoliaError,
};

/// Parsed and validated `Algolia` connector configuration.
#[derive(Debug, Clone)]
struct AlgoliaConfig {
    auth: AlgoliaAuth,
    base_url: Option<String>,
}

impl AlgoliaConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let application_id = params
            .get("application_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty application_id in configuration".into(),
            })?
            .to_string();

        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty api_key in configuration".into(),
            })?
            .to_string();

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if let Some(ref url) = base_url {
            reject_base_url_qfu(url)?;
        }

        Ok(Self {
            auth: AlgoliaAuth {
                application_id,
                api_key,
            },
            base_url,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let effective_url = self.base_url.clone().unwrap_or_else(|| {
            DEFAULT_BASE_URL_TEMPLATE.replace("{app_id}", &self.auth.application_id)
        });
        let (network_ok, network_message) = base_url_policy(&effective_url);

        ProvisioningReadiness {
            application_id_configured: true,
            api_key_configured: true,
            network_ok,
            network_message,
            base_url: effective_url,
        }
    }
}

/// Provisioning readiness summary for the Algolia connector.
#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    application_id_configured: bool,
    api_key_configured: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
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

/// FCP `Algolia` Connector.
pub struct AlgoliaConnector {
    base: Arc<BaseConnector>,
    config: Option<AlgoliaConfig>,
    client: Option<Arc<AlgoliaClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl AlgoliaConnector {
    /// Create a new `Algolia` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("algolia"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for AlgoliaConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgoliaConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = AlgoliaConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), "Configuring Algolia connector");

        let client = AlgoliaClient::new(config.auth.clone(), config.base_url.as_deref())
            .map_err(|e| e.to_fcp_error())?;

        self.session_id = None;
        self.base.set_handshaken(false);
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
            "connector_id": "fcp.algolia",
            "connector_version": "0.1.0",
            "capabilities": [
                "algolia.indices.read",
                "algolia.search.read",
                "algolia.records.read",
                "algolia.records.write",
                "algolia.records.delete"
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
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness();
        if !readiness.network_ok {
            let mut report = SelfCheckReport::failed(
                "network_constraints_invalid",
                readiness.network_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let Some(_client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "algolia.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Algolia self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle the `introspect` method.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("algolia.search"),
                    summary: "Search an index".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["index_name", "query"],
                        "properties": {
                            "index_name": {"type": "string"},
                            "query": {"type": "string"},
                            "hits_per_page": {"type": "integer", "maximum": 1000}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["hits"],
                        "properties": {"hits": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("algolia.search.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Search for records in an Algolia index.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"index_name": "products", "query": "laptop", "hits_per_page": 20}"#
                                .into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("algolia.indices.list"),
                            CapabilityId::from_static("algolia.records.get"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("algolia.indices.list"),
                    summary: "List indices".into(),
                    input_schema: json!({"type": "object", "required": []}),
                    output_schema: json!({
                        "type": "object",
                        "required": ["items"],
                        "properties": {"items": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("algolia.indices.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List Algolia search indices.".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("algolia.search")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("algolia.records.get"),
                    summary: "Get a record by objectID".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["index_name", "object_id"],
                        "properties": {
                            "index_name": {"type": "string"},
                            "object_id": {"type": "string"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["objectID"],
                        "properties": {"objectID": {"type": "string"}}
                    }),
                    capability: CapabilityId::from_static("algolia.records.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get a specific record by its objectID.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"index_name": "products", "object_id": "abc123"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("algolia.search")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("algolia.records.delete"),
                    summary: "Delete a record".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["index_name", "object_id"],
                        "properties": {
                            "index_name": {"type": "string"},
                            "object_id": {"type": "string"}
                        }
                    }),
                    output_schema: json!({"type": "object"}),
                    capability: CapabilityId::from_static("algolia.records.delete"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Delete a record from an index. Cannot be undone.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"index_name": "products", "object_id": "abc123"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("algolia.records.get")],
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

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "algolia.search" => self.invoke_search(client, &input).await,
            "algolia.indices.list" => self.invoke_indices_list(client).await,
            "algolia.records.get" => self.invoke_records_get(client, &input).await,
            "algolia.records.delete" => self.invoke_records_delete(client, &input).await,
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
        info!("Algolia connector shutting down");
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

    async fn invoke_search(
        &self,
        client: &AlgoliaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AlgoliaError> {
        let index_name = require_str(input, "index_name")?;
        let query = require_str(input, "query")?;
        let hits_per_page = input
            .get("hits_per_page")
            .and_then(serde_json::Value::as_i64);
        let data = client.search(index_name, query, hits_per_page).await?;
        Ok(data)
    }

    async fn invoke_indices_list(
        &self,
        client: &AlgoliaClient,
    ) -> Result<serde_json::Value, AlgoliaError> {
        let data = client.list_indices().await?;
        Ok(data)
    }

    async fn invoke_records_get(
        &self,
        client: &AlgoliaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AlgoliaError> {
        let index_name = require_str(input, "index_name")?;
        let object_id = require_str(input, "object_id")?;
        let data = client.get_record(index_name, object_id).await?;
        Ok(data)
    }

    async fn invoke_records_delete(
        &self,
        client: &AlgoliaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AlgoliaError> {
        let index_name = require_str(input, "index_name")?;
        let object_id = require_str(input, "object_id")?;
        let data = client.delete_record(index_name, object_id).await?;
        Ok(data)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, AlgoliaError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AlgoliaError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "algolia.search",
            "summary": "Search an index",
            "capability": "algolia.search.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "algolia.indices.list",
            "summary": "List indices",
            "capability": "algolia.indices.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "algolia.records.get",
            "summary": "Get a record by objectID",
            "capability": "algolia.records.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "algolia.records.delete",
            "summary": "Delete a record",
            "capability": "algolia.records.delete",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
    ])
}

/// Build the provisioning recipe for the Algolia connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("algolia.api_key"),
        "1",
        "Provision Algolia connector with Application ID and API Key",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_application_id"),
        ProvisioningStepType::PromptUser {
            message: "Enter your Algolia Application ID".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_api_key"),
            ProvisioningStepType::PromptSecret {
                message: "Enter your Algolia API Key".into(),
            },
        )
        .depends_on(StepId::new("enter_application_id")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("enter_api_key"),
                scope: "connector:fcp.algolia".into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
}

/// Reject base_url overrides with userinfo, query, or fragment. The
/// AlgoliaClient concatenates via format!("{}{path}", self.base_url)
/// in every request method (client.rs:143/154/166). Without this
/// check, a base_url like
/// `https://{app_id}-dsn.algolia.net?leak=x` would leak
/// attacker-chosen query values on every request and put the endpoint
/// path after the `?` boundary. Userinfo would bake into every
/// request URL and silently override the X-Algolia-API-Key header.
/// Matches the hygiene in airtable / asana / gmail / notion / hubspot
/// / whatsapp / linear / clickup / monday / bitbucket / intercom /
/// dropbox / mailchimp.
fn reject_base_url_qfu(base_url: &str) -> FcpResult<()> {
    let parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    Ok(())
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let allowed_host = host.eq_ignore_ascii_case("algolia.net")
        || host.ends_with(".algolia.net")
        || host.eq_ignore_ascii_case("algolianet.com")
        || host.ends_with(".algolianet.com")
        || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and *.algolia.net or *.algolianet.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation_capability<'a>(ops: &'a serde_json::Value, id: &str) -> Option<&'a str> {
        ops.as_array()?
            .iter()
            .find(|op| op["id"] == id)?
            .get("capability")?
            .as_str()
    }

    #[test]
    fn config_from_valid_params() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "APP123",
            "api_key": "key456",
        }))
        .unwrap();
        assert_eq!(config.auth.application_id, "APP123");
        assert_eq!(config.auth.api_key, "key456");
        assert!(config.base_url.is_none());
    }

    #[test]
    fn config_with_custom_base_url() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
            "base_url": "https://test.algolia.net/1",
        }))
        .unwrap();
        assert_eq!(config.base_url, Some("https://test.algolia.net/1".into()));
    }

    #[test]
    fn config_rejects_missing_application_id() {
        let result = AlgoliaConfig::from_params(&json!({
            "api_key": "key456",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_api_key() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": "APP123",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_application_id() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": "",
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_application_id() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": "   ",
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = AlgoliaConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_application_id() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": 12345,
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_api_key() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_application_id() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "  APP  ",
            "api_key": "key",
        }))
        .unwrap();
        assert_eq!(config.auth.application_id, "APP");
    }

    #[test]
    fn config_trims_api_key() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "  key  ",
        }))
        .unwrap();
        assert_eq!(config.auth.api_key, "key");
    }

    #[test]
    fn config_rejects_null_application_id() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": null,
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_api_key() {
        let result = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"index_name": "products"});
        assert_eq!(require_str(&input, "index_name").unwrap(), "products");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "index_name").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"index_name": 42});
        assert!(require_str(&input, "index_name").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"index_name": null});
        assert!(require_str(&input, "index_name").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"index_name": true});
        assert!(require_str(&input, "index_name").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"index_name": ["a", "b"]});
        assert!(require_str(&input, "index_name").is_err());
    }

    #[test]
    fn operations_info_has_4_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 4);
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
        assert!(ids.contains(&"algolia.search"));
        assert!(ids.contains(&"algolia.indices.list"));
        assert!(ids.contains(&"algolia.records.get"));
        assert!(ids.contains(&"algolia.records.delete"));
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
    fn operations_delete_is_dangerous() {
        let ops = operations_info();
        let delete_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "algolia.records.delete")
            .unwrap();
        assert_eq!(delete_op["safety_tier"], "dangerous");
        assert_eq!(delete_op["risk_level"], "high");
    }

    #[fcp_async_core::runtime::test]
    async fn operations_records_delete_requires_dedicated_capability() {
        let ops = operations_info();
        let delete = operation_capability(&ops, "algolia.records.delete");

        assert_eq!(delete, Some("algolia.records.delete"));
        assert_ne!(delete, Some("algolia.records.write"));

        let typed = AlgoliaConnector::new().handle_introspect().await.unwrap();
        let typed_delete = typed["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["id"] == "algolia.records.delete")
            .unwrap();
        assert_eq!(typed_delete["capability"], "algolia.records.delete");
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_advertises_dedicated_records_delete_capability() {
        let mut connector = AlgoliaConnector::new();
        connector
            .handle_configure(json!({
                "application_id": "APP123",
                "api_key": "key456",
            }))
            .await
            .unwrap();

        let handshake = connector
            .handle_handshake(json!({"session_id": "test-session"}))
            .await
            .unwrap();
        let capabilities = handshake["capabilities"].as_array().unwrap();

        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("algolia.records.write"))
        );
        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("algolia.records.delete"))
        );
    }

    #[test]
    fn operations_search_capability() {
        let ops = operations_info();
        let search_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "algolia.search")
            .unwrap();
        assert_eq!(search_op["capability"], "algolia.search.read");
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
        let c = AlgoliaConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = AlgoliaConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_request_count_starts_at_zero() {
        let c = AlgoliaConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_error_count_starts_at_zero() {
        let c = AlgoliaConnector::new();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_check_serializes_with_message() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: false,
            message: Some("failure reason".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["name"], "test_check");
        assert_eq!(v["passed"], false);
        assert_eq!(v["message"], "failure reason");
        assert_eq!(v["critical"], true);
    }

    #[test]
    fn doctor_check_serializes_without_message() {
        let check = DoctorCheck {
            name: "ok_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["name"], "ok_check");
        assert_eq!(v["passed"], true);
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let statuses = [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ];
        for status in &statuses {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(*status, back);
        }
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let c = r.clone();
        assert_eq!(c.status, DoctorStatus::Healthy);
        assert_eq!(c.checks.len(), 1);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn write_operations_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".write") {
                let tier = op["safety_tier"].as_str().unwrap();
                assert_ne!(tier, "safe", "write op {} should not be safe", op["id"]);
            }
        }
    }

    #[test]
    fn operations_records_delete_is_dangerous() {
        let ops = operations_info();
        let del_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "algolia.records.delete")
            .unwrap();
        assert_eq!(del_op["safety_tier"], "dangerous");
        assert_eq!(del_op["risk_level"], "high");
    }

    #[test]
    fn operations_search_summary() {
        let ops = operations_info();
        let search_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "algolia.search")
            .unwrap();
        assert!(search_op["summary"].as_str().unwrap().len() > 5);
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"index_name": {"nested": true}});
        assert!(require_str(&input, "index_name").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"index_name": 9.87});
        assert!(require_str(&input, "index_name").is_err());
    }

    #[test]
    fn operations_all_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("algolia."),
                "op {:?} capability {cap} should start with algolia.",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_status_copy_eq() {
        let a = DoctorStatus::Healthy;
        let b = a;
        assert_eq!(a, b);
        let c = DoctorStatus::Degraded;
        assert_ne!(a, c);
    }

    // -- Provisioning recipe tests -----------------------------------------------

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "algolia.api_key");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_application_id");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_api_key");
        assert_eq!(recipe.steps[2].id.as_str(), "store_api_key");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(
            recipe.steps[1].depends_on[0].as_str(),
            "enter_application_id"
        );
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_api_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "algolia.api_key");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn provisioning_recipe_first_step_is_prompt_user() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(recipe.steps[0].kind.clone()).unwrap();
        assert_eq!(v["type"], "prompt_user");
    }

    #[test]
    fn provisioning_recipe_second_step_is_prompt_secret() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(recipe.steps[1].kind.clone()).unwrap();
        assert_eq!(v["type"], "prompt_secret");
    }

    #[test]
    fn provisioning_recipe_third_step_is_store_secret() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(recipe.steps[2].kind.clone()).unwrap();
        assert_eq!(v["type"], "store_secret");
        assert_eq!(v["key"], "api_key");
        assert_eq!(v["scope"], "connector:fcp.algolia");
    }

    #[test]
    fn provisioning_recipe_description_non_empty() {
        let recipe = provisioning_recipe();
        assert!(!recipe.description.is_empty());
    }

    // -- base_url_policy tests ---------------------------------------------------

    #[test]
    fn base_url_policy_accepts_algolia_net_https() {
        let (ok, message) = base_url_policy("https://TESTAPP.algolia.net/1");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_algolianet_com_https() {
        let (ok, message) = base_url_policy("https://TESTAPP-dsn.algolianet.com/1");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://TESTAPP.algolia.net/1");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("algolia.net"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_no_host() {
        let (ok, message) = base_url_policy("file:///etc/passwd");
        assert!(!ok);
        assert!(message.contains("must include a host"));
    }

    // -- ProvisioningReadiness tests ---------------------------------------------

    #[test]
    fn provisioning_readiness_default_url() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "MYAPP",
            "api_key": "secret",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.application_id_configured);
        assert!(readiness.api_key_configured);
        assert!(readiness.network_ok);
        assert!(readiness.base_url.contains("MYAPP"));
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("algolia.net"));
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["application_id_configured"], true);
        assert_eq!(v["api_key_configured"], true);
        assert!(v["network_ok"].as_bool().unwrap());
    }

    #[test]
    fn provisioning_readiness_localhost_ok() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
            "base_url": "http://localhost:9200",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn from_params_accepts_clean_base_url() {
        let config = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
            "base_url": "https://app-dsn.algolia.net",
        }))
        .unwrap();
        assert_eq!(
            config.base_url.as_deref(),
            Some("https://app-dsn.algolia.net")
        );
    }

    #[test]
    fn from_params_rejects_base_url_query_string() {
        let err = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
            "base_url": "https://app-dsn.algolia.net?leak=x",
        }))
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_params_rejects_base_url_fragment() {
        let err = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
            "base_url": "https://app-dsn.algolia.net#frag",
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_params_rejects_base_url_userinfo() {
        let err = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
            "base_url": "https://attacker:pw@app-dsn.algolia.net",
        }))
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_params_rejects_base_url_unparseable() {
        let err = AlgoliaConfig::from_params(&json!({
            "application_id": "APP",
            "api_key": "KEY",
            "base_url": "not a url",
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }
}
