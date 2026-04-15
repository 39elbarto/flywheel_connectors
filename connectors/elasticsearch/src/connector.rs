//! FCP Elasticsearch Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, Introspection, OperationId, OperationInfo, ProvisioningRecipe,
    ProvisioningStep, ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, StepId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, ElasticsearchAuth, ElasticsearchClient},
    error::ElasticsearchError,
};

/// Parsed and validated Elasticsearch connector configuration.
#[derive(Debug, Clone)]
struct ElasticsearchConfig {
    auth: ElasticsearchAuth,
    base_url: String,
}

impl ElasticsearchConfig {
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
            (Some(key), None) => ElasticsearchAuth::ApiKey(key),
            (None, Some(cred_id)) => ElasticsearchAuth::CredentialId(cred_id),
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

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
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

/// FCP Elasticsearch Connector.
pub struct ElasticsearchConnector {
    base: Arc<BaseConnector>,
    config: Option<ElasticsearchConfig>,
    client: Option<Arc<ElasticsearchClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl ElasticsearchConnector {
    /// Create a new Elasticsearch connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "elasticsearch",
            ))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for ElasticsearchConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl ElasticsearchConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = ElasticsearchConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Elasticsearch connector");

        let client = ElasticsearchClient::new(config.auth.clone(), Some(&config.base_url))
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
            .and_then(|v| v.as_str())
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.elasticsearch",
            "connector_version": "0.1.0",
            "capabilities": [
                "elasticsearch.search.read",
                "elasticsearch.index.write",
                "elasticsearch.indices.read",
                "elasticsearch.indices.write",
                "elasticsearch.cluster.read"
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

    /// Return provisioning readiness information.
    pub fn provisioning_readiness(&self) -> serde_json::Value {
        let (auth_mode, api_key_configured, credential_id_configured) = match &self.config {
            Some(config) => match &config.auth {
                ElasticsearchAuth::ApiKey(_) => ("api_key", true, false),
                ElasticsearchAuth::CredentialId(_) => ("credential_id", false, true),
            },
            None => ("unconfigured", false, false),
        };

        let base_url = self
            .config
            .as_ref()
            .map_or_else(|| DEFAULT_BASE_URL.to_string(), |c| c.base_url.clone());

        let network_ok = base_url.contains(".elastic-cloud.com") || base_url.contains(".found.io");

        json!({
            "auth_mode": auth_mode,
            "api_key_configured": api_key_configured,
            "credential_id_configured": credential_id_configured,
            "network_ok": network_ok,
            "base_url": base_url,
        })
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.elasticsearch",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ok" } else { "degraded" },
            "provisioning": self.provisioning_readiness(),
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("elasticsearch.search"),
                    summary: "Search documents across one or more indices".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["index"],
                        "properties": {
                            "index": { "type": "string", "description": "Index name or pattern" },
                            "query": { "type": "object", "description": "Elasticsearch query DSL" },
                            "size": { "type": "integer", "minimum": 0, "maximum": 10000 },
                            "from": { "type": "integer" },
                            "sort": { "type": "array" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["hits"],
                        "properties": {
                            "hits": { "type": "object" },
                            "took": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("elasticsearch.search.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Search documents using Elasticsearch query DSL.".into(),
                        common_mistakes: vec![
                            "Not specifying size — defaults to 10 results.".into(),
                            "Using match_all without size limit on large indices.".into(),
                        ],
                        examples: vec![
                            r#"{"index": "logs-*", "query": {"match": {"message": "error"}}, "size": 100}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("elasticsearch.get_document"),
                            CapabilityId::from_static("elasticsearch.index_document"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("elasticsearch.get_document"),
                    summary: "Get a single document by ID".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["index", "id"],
                        "properties": {
                            "index": { "type": "string" },
                            "id": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["_source"],
                        "properties": {
                            "_id": { "type": "string" },
                            "_source": { "type": "object" }
                        }
                    }),
                    capability: CapabilityId::from_static("elasticsearch.search.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Retrieve a specific document by ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"index": "logs-2026.03", "id": "abc123"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("elasticsearch.search")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("elasticsearch.index_document"),
                    summary: "Index (create or update) a single document".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["index", "document"],
                        "properties": {
                            "index": { "type": "string" },
                            "id": { "type": "string", "description": "Document ID (auto-generated if omitted)" },
                            "document": { "type": "object" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["_id", "result"],
                        "properties": {
                            "_id": { "type": "string" },
                            "result": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("elasticsearch.index.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Index a single document.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"index": "products", "id": "1", "document": {"name": "Widget", "price": 9.99}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("elasticsearch.bulk")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("elasticsearch.bulk"),
                    summary: "Bulk index, update, or delete documents".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["operations"],
                        "properties": {
                            "operations": { "type": "array", "description": "Array of bulk action objects" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["items", "errors"],
                        "properties": {
                            "errors": { "type": "boolean" },
                            "items": { "type": "array" },
                            "took": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("elasticsearch.index.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Perform bulk indexing, updating, or deleting of documents.".into(),
                        common_mistakes: vec![
                            "Sending too many operations in one request — use batches of 1000-5000.".into(),
                        ],
                        examples: vec![
                            r#"{"operations": [{"index": {"_index": "products", "_id": "1"}}, {"name": "Widget"}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("elasticsearch.index_document")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("elasticsearch.indices.list"),
                    summary: "List indices".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "pattern": { "type": "string", "description": "Index name pattern (e.g. logs-*)" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["indices"],
                        "properties": {
                            "indices": { "type": "array" }
                        }
                    }),
                    capability: CapabilityId::from_static("elasticsearch.indices.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List indices and their metadata.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"pattern": "logs-*"}"#.into()],
                        related: vec![CapabilityId::from_static("elasticsearch.indices.delete")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("elasticsearch.indices.delete"),
                    summary: "Delete an index".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["index"],
                        "properties": {
                            "index": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["acknowledged"],
                        "properties": {
                            "acknowledged": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("elasticsearch.indices.write"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Delete an index and all its documents. Cannot be undone.".into(),
                        common_mistakes: vec![
                            "Deleting indices with active aliases.".into(),
                        ],
                        examples: vec![r#"{"index": "old-logs-2024"}"#.into()],
                        related: vec![CapabilityId::from_static("elasticsearch.indices.list")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("elasticsearch.cluster.health"),
                    summary: "Get cluster health status".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": []
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["cluster_name", "status"],
                        "properties": {
                            "cluster_name": { "type": "string" },
                            "status": { "type": "string" },
                            "number_of_nodes": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("elasticsearch.cluster.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Check cluster health (green/yellow/red).".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("elasticsearch.indices.list")],
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
            "elasticsearch.search" => self.invoke_search(client, &input).await,
            "elasticsearch.get_document" => self.invoke_get_document(client, &input).await,
            "elasticsearch.index_document" => self.invoke_index_document(client, &input).await,
            "elasticsearch.bulk" => self.invoke_bulk(client, &input).await,
            "elasticsearch.indices.list" => self.invoke_indices_list(client, &input).await,
            "elasticsearch.indices.delete" => self.invoke_indices_delete(client, &input).await,
            "elasticsearch.cluster.health" => self.invoke_cluster_health(client).await,
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
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(|v| v.as_str()) == Some(operation))
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
        info!("Elasticsearch connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // ── Operation implementations ─────────────────────────────────────

    async fn invoke_search(
        &self,
        client: &ElasticsearchClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ElasticsearchError> {
        let index = require_str(input, "index")?;
        let query = input.get("query");
        let size = input.get("size").and_then(|v| v.as_i64());
        let from = input.get("from").and_then(|v| v.as_i64());
        let sort = input.get("sort");
        client.search(index, query, size, from, sort).await
    }

    async fn invoke_get_document(
        &self,
        client: &ElasticsearchClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ElasticsearchError> {
        let index = require_str(input, "index")?;
        let document_id = require_str(input, "id")?;
        client.get_document(index, document_id).await
    }

    async fn invoke_index_document(
        &self,
        client: &ElasticsearchClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ElasticsearchError> {
        let index = require_str(input, "index")?;
        let document_id = input.get("id").and_then(|v| v.as_str());
        let document = input.get("document").ok_or(ElasticsearchError::InvalidInput(
            "Missing required field: document".into(),
        ))?;
        client.index_document(index, document_id, document).await
    }

    async fn invoke_bulk(
        &self,
        client: &ElasticsearchClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ElasticsearchError> {
        let operations =
            input
                .get("operations")
                .and_then(|v| v.as_array())
                .ok_or(ElasticsearchError::InvalidInput(
                    "Missing required field: operations".into(),
                ))?;
        client.bulk(operations).await
    }

    async fn invoke_indices_list(
        &self,
        client: &ElasticsearchClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ElasticsearchError> {
        let pattern = input.get("pattern").and_then(|v| v.as_str());
        let data = client.list_indices(pattern).await?;
        Ok(json!({ "indices": data }))
    }

    async fn invoke_indices_delete(
        &self,
        client: &ElasticsearchClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ElasticsearchError> {
        let index = require_str(input, "index")?;
        client.delete_index(index).await
    }

    async fn invoke_cluster_health(
        &self,
        client: &ElasticsearchClient,
    ) -> Result<serde_json::Value, ElasticsearchError> {
        client.cluster_health().await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, ElasticsearchError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElasticsearchError::InvalidInput(format!("Missing required field: {field}")))
}

/// Extract a required i64 field from input.
fn require_i64(input: &serde_json::Value, field: &str) -> Result<i64, ElasticsearchError> {
    input
        .get(field)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ElasticsearchError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "elasticsearch.search",
            "summary": "Search documents across one or more indices",
            "capability": "elasticsearch.search.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "elasticsearch.get_document",
            "summary": "Get a single document by ID",
            "capability": "elasticsearch.search.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "elasticsearch.index_document",
            "summary": "Index (create or update) a single document",
            "capability": "elasticsearch.index.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "elasticsearch.bulk",
            "summary": "Bulk index, update, or delete documents",
            "capability": "elasticsearch.index.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "elasticsearch.indices.list",
            "summary": "List indices",
            "capability": "elasticsearch.indices.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "elasticsearch.indices.delete",
            "summary": "Delete an index",
            "capability": "elasticsearch.indices.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "elasticsearch.cluster.health",
            "summary": "Get cluster health status",
            "capability": "elasticsearch.cluster.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

/// Build the provisioning recipe for the Elasticsearch connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("elasticsearch/setup"),
        "1",
        "Provision Elasticsearch connector with API key or credential injection",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_auth_mode"),
        ProvisioningStepType::PromptUser {
            message: "Choose authentication mode: api_key or credential_id".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("prompt_api_key"),
            ProvisioningStepType::PromptSecret {
                message: "Enter the Elasticsearch API key (base64-encoded id:api_key)".into(),
            },
        )
        .depends_on(StepId::new("prompt_auth_mode")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "elasticsearch_api_key".into(),
                value_from: StepId::new("prompt_api_key"),
                scope: "connector:fcp.elasticsearch".into(),
            },
        )
        .depends_on(StepId::new("prompt_api_key")),
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_base_url"),
        ProvisioningStepType::PromptUser {
            message: "Enter the Elasticsearch cluster URL (default: https://localhost:9200)".into(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ElasticsearchConfig::from_params ────────────────────────────

    #[test]
    fn config_from_api_key() {
        let config = ElasticsearchConfig::from_params(&json!({
            "api_key": "base64encodedkey",
            "base_url": "https://my-cluster.elastic-cloud.com:9243",
        }))
        .unwrap();
        assert!(matches!(config.auth, ElasticsearchAuth::ApiKey(_)));
        assert_eq!(config.base_url, "https://my-cluster.elastic-cloud.com:9243");
    }

    #[test]
    fn config_from_credential_id() {
        let config = ElasticsearchConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_default_base_url() {
        let config = ElasticsearchConfig::from_params(&json!({
            "api_key": "key",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = ElasticsearchConfig::from_params(&json!({
            "api_key": "key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = ElasticsearchConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = ElasticsearchConfig::from_params(&json!({
            "api_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = ElasticsearchConfig::from_params(&json!({
            "api_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = ElasticsearchConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = ElasticsearchConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    // ── require_str ──────────────────────────────────────────────────

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"index": "logs", "id": "abc123"});
        assert_eq!(require_str(&input, "index").unwrap(), "logs");
        assert_eq!(require_str(&input, "id").unwrap(), "abc123");
    }

    #[test]
    fn require_str_missing_field() {
        let input = json!({"index": "logs"});
        let err = require_str(&input, "id").unwrap_err();
        assert!(err.to_string().contains("id"));
    }

    #[test]
    fn require_str_non_string_field() {
        let input = json!({"count": 42});
        assert!(require_str(&input, "count").is_err());
    }

    #[test]
    fn require_str_null_field() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    // ── require_i64 ─────────────────────────────────────────────────

    #[test]
    fn require_i64_extracts_value() {
        let input = json!({"size": 100});
        assert_eq!(require_i64(&input, "size").unwrap(), 100);
    }

    #[test]
    fn require_i64_missing_field() {
        let input = json!({});
        assert!(require_i64(&input, "size").is_err());
    }

    // ── operations_info ──────────────────────────────────────────────

    #[test]
    fn operations_info_has_7_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 7);
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
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.to_ascii_lowercase().ends_with(".read") {
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

    // ── DoctorResult ─────────────────────────────────────────────────

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
                message: Some("warning".into()),
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

    // ── ElasticsearchConnector ──────────────────────────────────────

    #[test]
    fn connector_default() {
        let c = ElasticsearchConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_equals_default() {
        let c = ElasticsearchConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"index": ""});
        assert_eq!(require_str(&input, "index").unwrap(), "");
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"index": true});
        assert!(require_str(&input, "index").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"index": [1, 2]});
        assert!(require_str(&input, "index").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"index": {"nested": true}});
        assert!(require_str(&input, "index").is_err());
    }

    #[test]
    fn require_i64_string_value() {
        let input = json!({"size": "100"});
        assert!(require_i64(&input, "size").is_err());
    }

    #[test]
    fn require_i64_null_value() {
        let input = json!({"size": null});
        assert!(require_i64(&input, "size").is_err());
    }

    #[test]
    fn require_i64_negative_value() {
        let input = json!({"size": -42});
        assert_eq!(require_i64(&input, "size").unwrap(), -42);
    }

    #[test]
    fn require_str_error_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "my_field").unwrap_err();
        assert!(err.to_string().contains("my_field"));
    }

    #[test]
    fn require_i64_error_contains_field_name() {
        let input = json!({});
        let err = require_i64(&input, "my_count").unwrap_err();
        assert!(err.to_string().contains("my_count"));
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
        let expected = [
            "elasticsearch.search",
            "elasticsearch.get_document",
            "elasticsearch.index_document",
            "elasticsearch.bulk",
            "elasticsearch.indices.list",
            "elasticsearch.indices.delete",
            "elasticsearch.cluster.health",
        ];
        for e in &expected {
            assert!(ids.contains(e), "missing expected operation {e}");
        }
    }

    #[test]
    fn operations_all_prefixed_elasticsearch() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("elasticsearch."),
                "op {id} missing elasticsearch. prefix"
            );
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
    fn operations_valid_idempotency_values() {
        let valid = ["strict", "best_effort", "none"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency {idem} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_delete_index_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "elasticsearch.indices.delete")
            .unwrap();
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["risk_level"], "high");
    }

    #[test]
    fn operations_bulk_is_risky() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "elasticsearch.bulk")
            .unwrap();
        assert_eq!(op["safety_tier"], "risky");
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
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
    fn doctor_result_mixed_failures() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "crit".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "opt".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_skip_none_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_includes_some_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failure".into()),
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["message"], "failure");
    }

    #[test]
    fn doctor_check_roundtrip() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let s = serde_json::to_string(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(c2.name, "cfg");
        assert!(c2.passed);
        assert_eq!(c2.message, Some("ok".into()));
    }

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.status, DoctorStatus::Healthy);
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_status_serde_all_variants() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_eq_ne() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn config_trims_api_key() {
        let config = ElasticsearchConfig::from_params(&json!({"api_key": "  my-key  "})).unwrap();
        match &config.auth {
            ElasticsearchAuth::ApiKey(k) => assert_eq!(k, "my-key"),
            ElasticsearchAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn config_error_codes_are_1003() {
        let cases = vec![
            json!({}),
            json!({"credential_id": 42}),
            json!({"credential_id": "not-valid"}),
            json!({"api_key": "k", "credential_id": "550e8400-e29b-41d4-a716-446655440000"}),
        ];
        for case in cases {
            let err = ElasticsearchConfig::from_params(&case).unwrap_err();
            match err {
                FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
                e => panic!("expected InvalidRequest, got {e:?}"),
            }
        }
    }

    #[test]
    fn config_rejects_both_error_message() {
        let result = ElasticsearchConfig::from_params(&json!({
            "api_key": "k",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_none_error_message() {
        let result = ElasticsearchConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── provisioning_recipe ─────────────────────────────────────────

    #[test]
    fn provisioning_recipe_has_expected_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps.len(), 4);
        assert_eq!(recipe.id.as_str(), "elasticsearch/setup");
        assert_eq!(recipe.version, "1");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        let steps = &recipe.steps;

        // prompt_auth_mode has no deps
        assert_eq!(steps[0].id.as_str(), "prompt_auth_mode");
        assert!(steps[0].depends_on.is_empty());

        // prompt_api_key depends on prompt_auth_mode
        assert_eq!(steps[1].id.as_str(), "prompt_api_key");
        assert_eq!(steps[1].depends_on.len(), 1);
        assert_eq!(steps[1].depends_on[0].as_str(), "prompt_auth_mode");

        // store_api_key depends on prompt_api_key
        assert_eq!(steps[2].id.as_str(), "store_api_key");
        assert_eq!(steps[2].depends_on.len(), 1);
        assert_eq!(steps[2].depends_on[0].as_str(), "prompt_api_key");

        // prompt_base_url has no deps
        assert_eq!(steps[3].id.as_str(), "prompt_base_url");
        assert!(steps[3].depends_on.is_empty());
    }

    #[test]
    fn provisioning_recipe_store_secret_scope() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[2];
        assert_eq!(store_step.id.as_str(), "store_api_key");
        match &store_step.kind {
            ProvisioningStepType::StoreSecret {
                scope,
                key,
                value_from,
            } => {
                assert_eq!(scope, "connector:fcp.elasticsearch");
                assert_eq!(key, "elasticsearch_api_key");
                assert_eq!(value_from.as_str(), "prompt_api_key");
            }
            other => panic!("expected StoreSecret, got {other:?}"),
        }
    }

    // ── provisioning_readiness ──────────────────────────────────────

    #[test]
    fn provisioning_readiness_unconfigured() {
        let connector = ElasticsearchConnector::new();
        let readiness = connector.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "unconfigured");
        assert_eq!(readiness["api_key_configured"], false);
        assert_eq!(readiness["credential_id_configured"], false);
        assert_eq!(readiness["base_url"], DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_api_key() {
        let mut connector = ElasticsearchConnector::new();
        connector.config = Some(ElasticsearchConfig {
            auth: ElasticsearchAuth::ApiKey("test-key".into()),
            base_url: "https://my-cluster.elastic-cloud.com:9243".into(),
        });
        let readiness = connector.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "api_key");
        assert_eq!(readiness["api_key_configured"], true);
        assert_eq!(readiness["credential_id_configured"], false);
        assert_eq!(readiness["network_ok"], true);
        assert_eq!(
            readiness["base_url"],
            "https://my-cluster.elastic-cloud.com:9243"
        );
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let mut connector = ElasticsearchConnector::new();
        connector.config = Some(ElasticsearchConfig {
            auth: ElasticsearchAuth::CredentialId(CredentialId::new()),
            base_url: "https://abc.found.io:9243".into(),
        });
        let readiness = connector.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "credential_id");
        assert_eq!(readiness["api_key_configured"], false);
        assert_eq!(readiness["credential_id_configured"], true);
        assert_eq!(readiness["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_network_check() {
        let mut connector = ElasticsearchConnector::new();

        // Valid: elastic-cloud.com domain
        connector.config = Some(ElasticsearchConfig {
            auth: ElasticsearchAuth::ApiKey("k".into()),
            base_url: "https://deploy.elastic-cloud.com:443".into(),
        });
        assert_eq!(connector.provisioning_readiness()["network_ok"], true);

        // Valid: found.io domain
        connector.config = Some(ElasticsearchConfig {
            auth: ElasticsearchAuth::ApiKey("k".into()),
            base_url: "https://my-deploy.found.io:9243".into(),
        });
        assert_eq!(connector.provisioning_readiness()["network_ok"], true);

        // Invalid: localhost
        connector.config = Some(ElasticsearchConfig {
            auth: ElasticsearchAuth::ApiKey("k".into()),
            base_url: "https://localhost:9200".into(),
        });
        assert_eq!(connector.provisioning_readiness()["network_ok"], false);

        // Invalid: arbitrary domain
        connector.config = Some(ElasticsearchConfig {
            auth: ElasticsearchAuth::ApiKey("k".into()),
            base_url: "https://es.example.com:9200".into(),
        });
        assert_eq!(connector.provisioning_readiness()["network_ok"], false);

        // Unconfigured: defaults to localhost
        connector.config = None;
        assert_eq!(connector.provisioning_readiness()["network_ok"], false);
    }

    // ── self_check includes provisioning ────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn self_check_includes_provisioning() {
        let connector = ElasticsearchConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert!(result.get("provisioning").is_some());
        let prov = &result["provisioning"];
        assert_eq!(prov["auth_mode"], "unconfigured");
        assert_eq!(prov["api_key_configured"], false);
        assert_eq!(prov["credential_id_configured"], false);
    }
}
