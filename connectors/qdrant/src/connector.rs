//! FCP Qdrant Connector implementation.

use std::sync::Arc;

use chrono::Utc;
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::QdrantClient, error::QdrantError, types::OperationReceipt};

#[derive(Debug, Clone)]
enum QdrantAuthMode {
    ApiKey(String),
    CredentialId(CredentialId),
}

#[derive(Debug, Clone)]
struct QdrantConfig {
    cluster_url: String,
    auth: QdrantAuthMode,
}

impl QdrantConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
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
            (Some(key), None) => QdrantAuthMode::ApiKey(key),
            (None, Some(id)) => QdrantAuthMode::CredentialId(id),
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

        let cluster_url = params
            .get("cluster_url")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing cluster_url in configuration".into(),
            })?;

        let parsed = Url::parse(cluster_url).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid cluster_url: {error}"),
        })?;
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "cluster_url must use http or https".into(),
            });
        }
        if parsed.host_str().is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "cluster_url must include a host".into(),
            });
        }

        Ok(Self {
            cluster_url: cluster_url.trim_end_matches('/').to_string(),
            auth,
        })
    }

    fn auth_label(&self) -> &'static str {
        match self.auth {
            QdrantAuthMode::ApiKey(_) => "api_key",
            QdrantAuthMode::CredentialId(_) => "credential_id",
        }
    }

    fn redacted_auth_label(&self) -> String {
        match self.auth {
            QdrantAuthMode::ApiKey(_) => "api_key".to_string(),
            QdrantAuthMode::CredentialId(id) => format!("credential_id:{id}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }

    fn status_label(&self) -> &'static str {
        match self.status {
            DoctorStatus::Healthy => "healthy",
            DoctorStatus::Degraded => "degraded",
            DoctorStatus::Unhealthy => "unhealthy",
        }
    }
}

/// FCP Qdrant Connector.
pub struct QdrantConnector {
    base: Arc<BaseConnector>,
    config: Option<QdrantConfig>,
    client: Option<QdrantClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl QdrantConnector {
    /// Create a new Qdrant connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("qdrant"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = QdrantConfig::from_params(&params)?;
        let mut status = "configured";
        let mut details = json!({
            "cluster_url": config.cluster_url,
            "auth_mode": config.auth_label(),
        });

        self.client = match &config.auth {
            QdrantAuthMode::ApiKey(api_key) => {
                let client = QdrantClient::new(api_key, &config.cluster_url).map_err(|e| {
                    FcpError::Internal {
                        message: format!("Failed to create HTTP client: {e}"),
                    }
                })?;
                Some(client)
            }
            QdrantAuthMode::CredentialId(id) => {
                status = "configured_pending_token_materialization";
                details["credential_id"] = json!(id.to_string());
                details["note"] = json!(
                    "credential_id configured; direct API calls require token materialization in current runtime"
                );
                None
            }
        };
        let redacted_auth = config.redacted_auth_label();
        self.config = Some(config);
        self.base.set_configured(true);
        info!(
            event = "qdrant.provisioning.configure",
            auth = %redacted_auth,
            status,
            "Qdrant connector configured"
        );

        Ok(json!({ "status": status, "details": details }))
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
            manifest_hash: "sha256:qdrant-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
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
        let metrics = self.base.metrics();
        let status = if self.client.is_some() {
            "healthy"
        } else if self.config.is_some() {
            "degraded_pending_credential_materialization"
        } else {
            "not_configured"
        };
        Ok(json!({
            "status": status,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result().await;
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "qdrant.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Qdrant doctor checks completed"
        );
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    async fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - call configure first".into()
            },
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: format!("Auth mode: {}", config.auth_label()),
            critical: false,
        });

        let endpoint_check = Url::parse(&config.cluster_url).ok().map_or(
            DoctorCheck {
                name: "network_constraints".into(),
                passed: false,
                message: "cluster_url could not be parsed".into(),
                critical: true,
            },
            |parsed| {
                let local = parsed.host_str().is_some_and(is_local_test_host);
                let secure_or_local = parsed.scheme() == "https" || local;
                DoctorCheck {
                    name: "network_constraints".into(),
                    passed: secure_or_local,
                    message: if secure_or_local {
                        format!("Endpoint accepted by policy checks: {}", config.cluster_url)
                    } else {
                        format!(
                            "Endpoint must be https or localhost/127.0.0.1 for tests: {}",
                            config.cluster_url
                        )
                    },
                    critical: true,
                }
            },
        );
        checks.push(endpoint_check);

        match (&config.auth, &self.client) {
            (QdrantAuthMode::ApiKey(_), Some(client)) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: true,
                    message: "Direct API key configured in-memory".into(),
                    critical: false,
                });

                match client.list_collections().await {
                    Ok(_) => checks.push(DoctorCheck {
                        name: "read_only_connectivity".into(),
                        passed: true,
                        message: "Read-only list_collections check succeeded".into(),
                        critical: true,
                    }),
                    Err(error) => checks.push(DoctorCheck {
                        name: "read_only_connectivity".into(),
                        passed: false,
                        message: format!("Read-only list_collections check failed: {error}"),
                        critical: true,
                    }),
                }
            }
            (QdrantAuthMode::CredentialId(id), _) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: false,
                    message: format!(
                        "credential_id {id} configured; token materialization required by egress proxy"
                    ),
                    critical: false,
                });
                checks.push(DoctorCheck {
                    name: "read_only_connectivity".into(),
                    passed: false,
                    message: "Skipping live connectivity check in credential_id mode".into(),
                    critical: false,
                });
            }
            (QdrantAuthMode::ApiKey(_), None) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: false,
                    message: "API key mode configured but HTTP client not initialized".into(),
                    critical: true,
                });
            }
        }

        DoctorResult::from_checks(checks)
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "qdrant.list_collections",
                    "List all collections",
                    json!({ "type": "object", "properties": {} }),
                    json!({ "type": "object", "properties": { "collections": { "type": "array" } } }),
                    "qdrant.collections.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all collections in the Qdrant instance.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("qdrant.collection_info")],
                    },
                ),
                op_info(
                    "qdrant.collection_info",
                    "Get collection configuration and statistics",
                    json!({
                        "type": "object",
                        "required": ["collection_name"],
                        "properties": { "collection_name": { "type": "string" } }
                    }),
                    json!({ "type": "object", "properties": { "result": { "type": "object" } } }),
                    "qdrant.collections.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get details about a collection: vector size, distance metric, point count, index status.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"collection_name": "my-collection"}"#.into()],
                        related: vec![CapabilityId::from_static("qdrant.list_collections")],
                    },
                ),
                op_info(
                    "qdrant.create_collection",
                    "Create a new collection",
                    json!({
                        "type": "object",
                        "required": ["collection_name", "vectors"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "vectors": { "type": "object" },
                            "hnsw_config": { "type": "object" },
                            "optimizers_config": { "type": "object" },
                            "wal_config": { "type": "object" },
                            "quantization_config": { "type": "object" },
                            "on_disk_payload": { "type": "boolean" },
                            "shard_number": { "type": "integer" },
                            "replication_factor": { "type": "integer" },
                            "write_consistency_factor": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["status", "receipt"],
                        "properties": {
                            "status": { "type": "string" },
                            "receipt": { "type": "object" }
                        }
                    }),
                    "qdrant.collections.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Provision a new collection before inserting points.".into(),
                        common_mistakes: vec![
                            "Using vector size/distance settings that do not match embeddings.".into(),
                        ],
                        examples: vec![
                            r#"{"collection_name":"docs","vectors":{"size":384,"distance":"Cosine"}}"#
                                .into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("qdrant.collection_info"),
                            CapabilityId::from_static("qdrant.delete_collection"),
                        ],
                    },
                ),
                op_info(
                    "qdrant.delete_collection",
                    "Delete a collection and all points",
                    json!({
                        "type": "object",
                        "required": ["collection_name"],
                        "properties": {
                            "collection_name": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["status", "receipt"],
                        "properties": {
                            "status": { "type": "string" },
                            "receipt": { "type": "object" }
                        }
                    }),
                    "qdrant.collections.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Delete a collection when all stored vectors can be removed."
                            .into(),
                        common_mistakes: vec![
                            "Deleting production collections without backup/export.".into(),
                        ],
                        examples: vec![r#"{"collection_name":"docs"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("qdrant.create_collection"),
                            CapabilityId::from_static("qdrant.list_collections"),
                        ],
                    },
                ),
                op_info(
                    "qdrant.search",
                    "Search for similar points by vector",
                    json!({
                        "type": "object",
                        "required": ["collection_name", "vector", "limit"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "vector": { "type": "array" },
                            "limit": { "type": "integer" },
                            "filter": { "type": "object" },
                            "score_threshold": { "type": "number" },
                            "with_payload": { "type": "boolean" },
                            "with_vectors": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "result": { "type": "array" } } }),
                    "qdrant.points.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Find similar points by vector similarity with optional payload filtering.".into(),
                        common_mistakes: vec!["Not specifying score_threshold - may return low-quality matches.".into()],
                        examples: vec![
                            r#"{"collection_name": "docs", "vector": [0.1, 0.2, 0.3], "limit": 10, "with_payload": true}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("qdrant.get_points"),
                            CapabilityId::from_static("qdrant.scroll"),
                        ],
                    },
                ),
                op_info(
                    "qdrant.query_points",
                    "Query points using Qdrant query API",
                    json!({
                        "type": "object",
                        "required": ["collection_name", "query"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "query": {},
                            "limit": { "type": "integer" },
                            "filter": { "type": "object" },
                            "score_threshold": { "type": "number" },
                            "with_payload": { "type": "boolean" },
                            "with_vectors": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "result": { "type": "array" } } }),
                    "qdrant.points.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use:
                            "Run modern query-style vector search with optional ranking/filter controls."
                                .into(),
                        common_mistakes: vec![
                            "Forgetting to set limit, causing large result payloads.".into(),
                        ],
                        examples: vec![
                            r#"{"collection_name":"docs","query":[0.1,0.2,0.3],"limit":10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("qdrant.search"),
                            CapabilityId::from_static("qdrant.batch_query_points"),
                        ],
                    },
                ),
                op_info(
                    "qdrant.batch_query_points",
                    "Execute multiple vector queries in one request",
                    json!({
                        "type": "object",
                        "required": ["collection_name", "queries"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "queries": { "type": "array" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "result": { "type": "array" } } }),
                    "qdrant.points.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use:
                            "Batch independent vector queries to reduce network overhead and latency."
                                .into(),
                        common_mistakes: vec![
                            "Submitting oversized query batches that exceed service limits.".into(),
                        ],
                        examples: vec![
                            r#"{"collection_name":"docs","queries":[{"query":[0.1,0.2,0.3],"limit":5}]}"#
                                .into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("qdrant.query_points"),
                            CapabilityId::from_static("qdrant.search"),
                        ],
                    },
                ),
                op_info(
                    "qdrant.get_points",
                    "Retrieve points by ID",
                    json!({
                        "type": "object",
                        "required": ["collection_name", "ids"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "ids": { "type": "array" },
                            "with_payload": { "type": "boolean" },
                            "with_vectors": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "result": { "type": "array" } } }),
                    "qdrant.points.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve specific points by their IDs.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"collection_name": "docs", "ids": [1, 2, 3]}"#.into()],
                        related: vec![CapabilityId::from_static("qdrant.search")],
                    },
                ),
                op_info(
                    "qdrant.scroll",
                    "Iterate over points with optional filtering",
                    json!({
                        "type": "object",
                        "required": ["collection_name"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "limit": { "type": "integer" },
                            "offset": { "type": "string" },
                            "filter": { "type": "object" },
                            "with_payload": { "type": "boolean" },
                            "with_vectors": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "result": { "type": "object" } } }),
                    "qdrant.points.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Paginate through all points in a collection, optionally filtered.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"collection_name": "docs", "limit": 100, "with_payload": true}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("qdrant.search"),
                            CapabilityId::from_static("qdrant.count"),
                        ],
                    },
                ),
                op_info(
                    "qdrant.count",
                    "Count points in a collection with optional filter",
                    json!({
                        "type": "object",
                        "required": ["collection_name"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "filter": { "type": "object" },
                            "exact": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "count": { "type": "integer" } } }),
                    "qdrant.points.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Count points in a collection, optionally filtered.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"collection_name": "docs", "exact": true}"#.into()],
                        related: vec![CapabilityId::from_static("qdrant.scroll")],
                    },
                ),
                op_info(
                    "qdrant.upsert_points",
                    "Upsert points (insert or update)",
                    json!({
                        "type": "object",
                        "required": ["collection_name", "points"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "points": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["status", "receipt"],
                        "properties": {
                            "status": { "type": "string" },
                            "receipt": { "type": "object" }
                        }
                    }),
                    "qdrant.points.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Insert new points or update existing ones by ID.".into(),
                        common_mistakes: vec!["Upserting points with mismatched vector dimensions.".into()],
                        examples: vec![
                            r#"{"collection_name": "docs", "points": [{"id": 1, "vector": [0.1, 0.2, 0.3], "payload": {"text": "hello"}}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("qdrant.delete_points"),
                            CapabilityId::from_static("qdrant.search"),
                        ],
                    },
                ),
                op_info(
                    "qdrant.delete_points",
                    "Delete points by ID or filter",
                    json!({
                        "type": "object",
                        "required": ["collection_name"],
                        "properties": {
                            "collection_name": { "type": "string" },
                            "points": { "type": "array" },
                            "filter": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["status", "receipt"],
                        "properties": {
                            "status": { "type": "string" },
                            "receipt": { "type": "object" }
                        }
                    }),
                    "qdrant.points.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Delete points by ID or metadata filter. Irreversible.".into(),
                        common_mistakes: vec![
                            "Using a broad filter that deletes more points than intended.".into(),
                        ],
                        examples: vec![
                            r#"{"collection_name": "docs", "points": [1, 2, 3]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("qdrant.upsert_points")],
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
        let intro = self.handle_introspect().await?;
        let cap_str = intro.get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| ops.iter().find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation)))
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "qdrant.list_collections" => self.invoke_list_collections().await,
            "qdrant.collection_info" => self.invoke_collection_info(input).await,
            "qdrant.create_collection" => self.invoke_create_collection(input).await,
            "qdrant.delete_collection" => self.invoke_delete_collection(input).await,
            "qdrant.search" => self.invoke_search(input).await,
            "qdrant.query_points" => self.invoke_query_points(input).await,
            "qdrant.batch_query_points" => self.invoke_batch_query_points(input).await,
            "qdrant.get_points" => self.invoke_get_points(input).await,
            "qdrant.scroll" => self.invoke_scroll(input).await,
            "qdrant.count" => self.invoke_count(input).await,
            "qdrant.upsert_points" => self.invoke_upsert_points(input).await,
            "qdrant.delete_points" => self.invoke_delete_points(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // -- Operation implementations --

    async fn invoke_list_collections(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let result = client
            .list_collections()
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;
        Ok(json!({ "collections": result.collections }))
    }

    async fn invoke_collection_info(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;
        let info = client
            .collection_info(collection_name)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;
        Ok(json!({ "result": info }))
    }

    async fn invoke_create_collection(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;
        let vectors = input.get("vectors").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: vectors".into(),
        })?;

        let mut body = serde_json::Map::new();
        body.insert("vectors".into(), vectors.clone());
        for key in [
            "hnsw_config",
            "optimizers_config",
            "wal_config",
            "quantization_config",
            "on_disk_payload",
            "shard_number",
            "replication_factor",
            "write_consistency_factor",
            "on_disk",
            "timeout",
        ] {
            if let Some(value) = input.get(key) {
                body.insert(key.into(), value.clone());
            }
        }

        let result = client
            .create_collection(collection_name, &serde_json::Value::Object(body))
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;

        let status = result
            .get("result")
            .and_then(|r| r.get("status"))
            .and_then(|s| s.as_str())
            .or_else(|| result.get("status").and_then(|s| s.as_str()))
            .unwrap_or("completed");
        let receipt = operation_receipt(
            "qdrant.create_collection",
            "collection_created",
            format!("collection:{collection_name}"),
        );
        Ok(json!({ "status": status, "receipt": receipt }))
    }

    async fn invoke_delete_collection(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;
        let result = client
            .delete_collection(collection_name)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;

        let status = result
            .get("result")
            .and_then(|r| r.get("status"))
            .and_then(|s| s.as_str())
            .or_else(|| result.get("status").and_then(|s| s.as_str()))
            .unwrap_or("completed");
        let receipt = operation_receipt(
            "qdrant.delete_collection",
            "collection_deleted",
            format!("collection:{collection_name}"),
        );
        Ok(json!({ "status": status, "receipt": receipt }))
    }

    async fn invoke_search(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;

        // Build the search body from input parameters
        let mut body = json!({});
        if let Some(vector) = input.get("vector") {
            body["vector"] = vector.clone();
        }
        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(filter) = input.get("filter") {
            body["filter"] = filter.clone();
        }
        if let Some(score_threshold) = input.get("score_threshold") {
            body["score_threshold"] = score_threshold.clone();
        }
        if let Some(with_payload) = input.get("with_payload") {
            body["with_payload"] = with_payload.clone();
        }
        if let Some(with_vectors) = input.get("with_vectors") {
            body["with_vectors"] = with_vectors.clone();
        }

        let result = client
            .search(collection_name, &body)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_query_points(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;
        if input.get("query").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: query".into(),
            });
        }

        let mut body = serde_json::Map::new();
        for key in [
            "query",
            "limit",
            "filter",
            "score_threshold",
            "with_payload",
            "with_vectors",
            "params",
            "lookup_from",
            "offset",
        ] {
            if let Some(value) = input.get(key) {
                body.insert(key.into(), value.clone());
            }
        }

        let result = client
            .query_points(collection_name, &serde_json::Value::Object(body))
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_batch_query_points(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;
        let queries = input
            .get("queries")
            .and_then(|value| value.as_array())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: queries (must be an array)".into(),
            })?;

        let result = client
            .batch_query_points(collection_name, queries)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_get_points(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;

        let mut body = json!({});
        if let Some(ids) = input.get("ids") {
            body["ids"] = ids.clone();
        }
        if let Some(with_payload) = input.get("with_payload") {
            body["with_payload"] = with_payload.clone();
        }
        if let Some(with_vectors) = input.get("with_vectors") {
            body["with_vectors"] = with_vectors.clone();
        }

        let result = client
            .get_points(collection_name, &body)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_scroll(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;

        let mut body = json!({});
        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(offset) = input.get("offset") {
            body["offset"] = offset.clone();
        }
        if let Some(filter) = input.get("filter") {
            body["filter"] = filter.clone();
        }
        if let Some(with_payload) = input.get("with_payload") {
            body["with_payload"] = with_payload.clone();
        }
        if let Some(with_vectors) = input.get("with_vectors") {
            body["with_vectors"] = with_vectors.clone();
        }

        let result = client
            .scroll(collection_name, &body)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_count(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;

        let mut body = json!({});
        if let Some(filter) = input.get("filter") {
            body["filter"] = filter.clone();
        }
        if let Some(exact) = input.get("exact") {
            body["exact"] = exact.clone();
        }

        let result = client
            .count(collection_name, &body)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;
        Ok(json!({ "count": result.count }))
    }

    async fn invoke_upsert_points(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;

        let points = input.get("points").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: points".into(),
        })?;

        let body = json!({ "points": points });
        let result = client
            .upsert_points(collection_name, &body)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;

        let status = result
            .get("result")
            .and_then(|r| r.get("status"))
            .and_then(|s| s.as_str())
            .unwrap_or("completed");
        let receipt = operation_receipt(
            "qdrant.upsert_points",
            "points_upserted",
            format!("collection:{collection_name}"),
        );
        Ok(json!({ "status": status, "receipt": receipt }))
    }

    async fn invoke_delete_points(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let collection_name = require_str(&input, "collection_name")?;

        let mut body = json!({});
        if let Some(points) = input.get("points") {
            body["points"] = points.clone();
        }
        if let Some(filter) = input.get("filter") {
            body["filter"] = filter.clone();
        }

        let result = client
            .delete_points(collection_name, &body)
            .await
            .map_err(|e: QdrantError| e.to_fcp_error())?;

        let status = result
            .get("result")
            .and_then(|r| r.get("status"))
            .and_then(|s| s.as_str())
            .unwrap_or("completed");
        let receipt = operation_receipt(
            "qdrant.delete_points",
            "points_deleted",
            format!("collection:{collection_name}"),
        );
        Ok(json!({ "status": status, "receipt": receipt }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Qdrant connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for QdrantConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn operation_receipt(operation: &str, effect: &str, resource: String) -> OperationReceipt {
    OperationReceipt {
        operation: operation.to_string(),
        effect: effect.to_string(),
        resource,
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1")
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
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
        let cap = match op {
            "qdrant.list_collections" | "qdrant.collection_info" => "qdrant.collections.read",
            "qdrant.create_collection" | "qdrant.delete_collection" => "qdrant.collections.write",
            "qdrant.search" | "qdrant.query_points" | "qdrant.batch_query_points"
            | "qdrant.get_points" | "qdrant.scroll" | "qdrant.count" => "qdrant.points.read",
            "qdrant.upsert_points" | "qdrant.delete_points" => "qdrant.points.write",
            _ => "qdrant.collections.read",
        };
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = QdrantConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["qdrant.collections.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = QdrantConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_api_key() {
        let mut connector = QdrantConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "test-key",
                "cluster_url": "https://example.qdrant.io/"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert_eq!(result["details"]["auth_mode"], "api_key");
        assert_eq!(
            result["details"]["cluster_url"],
            "https://example.qdrant.io"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = QdrantConnector::new();
        let credential_id = CredentialId::new();

        let result = connector
            .handle_configure(json!({
                "credential_id": credential_id.to_string(),
                "cluster_url": "https://example.qdrant.io"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured_pending_token_materialization");
        assert_eq!(result["details"]["auth_mode"], "credential_id");
        assert_eq!(
            result["details"]["credential_id"],
            json!(credential_id.to_string())
        );

        let health = connector.handle_health().await.unwrap();
        assert_eq!(
            health["status"],
            "degraded_pending_credential_materialization"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_ambiguous_auth() {
        let mut connector = QdrantConnector::new();
        let credential_id = CredentialId::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "test-key",
                "credential_id": credential_id.to_string(),
                "cluster_url": "https://example.qdrant.io"
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one of api_key or credential_id"));
            }
            other => panic!("expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = QdrantConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_api_key_mode() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/collections"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": { "collections": [] }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = QdrantConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "cluster_url": mock_server.uri()
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let connectivity = checks
            .iter()
            .find(|check| check["name"] == "read_only_connectivity")
            .unwrap();
        assert_eq!(connectivity["passed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = QdrantConnector::new();
        let credential_id = CredentialId::new();
        connector
            .handle_configure(json!({
                "credential_id": credential_id.to_string(),
                "cluster_url": "https://example.qdrant.io"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "degraded");
        let checks = result["checks"].as_array().unwrap();
        let materialization = checks
            .iter()
            .find(|check| check["name"] == "credential_materialization")
            .unwrap();
        assert_eq!(materialization["passed"], false);
        assert_eq!(materialization["critical"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = QdrantConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["qdrant.list_collections"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "qdrant.list_collections");
        let result = connector
            .handle_invoke(json!({
                "operation": "qdrant.list_collections",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = QdrantConnector::new();
        connector.client = Some(QdrantClient::new("test-key", "http://localhost:9999").unwrap());

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["qdrant.collection_info"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "qdrant.collection_info");
        let result = connector
            .handle_invoke(json!({
                "operation": "qdrant.collection_info",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("collection_name"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_collection_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/collections/docs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "result": { "status": "acknowledged" }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = QdrantConnector::new();
        connector.client = Some(QdrantClient::new("test-key", &mock_server.uri()).unwrap());

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["qdrant.create_collection"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "qdrant.create_collection");
        let response = connector
            .handle_invoke(json!({
                "operation": "qdrant.create_collection",
                "input": {
                    "collection_name": "docs",
                    "vectors": { "size": 3, "distance": "Cosine" }
                },
                "capability_token": token
            }))
            .await
            .unwrap();
        assert_eq!(response["status"], "acknowledged");
        assert_eq!(response["receipt"]["operation"], "qdrant.create_collection");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_batch_query_requires_queries() {
        let mut connector = QdrantConnector::new();
        connector.client = Some(QdrantClient::new("test-key", "http://localhost:9999").unwrap());
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["qdrant.batch_query_points"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "qdrant.batch_query_points");
        let result = connector
            .handle_invoke(json!({
                "operation": "qdrant.batch_query_points",
                "input": { "collection_name": "docs" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("queries")),
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = QdrantConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"qdrant.list_collections"));
        assert!(op_ids.contains(&"qdrant.collection_info"));
        assert!(op_ids.contains(&"qdrant.create_collection"));
        assert!(op_ids.contains(&"qdrant.delete_collection"));
        assert!(op_ids.contains(&"qdrant.search"));
        assert!(op_ids.contains(&"qdrant.query_points"));
        assert!(op_ids.contains(&"qdrant.batch_query_points"));
        assert!(op_ids.contains(&"qdrant.get_points"));
        assert!(op_ids.contains(&"qdrant.scroll"));
        assert!(op_ids.contains(&"qdrant.count"));
        assert!(op_ids.contains(&"qdrant.upsert_points"));
        assert!(op_ids.contains(&"qdrant.delete_points"));
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
}
