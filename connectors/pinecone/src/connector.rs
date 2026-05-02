//! FCP Pinecone Connector implementation.

use std::sync::Arc;

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_CONTROL_PLANE_URL, PineconeAuth, PineconeClient},
    error::PineconeError,
    types::Vector,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

/// Validated configuration for the Pinecone connector.
struct PineconeConfig {
    auth: PineconeAuth,
    control_plane_url: String,
    data_plane_url: Option<String>,
}

impl PineconeConfig {
    /// Parse and validate configuration from FCP params.
    ///
    /// Strict auth: exactly one of `api_key` or `credential_id` must be supplied.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(String::from);
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
            (Some(key), None) => PineconeAuth::ApiKey(key),
            (None, Some(cid)) => PineconeAuth::CredentialId(cid),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Supply exactly one of `api_key` or `credential_id`, not both".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing authentication: supply `api_key` or `credential_id`".into(),
                });
            }
        };

        let control_plane_url = params
            .get("control_plane_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_CONTROL_PLANE_URL)
            .to_string();

        let data_plane_url = params
            .get("data_plane_url")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(Self {
            auth,
            control_plane_url,
            data_plane_url,
        })
    }
}

/// Structured readiness diagnostic for the doctor command.
#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// FCP Pinecone Connector.
pub struct PineconeConnector {
    base: Arc<BaseConnector>,
    config: Option<PineconeConfig>,
    client: Option<PineconeClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl PineconeConnector {
    /// Create a new Pinecone connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.pinecone"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = PineconeConfig::from_params(&params)?;

        let mut client =
            PineconeClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        client = client.with_control_plane_url(&config.control_plane_url);
        if let Some(url) = &config.data_plane_url {
            client = client.with_data_plane_url(url);
        }

        info!(auth = %config.auth.redacted_label(), "Pinecone connector configured");

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        Ok(json!({ "status": "configured" }))
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
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
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
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(config.auth.redacted_label());
            health["control_plane_url"] = json!(config.control_plane_url);
        }
        Ok(health)
    }

    /// Handle doctor readiness check.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. Configuration
        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured – call `configure` first".into(),
            }
        });

        // 2. Client initialized
        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "HTTP client is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "HTTP client is not initialized".into(),
            }
        });

        // 3. Base URL
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Control plane: {}", config.control_plane_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "Control plane URL not set (not configured)".into(),
            });
        }

        // 4. Auth mode
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", config.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Unhealthy,
                message: "Auth mode not set (not configured)".into(),
            });
        }

        // 5. Network constraints
        let egress_target = self.config.as_ref().map_or("api.pinecone.io", |c| {
            c.control_plane_url
                .strip_prefix("https://")
                .or_else(|| c.control_plane_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .unwrap_or("api.pinecone.io")
        });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: format!("Egress target: {egress_target}"),
        });

        // 6. Credential injection
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Secretless mode – egress proxy will inject credentials".into(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Direct API key mode – no proxy injection needed".into(),
                });
            }
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode, we can't verify connectivity without the egress proxy
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
        }

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "pinecone.list_indexes",
                    "List all indexes in the project",
                    json!({
                        "type": "object",
                        "required": [],
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "required": ["indexes"],
                        "properties": { "indexes": { "type": "array" } }
                    }),
                    "pinecone.indexes.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all Pinecone indexes in the project.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("pinecone.describe_index")],
                    },
                ),
                op_info(
                    "pinecone.describe_index",
                    "Get index configuration and statistics",
                    json!({
                        "type": "object",
                        "required": ["index_name"],
                        "properties": { "index_name": { "type": "string" } }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "dimension", "metric", "status"],
                        "properties": {
                            "name": { "type": "string" },
                            "dimension": { "type": "integer" },
                            "metric": { "type": "string" },
                            "status": { "type": "object" }
                        }
                    }),
                    "pinecone.indexes.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get details about a specific index: dimension, metric, pod type, replicas.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"index_name": "my-index"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("pinecone.list_indexes"),
                            CapabilityId::from_static("pinecone.describe_index_stats"),
                        ],
                    },
                ),
                op_info(
                    "pinecone.describe_index_stats",
                    "Get per-namespace vector counts and index fullness",
                    json!({
                        "type": "object",
                        "required": ["index_name"],
                        "properties": {
                            "index_name": { "type": "string" },
                            "filter": { "type": "object", "description": "Metadata filter to count matching vectors only" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["namespaces", "dimension", "index_fullness", "total_vector_count"],
                        "properties": {
                            "namespaces": { "type": "object" },
                            "dimension": { "type": "integer" },
                            "index_fullness": { "type": "number" },
                            "total_vector_count": { "type": "integer" }
                        }
                    }),
                    "pinecone.indexes.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get vector counts per namespace and overall index utilization.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"index_name": "my-index"}"#.into()],
                        related: vec![CapabilityId::from_static("pinecone.describe_index")],
                    },
                ),
                op_info(
                    "pinecone.create_index",
                    "Create a new index",
                    json!({
                        "type": "object",
                        "required": ["name", "dimension"],
                        "properties": {
                            "name": { "type": "string" },
                            "dimension": { "type": "integer" },
                            "metric": { "type": "string", "default": "cosine" },
                            "spec": { "type": "object", "description": "Index spec (serverless or pod configuration)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "dimension", "metric"],
                        "properties": {
                            "name": { "type": "string" },
                            "dimension": { "type": "integer" },
                            "metric": { "type": "string" },
                            "host": { "type": "string" },
                            "status": { "type": "object" }
                        }
                    }),
                    "pinecone.indexes.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Create a new Pinecone index. Choose dimension and metric carefully.".into(),
                        common_mistakes: vec!["Wrong dimension for your embedding model.".into()],
                        examples: vec![
                            r#"{"name": "my-index", "dimension": 1536, "metric": "cosine", "spec": {"serverless": {"cloud": "aws", "region": "us-east-1"}}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("pinecone.list_indexes"),
                            CapabilityId::from_static("pinecone.delete_index"),
                        ],
                    },
                ),
                op_info(
                    "pinecone.delete_index",
                    "Delete an index and all its data",
                    json!({
                        "type": "object",
                        "required": ["index_name"],
                        "properties": {
                            "index_name": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["deleted", "index_name"],
                        "properties": {
                            "deleted": { "type": "boolean" },
                            "index_name": { "type": "string" }
                        }
                    }),
                    "pinecone.indexes.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Delete a Pinecone index. This is irreversible and deletes all data.".into(),
                        common_mistakes: vec!["Deleting production indexes without backup.".into()],
                        examples: vec![r#"{"index_name": "my-index"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("pinecone.create_index"),
                            CapabilityId::from_static("pinecone.list_indexes"),
                        ],
                    },
                ),
                op_info(
                    "pinecone.query",
                    "Query vectors by similarity",
                    json!({
                        "type": "object",
                        "required": ["index_name", "top_k"],
                        "properties": {
                            "index_name": { "type": "string" },
                            "vector": { "type": "array", "description": "Query vector" },
                            "id": { "type": "string", "description": "Query by vector ID instead of vector values" },
                            "top_k": { "type": "integer", "description": "Number of results" },
                            "namespace": { "type": "string" },
                            "filter": { "type": "object", "description": "Metadata filter" },
                            "include_metadata": { "type": "boolean", "default": true },
                            "include_values": { "type": "boolean", "default": false }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["matches"],
                        "properties": {
                            "matches": { "type": "array" },
                            "namespace": { "type": "string" }
                        }
                    }),
                    "pinecone.vectors.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Find similar vectors by similarity search. Provide either 'vector' or 'id'.".into(),
                        common_mistakes: vec![
                            "Not specifying namespace when index has multiple namespaces.".into(),
                            "Setting include_values=true when only metadata is needed (increases response size).".into(),
                        ],
                        examples: vec![
                            r#"{"index_name": "my-index", "vector": [0.1, 0.2, 0.3], "top_k": 10, "include_metadata": true}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("pinecone.fetch"),
                            CapabilityId::from_static("pinecone.upsert"),
                        ],
                    },
                ),
                op_info(
                    "pinecone.fetch",
                    "Fetch vectors by ID",
                    json!({
                        "type": "object",
                        "required": ["index_name", "ids"],
                        "properties": {
                            "index_name": { "type": "string" },
                            "ids": { "type": "array" },
                            "namespace": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["vectors"],
                        "properties": { "vectors": { "type": "object" } }
                    }),
                    "pinecone.vectors.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve specific vectors by their IDs.".into(),
                        common_mistakes: vec!["Fetching too many IDs at once (max 1000 per request).".into()],
                        examples: vec![r#"{"index_name": "my-index", "ids": ["vec-1", "vec-2"]}"#.into()],
                        related: vec![CapabilityId::from_static("pinecone.query")],
                    },
                ),
                op_info(
                    "pinecone.upsert",
                    "Upsert vectors (insert or update)",
                    json!({
                        "type": "object",
                        "required": ["index_name", "vectors"],
                        "properties": {
                            "index_name": { "type": "string" },
                            "vectors": { "type": "array", "description": "Array of {id, values, metadata} objects" },
                            "namespace": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["upserted_count"],
                        "properties": { "upserted_count": { "type": "integer" } }
                    }),
                    "pinecone.vectors.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Insert new vectors or update existing ones. Batch up to 100 vectors per request.".into(),
                        common_mistakes: vec!["Exceeding max batch size (100 vectors) or max request size (2MB).".into()],
                        examples: vec![
                            r#"{"index_name": "my-index", "vectors": [{"id": "vec-1", "values": [0.1, 0.2, 0.3], "metadata": {"text": "hello"}}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("pinecone.query"),
                            CapabilityId::from_static("pinecone.delete"),
                        ],
                    },
                ),
                op_info(
                    "pinecone.delete",
                    "Delete vectors by ID, filter, or delete all in namespace",
                    json!({
                        "type": "object",
                        "required": ["index_name"],
                        "properties": {
                            "index_name": { "type": "string" },
                            "ids": { "type": "array" },
                            "delete_all": { "type": "boolean", "default": false },
                            "namespace": { "type": "string" },
                            "filter": { "type": "object" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "pinecone.vectors.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Delete vectors by ID, metadata filter, or clear an entire namespace. Irreversible.".into(),
                        common_mistakes: vec!["Setting delete_all=true without specifying namespace \u{2014} deletes everything.".into()],
                        examples: vec![r#"{"index_name": "my-index", "ids": ["vec-1", "vec-2"]}"#.into()],
                        related: vec![CapabilityId::from_static("pinecone.upsert")],
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
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
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
            let _bound = verifier.verify_bound(token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotHandshaken);
        }

        match operation {
            "pinecone.list_indexes" => self.invoke_list_indexes().await,
            "pinecone.describe_index" => self.invoke_describe_index(input).await,
            "pinecone.describe_index_stats" => self.invoke_describe_index_stats(input).await,
            "pinecone.create_index" => self.invoke_create_index(input).await,
            "pinecone.delete_index" => self.invoke_delete_index(input).await,
            "pinecone.query" => self.invoke_query(input).await,
            "pinecone.fetch" => self.invoke_fetch(input).await,
            "pinecone.upsert" => self.invoke_upsert(input).await,
            "pinecone.delete" => self.invoke_delete(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_list_indexes(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let result = client
            .list_indexes()
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        Ok(json!({ "indexes": result.indexes }))
    }

    async fn invoke_describe_index(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let index_name = require_str(&input, "index_name")?;
        let index = client
            .describe_index(index_name)
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        serde_json::to_value(&index).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize index: {e}"),
        })
    }

    async fn invoke_describe_index_stats(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let _index_name = require_str(&input, "index_name")?;
        let filter = input.get("filter");
        let stats = client
            .describe_index_stats(filter)
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        serde_json::to_value(&stats).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize stats: {e}"),
        })
    }

    async fn invoke_create_index(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let name = require_str(&input, "name")?;
        let dimension = input
            .get("dimension")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: dimension".into(),
            })?;
        let metric = input
            .get("metric")
            .and_then(|v| v.as_str())
            .unwrap_or("cosine");
        let spec = input.get("spec");

        let index = client
            .create_index(name, dimension, metric, spec)
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        serde_json::to_value(&index).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize index: {e}"),
        })
    }

    async fn invoke_delete_index(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let index_name = require_str(&input, "index_name")?;
        client
            .delete_index(index_name)
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        Ok(json!({ "deleted": true, "index_name": index_name }))
    }

    async fn invoke_query(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let _index_name = require_str(&input, "index_name")?;
        let top_k = input
            .get("top_k")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: top_k".into(),
            })?;

        let vector: Option<Vec<f32>> = input
            .get("vector")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let id = input.get("id").and_then(|v| v.as_str());
        let namespace = input.get("namespace").and_then(|v| v.as_str());
        let filter = input.get("filter");
        let include_metadata = input
            .get("include_metadata")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let include_values = input
            .get("include_values")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let result = client
            .query(
                vector.as_deref(),
                id,
                top_k,
                namespace,
                filter,
                include_metadata,
                include_values,
            )
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        serde_json::to_value(&result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize query result: {e}"),
        })
    }

    async fn invoke_fetch(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let _index_name = require_str(&input, "index_name")?;
        let ids: Vec<String> = input
            .get("ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: ids".into(),
            })?;
        let namespace = input.get("namespace").and_then(|v| v.as_str());

        let result = client
            .fetch(&ids, namespace)
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        serde_json::to_value(&result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize fetch result: {e}"),
        })
    }

    async fn invoke_upsert(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let _index_name = require_str(&input, "index_name")?;
        let vectors: Vec<Vector> = input
            .get("vectors")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: vectors".into(),
            })?;
        let namespace = input.get("namespace").and_then(|v| v.as_str());

        let result = client
            .upsert(&vectors, namespace)
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        Ok(json!({ "upserted_count": result.upserted_count }))
    }

    async fn invoke_delete(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let _index_name = require_str(&input, "index_name")?;
        let ids: Option<Vec<String>> = input
            .get("ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let delete_all = input
            .get("delete_all")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let namespace = input.get("namespace").and_then(|v| v.as_str());
        let filter = input.get("filter");

        let result = client
            .delete(ids.as_deref(), delete_all, namespace, filter)
            .await
            .map_err(|e: PineconeError| e.to_fcp_error())?;
        Ok(result)
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Pinecone connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for PineconeConnector {
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

    fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
        let cap = match op {
            "pinecone.list_indexes"
            | "pinecone.describe_index"
            | "pinecone.describe_index_stats" => "pinecone.indexes.read",
            "pinecone.create_index" | "pinecone.delete_index" => "pinecone.indexes.write",
            "pinecone.query" | "pinecone.fetch" => "pinecone.vectors.read",
            "pinecone.upsert" | "pinecone.delete" => "pinecone.vectors.write",
            _ => "pinecone.indexes.read",
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
        CapabilityToken::from_raw(cose)
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = PineconeConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["pinecone.indexes.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
        assert_eq!(result["manifest_hash"], PineconeConnector::manifest_hash());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = PineconeConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = PineconeConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["pinecone.list_indexes"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "pinecone.list_indexes");
        let result = connector
            .handle_invoke(json!({
                "operation": "pinecone.list_indexes",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_handshake() {
        let mut connector = PineconeConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "control_plane_url": "http://localhost:9999",
                "data_plane_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, "pinecone.list_indexes");
        let result = connector
            .handle_invoke(json!({
                "operation": "pinecone.list_indexes",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = PineconeConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "control_plane_url": "http://localhost:9999",
                "data_plane_url": "http://localhost:9999"
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
                "capabilities_requested": ["pinecone.query"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "pinecone.query");
        let result = connector
            .handle_invoke(json!({
                "operation": "pinecone.query",
                "input": { "index_name": "my-index" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("top_k")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = PineconeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"pinecone.list_indexes"));
        assert!(op_ids.contains(&"pinecone.describe_index"));
        assert!(op_ids.contains(&"pinecone.describe_index_stats"));
        assert!(op_ids.contains(&"pinecone.create_index"));
        assert!(op_ids.contains(&"pinecone.delete_index"));
        assert!(op_ids.contains(&"pinecone.query"));
        assert!(op_ids.contains(&"pinecone.fetch"));
        assert!(op_ids.contains(&"pinecone.upsert"));
        assert!(op_ids.contains(&"pinecone.delete"));
        assert_eq!(ops.len(), 9);
    }

    // ── Provisioning automation tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_api_key() {
        let mut connector = PineconeConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "pcsk_test123"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = PineconeConnector::new();
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
    async fn test_configure_rejects_both_auth_modes() {
        let mut connector = PineconeConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "api_key": "pcsk_test123",
                "credential_id": cid
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth() {
        let mut connector = PineconeConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing authentication"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_urls() {
        let mut connector = PineconeConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "pcsk_test123",
                "control_plane_url": "https://custom.pinecone.io",
                "data_plane_url": "https://custom-data.pinecone.io"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.control_plane_url, "https://custom.pinecone.io");
        assert_eq!(
            config.data_plane_url.as_deref(),
            Some("https://custom-data.pinecone.io")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = PineconeConnector::new();
        connector
            .handle_configure(json!({ "api_key": "pcsk_test123" }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert!(health["auth_mode"].as_str().unwrap().contains("api_key"));
        assert!(health["control_plane_url"].as_str().is_some());
    }

    #[test]
    fn connector_base_id_matches_manifest() {
        let connector = PineconeConnector::new();
        assert_eq!(connector.base.id.as_ref(), "fcp.pinecone");
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_clears_state() {
        let mut connector = PineconeConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "control_plane_url": "http://localhost:9999",
                "data_plane_url": "http://localhost:9999"
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
                "capabilities_requested": ["pinecone.indexes.read"]
            }))
            .await
            .unwrap();

        connector.handle_shutdown(json!({})).await.unwrap();

        assert!(connector.client.is_none());
        assert!(connector.config.is_none());
        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = PineconeConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = PineconeConnector::new();
        connector
            .handle_configure(json!({ "api_key": "pcsk_test123" }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        for check in checks {
            assert_eq!(check["status"], "healthy");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = PineconeConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "healthy");
        assert!(
            cred_check["message"]
                .as_str()
                .unwrap()
                .contains("Secretless")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = PineconeConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = PineconeConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
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
