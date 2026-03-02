//! FCP Pinecone Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::PineconeClient, error::PineconeError, types::Vector};

/// FCP Pinecone Connector.
pub struct PineconeConnector {
    base: Arc<BaseConnector>,
    client: Option<PineconeClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl PineconeConnector {
    /// Create a new Pinecone connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("pinecone"))),
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
        let api_key =
            params
                .get("api_key")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key in configuration".into(),
                })?;

        let control_plane_url = params.get("control_plane_url").and_then(|v| v.as_str());
        let data_plane_url = params.get("data_plane_url").and_then(|v| v.as_str());

        let mut client = PineconeClient::new(api_key).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = control_plane_url {
            client = client.with_control_plane_url(url);
        }
        if let Some(url) = data_plane_url {
            client = client.with_data_plane_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Pinecone connector configured");

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
            manifest_hash: "sha256:pinecone-connector-v1".into(),
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
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
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
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "pinecone.list_indexes" => self.invoke_list_indexes().await,
            "pinecone.describe_index" => self.invoke_describe_index(input).await,
            "pinecone.describe_index_stats" => self.invoke_describe_index_stats(input).await,
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

    async fn invoke_query(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let _index_name = require_str(&input, "index_name")?;
        let top_k = input
            .get("top_k")
            .and_then(|v| v.as_u64())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: top_k".into(),
            })? as u32;

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
    pub async fn handle_shutdown(&self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
        info!("Pinecone connector shutting down");
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

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
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
    async fn test_invoke_missing_field() {
        let mut connector = PineconeConnector::new();
        connector.client = Some(
            PineconeClient::new("test-key")
                .unwrap()
                .with_control_plane_url("http://localhost:9999")
                .with_data_plane_url("http://localhost:9999"),
        );

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
        assert!(op_ids.contains(&"pinecone.query"));
        assert!(op_ids.contains(&"pinecone.fetch"));
        assert!(op_ids.contains(&"pinecone.upsert"));
        assert!(op_ids.contains(&"pinecone.delete"));
        assert_eq!(ops.len(), 7);
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
        let computed = manifest.compute_interface_hash().expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2.compute_interface_hash().expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
