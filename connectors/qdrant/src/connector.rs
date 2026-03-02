//! FCP Qdrant Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::QdrantClient, error::QdrantError};

/// FCP Qdrant Connector.
pub struct QdrantConnector {
    base: Arc<BaseConnector>,
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

        let cluster_url =
            params
                .get("cluster_url")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing cluster_url in configuration".into(),
                })?;

        let client =
            QdrantClient::new(api_key, cluster_url).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Qdrant connector configured");

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
                    json!({ "type": "object", "properties": { "status": { "type": "string" } } }),
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
                    json!({ "type": "object", "properties": { "status": { "type": "string" } } }),
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
            "qdrant.list_collections" => self.invoke_list_collections().await,
            "qdrant.collection_info" => self.invoke_collection_info(input).await,
            "qdrant.search" => self.invoke_search(input).await,
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

    async fn invoke_upsert_points(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
        Ok(json!({ "status": status }))
    }

    async fn invoke_delete_points(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
        Ok(json!({ "status": status }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(&self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
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
        connector.client = Some(
            QdrantClient::new("test-key", "http://localhost:9999")
                .unwrap(),
        );

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
    async fn test_introspect_has_all_operations() {
        let connector = QdrantConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"qdrant.list_collections"));
        assert!(op_ids.contains(&"qdrant.collection_info"));
        assert!(op_ids.contains(&"qdrant.search"));
        assert!(op_ids.contains(&"qdrant.get_points"));
        assert!(op_ids.contains(&"qdrant.scroll"));
        assert!(op_ids.contains(&"qdrant.count"));
        assert!(op_ids.contains(&"qdrant.upsert_points"));
        assert!(op_ids.contains(&"qdrant.delete_points"));
        assert_eq!(ops.len(), 8);
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
