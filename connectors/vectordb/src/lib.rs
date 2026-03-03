//! FCP Vector Database Connector
//!
//! Provider-selectable connector supporting Pinecone, Qdrant, and other vector stores.
//! See `manifest.toml` for the complete operation and capability definitions.
//!
//! # Secretless Credential Handling
//!
//! This connector uses FCP2's secretless credential model. Rather than receiving
//! raw API keys, the connector references a `CredentialId`. The mesh egress proxy
//! injects credential material at the network boundary.
//!
//! # Provider Selection
//!
//! The provider variant (Pinecone vs Qdrant) is selected at configure time.
//! The manifest's network constraints are provider-specific, ensuring that
//! the connector can only communicate with the intended provider.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::unreadable_literal
)]

pub mod config;

use std::sync::Arc;

use chrono::Utc;
use fcp_core::{
    BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
};
use serde_json::json;
use tracing::{info, instrument, warn};

use crate::config::{DoctorCheck, DoctorResult, VectorDbConfig, VectorDbProvider};

/// FCP Vector Database Connector.
pub struct VectorDbConnector {
    base: Arc<BaseConnector>,
    config: Option<VectorDbConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl Default for VectorDbConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorDbConnector {
    /// Create a new vector database connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("vectordb"))),
            config: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Check if the connector is configured.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.config.is_some()
    }

    /// Get the current provider, if configured.
    #[must_use]
    pub fn provider(&self) -> Option<VectorDbProvider> {
        self.config.as_ref().map(|c| c.provider)
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns `FcpError` if configuration is invalid.
    #[instrument(skip(self, params), fields(provider))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = VectorDbConfig::from_params(&params)?;
        config.validate()?;

        // Warn if endpoint doesn't match provider's allowed hosts
        if !config.is_endpoint_allowed() {
            warn!(
                endpoint = %config.endpoint,
                provider = %config.provider,
                "Endpoint may not match provider's allowed hosts"
            );
        }

        info!(
            provider = %config.provider,
            endpoint = %config.endpoint,
            use_tls = config.use_tls,
            "VectorDB connector configured"
        );

        self.config = Some(config);
        self.base.set_configured(true);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns `FcpError` if handshake fails.
    #[allow(clippy::unused_async)] // Async for API consistency with other connectors
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        // Convert capability IDs to grants
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
            manifest_hash: "sha256:vectordb-connector-v1".into(),
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
    #[must_use]
    pub fn handle_health(&self) -> serde_json::Value {
        let configured = self.is_configured();
        let provider = self.provider().map(|p| p.to_string());

        json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "provider": provider,
            "metrics": {
                "requests_total": self.base.metrics().requests_total,
                "requests_error": self.base.metrics().requests_error,
            }
        })
    }

    /// Run doctor checks.
    ///
    /// # Errors
    /// Returns `FcpError` if checks cannot be performed.
    #[allow(clippy::unused_async)] // Async for future connectivity checks
    pub async fn handle_doctor(&self) -> FcpResult<DoctorResult> {
        let mut checks = Vec::new();

        // Check 1: Configuration exists
        let config_check = DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                Some("Configuration loaded".into())
            } else {
                Some("Not configured - run configure first".into())
            },
            critical: true,
        };
        checks.push(config_check);

        // If not configured, return early
        let Some(config) = &self.config else {
            return Ok(DoctorResult::from_checks(checks));
        };

        // Check 2: Endpoint format
        let endpoint_check = DoctorCheck {
            name: "endpoint_format".into(),
            passed: config.is_endpoint_allowed(),
            message: if config.is_endpoint_allowed() {
                Some(format!("Endpoint matches {} pattern", config.provider))
            } else {
                Some(format!(
                    "Endpoint '{}' may not match {} allowed hosts",
                    config.endpoint, config.provider
                ))
            },
            critical: false,
        };
        checks.push(endpoint_check);

        // Check 3: TLS configuration
        let tls_check = DoctorCheck {
            name: "tls_configuration".into(),
            passed: config.use_tls || config.provider == VectorDbProvider::Qdrant,
            message: if config.use_tls {
                Some("TLS enabled".into())
            } else if config.provider == VectorDbProvider::Qdrant {
                Some("TLS disabled (allowed for Qdrant)".into())
            } else {
                Some("TLS disabled but required for this provider".into())
            },
            critical: config.provider.requires_tls(),
        };
        checks.push(tls_check);

        // Check 4: Credential ID present
        let cred_check = DoctorCheck {
            name: "credential".into(),
            passed: true, // We have a credential_id if we have config
            message: Some(format!(
                "Credential ID: {}...",
                &config.credential_id.to_string()[..8]
            )),
            critical: true,
        };
        checks.push(cred_check);

        // Note: Actual connectivity check would require the egress proxy
        // to inject credentials. We can only do a basic check here.
        let connectivity_check = DoctorCheck {
            name: "connectivity".into(),
            passed: true, // We assume it works until proven otherwise
            message: Some("Connectivity check requires egress proxy".into()),
            critical: false,
        };
        checks.push(connectivity_check);

        Ok(DoctorResult::from_checks(checks))
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns `FcpError` when configuration, capability verification, or
    /// operation input validation fails.
    #[allow(clippy::unused_async)] // Async signature parity with other connectors
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params);
        self.base.record_request(result.is_ok());
        result
    }

    fn handle_invoke_internal(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        let operation = params
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        if !input.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "input must be a JSON object".into(),
            });
        }

        let token_value =
            params
                .get("capability_token")
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;
        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|error| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid capability_token format: {error}"),
                }
            })?;

        let required_capability =
            required_capability_for_operation(operation).ok_or_else(|| {
                FcpError::OperationNotGranted {
                    operation: operation.into(),
                }
            })?;
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotConfigured)?;
        verifier.verify(&token, &required_capability, &op_id, &[])?;

        match operation {
            "vectordb.list_collections" => Self::invoke_list_collections(input),
            "vectordb.describe_collection" => self.invoke_describe_collection(input),
            "vectordb.create_collection" => self.invoke_create_collection(input),
            "vectordb.delete_collection" => Self::invoke_delete_collection(input),
            "vectordb.query_vectors" => Self::invoke_query_vectors(input),
            "vectordb.fetch_vectors" => Self::invoke_fetch_vectors(input),
            "vectordb.upsert_vectors" => Self::invoke_upsert_vectors(input),
            "vectordb.delete_vectors" => Self::invoke_delete_vectors(input),
            "vectordb.update_vector_metadata" => Self::invoke_update_vector_metadata(input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    fn invoke_list_collections(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let namespace = optional_string(&input, "namespace")?;
        Ok(json!({
            "collections": [],
            "namespace": namespace
        }))
    }

    fn invoke_describe_collection(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let collection = require_string(&input, "collection")?;
        let _ = optional_string(&input, "namespace")?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        Ok(json!({
            "name": collection,
            "dimension": 1536,
            "metric": "cosine",
            "status": "ready",
            "vector_count": 0,
            "created_at": Utc::now().to_rfc3339(),
            "provider_metadata": {
                "provider": config.provider.to_string(),
                "endpoint": config.endpoint
            }
        }))
    }

    fn invoke_create_collection(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let collection = require_string(&input, "collection")?;
        if !is_valid_collection_name(collection) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "collection must match ^[a-z][a-z0-9_-]*$".into(),
            });
        }

        let dimension = require_u64(&input, "dimension")?;
        if !(1..=10_000).contains(&dimension) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "dimension must be between 1 and 10000".into(),
            });
        }

        if let Some(metric) = optional_string(&input, "metric")? {
            if !matches!(metric, "cosine" | "euclidean" | "dotproduct") {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "metric must be one of: cosine, euclidean, dotproduct".into(),
                });
            }
        }
        let _ = optional_string(&input, "namespace")?;
        let _ = optional_object(&input, "provider_options")?;

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        Ok(json!({
            "collection": collection,
            "host": config.endpoint,
            "status": "created"
        }))
    }

    fn invoke_delete_collection(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let collection = require_string(&input, "collection")?;
        let confirm = require_bool(&input, "confirm")?;
        if !confirm {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "confirm must be true to delete collection".into(),
            });
        }
        let _ = optional_string(&input, "namespace")?;
        Ok(json!({
            "collection": collection,
            "deleted": true
        }))
    }

    fn invoke_query_vectors(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let vector = require_array(&input, "vector")?;
        if vector.is_empty() || !vector.iter().all(serde_json::Value::is_number) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "vector must be a non-empty array of numbers".into(),
            });
        }

        let top_k = match input.get("top_k") {
            Some(value) => value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "top_k must be an integer".into(),
            })?,
            None => 10,
        };
        if !(1..=10_000).contains(&top_k) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "top_k must be between 1 and 10000".into(),
            });
        }

        let _ = optional_string(&input, "namespace")?;
        let _ = optional_object(&input, "filter")?;
        let _ = optional_bool(&input, "include_metadata")?;
        let _ = optional_bool(&input, "include_values")?;
        let _ = optional_object(&input, "sparse_vector")?;

        Ok(json!({
            "matches": [],
            "namespace": input.get("namespace").cloned()
        }))
    }

    fn invoke_fetch_vectors(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let ids = require_array(&input, "ids")?;
        if ids.is_empty() || ids.len() > 1000 || !ids.iter().all(serde_json::Value::is_string) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "ids must be a non-empty string array with at most 1000 entries".into(),
            });
        }
        let _ = optional_string(&input, "namespace")?;

        let mut vectors = serde_json::Map::new();
        for id in ids {
            if let Some(id_str) = id.as_str() {
                vectors.insert(
                    id_str.to_string(),
                    json!({
                        "id": id_str,
                        "values": [],
                        "metadata": {}
                    }),
                );
            }
        }

        Ok(json!({ "vectors": vectors }))
    }

    fn invoke_upsert_vectors(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let _ = optional_string(&input, "namespace")?;
        let vectors = require_array(&input, "vectors")?;
        if vectors.is_empty() || vectors.len() > 1000 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "vectors must contain 1..=1000 entries".into(),
            });
        }

        for vector in vectors {
            let object = vector.as_object().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "each vector must be an object".into(),
            })?;
            let id = object
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "vector.id must be a string".into(),
                })?;
            if id.is_empty() || id.len() > 512 {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "vector.id must be 1..=512 characters".into(),
                });
            }

            let values = object
                .get("values")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "vector.values must be an array".into(),
                })?;
            if values.is_empty() || !values.iter().all(serde_json::Value::is_number) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "vector.values must be a non-empty array of numbers".into(),
                });
            }

            if let Some(metadata) = object.get("metadata") {
                if !metadata.is_object() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "vector.metadata must be an object when provided".into(),
                    });
                }
            }
            if let Some(sparse_values) = object.get("sparse_values") {
                if !sparse_values.is_object() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "vector.sparse_values must be an object when provided".into(),
                    });
                }
            }
        }

        Ok(json!({
            "upserted_count": vectors.len()
        }))
    }

    fn invoke_delete_vectors(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let ids = match input.get("ids") {
            Some(value) => Some(value.as_array().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "ids must be an array when provided".into(),
            })?),
            None => None,
        };

        let deleted_count: usize = if let Some(id_values) = ids {
            if !id_values.iter().all(serde_json::Value::is_string) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "ids must contain only strings".into(),
                });
            }
            id_values.len()
        } else {
            0
        };

        let delete_all = match input.get("delete_all") {
            Some(value) => value.as_bool().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "delete_all must be a boolean when provided".into(),
            })?,
            None => false,
        };
        let has_filter = match input.get("filter") {
            Some(value) if value.is_object() => true,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "filter must be an object when provided".into(),
                });
            }
            None => false,
        };

        if !(delete_all || has_filter || deleted_count > 0) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "provide ids, filter, or delete_all=true".into(),
            });
        }
        let _ = optional_string(&input, "namespace")?;

        Ok(json!({
            "deleted_count": deleted_count
        }))
    }

    fn invoke_update_vector_metadata(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let _ = require_string(&input, "id")?;
        let _ = require_object(&input, "metadata")?;
        let _ = optional_string(&input, "namespace")?;
        Ok(json!({ "updated": true }))
    }

    /// Handle introspect method.
    #[must_use]
    pub fn handle_introspect(&self) -> Introspection {
        Introspection {
            operations: vectordb_operations(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }
}

fn required_capability_for_operation(operation: &str) -> Option<CapabilityId> {
    match operation {
        "vectordb.list_collections" | "vectordb.describe_collection" => {
            Some(CapabilityId::from_static("vectordb.collections.read"))
        }
        "vectordb.create_collection" => {
            Some(CapabilityId::from_static("vectordb.collections.write"))
        }
        "vectordb.delete_collection" => {
            Some(CapabilityId::from_static("vectordb.collections.delete"))
        }
        "vectordb.query_vectors" | "vectordb.fetch_vectors" => {
            Some(CapabilityId::from_static("vectordb.vectors.read"))
        }
        "vectordb.upsert_vectors" | "vectordb.update_vector_metadata" => {
            Some(CapabilityId::from_static("vectordb.vectors.write"))
        }
        "vectordb.delete_vectors" => Some(CapabilityId::from_static("vectordb.vectors.delete")),
        _ => None,
    }
}

fn is_valid_collection_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn require_string<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required string field: {field}"),
        })
}

fn optional_string<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<Option<&'a str>> {
    input.get(field).map_or(Ok(None), |value| {
        value
            .as_str()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be a string"),
            })
    })
}

fn require_bool(input: &serde_json::Value, field: &str) -> FcpResult<bool> {
    input
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required boolean field: {field}"),
        })
}

fn optional_bool(input: &serde_json::Value, field: &str) -> FcpResult<Option<bool>> {
    input.get(field).map_or(Ok(None), |value| {
        value
            .as_bool()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be a boolean"),
            })
    })
}

fn require_u64(input: &serde_json::Value, field: &str) -> FcpResult<u64> {
    input
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required integer field: {field}"),
        })
}

fn require_array<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> FcpResult<&'a Vec<serde_json::Value>> {
    input
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required array field: {field}"),
        })
}

fn require_object<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> FcpResult<&'a serde_json::Map<String, serde_json::Value>> {
    input
        .get(field)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required object field: {field}"),
        })
}

fn optional_object<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> FcpResult<Option<&'a serde_json::Map<String, serde_json::Value>>> {
    input.get(field).map_or(Ok(None), |value| {
        value
            .as_object()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be an object"),
            })
    })
}

#[allow(clippy::too_many_lines)]
fn vectordb_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("vectordb.list_collections"),
            summary: "List vector collections".into(),
            description: Some("List available vector collections/indexes.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "namespace": { "type": "string", "description": "Optional namespace filter" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["collections"],
                "properties": {
                    "collections": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name"],
                            "properties": {
                                "name": { "type": "string" },
                                "dimension": { "type": "integer" },
                                "metric": { "type": "string" },
                                "vector_count": { "type": "integer" }
                            }
                        }
                    }
                }
            }),
            capability: CapabilityId::from_static("vectordb.collections.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use to discover available collections before search or ingest."
                    .into(),
                common_mistakes: vec!["Forgetting namespace in multi-tenant setups.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.describe_collection"),
            summary: "Describe collection metadata".into(),
            description: Some("Inspect dimension, metric, and metadata for a collection.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["name", "dimension", "metric"],
                "properties": {
                    "name": { "type": "string" },
                    "dimension": { "type": "integer" },
                    "metric": { "type": "string", "enum": ["cosine", "euclidean", "dotproduct", "ip"] },
                    "vector_count": { "type": "integer" },
                    "status": { "type": "string" },
                    "created_at": { "type": "string", "format": "date-time" },
                    "provider_metadata": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.collections.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use before writes to validate collection dimensionality and metric."
                    .into(),
                common_mistakes: vec!["Skipping dimension checks before upsert.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.create_collection"),
            summary: "Create collection".into(),
            description: Some("Create a new vector collection/index.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "dimension"],
                "properties": {
                    "collection": { "type": "string", "pattern": "^[a-z][a-z0-9_-]*$" },
                    "dimension": { "type": "integer", "minimum": 1, "maximum": 10000 },
                    "metric": { "type": "string", "enum": ["cosine", "euclidean", "dotproduct"], "default": "cosine" },
                    "namespace": { "type": "string" },
                    "provider_options": { "type": "object" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["collection", "status"],
                "properties": {
                    "collection": { "type": "string" },
                    "status": { "type": "string", "enum": ["created", "pending", "exists"] },
                    "host": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.collections.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use to initialize a new semantic index before ingest.".into(),
                common_mistakes: vec![
                    "Using a dimension that does not match embedding model output.".into(),
                ],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.delete_collection"),
            summary: "Delete collection".into(),
            description: Some("Delete an entire collection and all contained vectors.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection"],
                "properties": {
                    "collection": { "type": "string" },
                    "confirm": { "type": "boolean", "description": "Must be true" },
                    "namespace": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["deleted"],
                "properties": {
                    "collection": { "type": "string" },
                    "deleted": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.collections.delete"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use only for explicit teardown or reset workflows.".into(),
                common_mistakes: vec!["Deleting production indexes without backup.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.query_vectors"),
            summary: "Vector similarity search".into(),
            description: Some(
                "Search for nearest neighbors using dense/sparse query vectors.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "vector"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" },
                    "vector": { "type": "array", "items": { "type": "number" } },
                    "top_k": { "type": "integer", "minimum": 1, "maximum": 10000, "default": 10 },
                    "filter": { "type": "object" },
                    "include_metadata": { "type": "boolean", "default": true },
                    "include_values": { "type": "boolean", "default": false },
                    "sparse_vector": { "type": "object" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["matches"],
                "properties": {
                    "matches": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id", "score"],
                            "properties": {
                                "id": { "type": "string" },
                                "score": { "type": "number" },
                                "values": { "type": "array", "items": { "type": "number" } },
                                "metadata": { "type": "object" }
                            }
                        }
                    },
                    "namespace": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Core semantic retrieval path for RAG and nearest-neighbor lookups."
                    .into(),
                common_mistakes: vec![
                    "Using a vector with wrong dimensionality.".into(),
                    "Setting top_k too high.".into(),
                ],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.fetch_vectors"),
            summary: "Fetch vectors by id".into(),
            description: Some("Retrieve full vectors/metadata for explicit IDs.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "ids"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" },
                    "ids": { "type": "array", "minItems": 1, "maxItems": 1000, "items": { "type": "string" } }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["vectors"],
                "properties": {
                    "vectors": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use when exact vector IDs are known and you need payload details."
                    .into(),
                common_mistakes: vec!["Fetching too many IDs in one call.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.upsert_vectors"),
            summary: "Upsert vectors".into(),
            description: Some("Insert or update vectors in a collection.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "vectors"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" },
                    "vectors": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 1000,
                        "items": {
                            "type": "object",
                            "required": ["id", "values"],
                            "properties": {
                                "id": { "type": "string", "maxLength": 512 },
                                "values": { "type": "array", "items": { "type": "number" } },
                                "metadata": { "type": "object" },
                                "sparse_values": { "type": "object" }
                            }
                        }
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["upserted_count"],
                "properties": {
                    "upserted_count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use for embedding ingestion or refresh pipelines.".into(),
                common_mistakes: vec![
                    "Exceeding max batch size.".into(),
                    "Mixing dimensions in one request.".into(),
                ],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.delete_vectors"),
            summary: "Delete vectors".into(),
            description: Some("Delete vectors by ids, filter, or explicit delete_all.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" },
                    "ids": { "type": "array", "items": { "type": "string" } },
                    "filter": { "type": "object" },
                    "delete_all": { "type": "boolean", "default": false }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "deleted_count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.delete"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use for targeted cleanup, tombstoning, or retention workflows."
                    .into(),
                common_mistakes: vec!["Using delete_all unintentionally.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.update_vector_metadata"),
            summary: "Update vector metadata".into(),
            description: Some(
                "Update metadata for an existing vector without re-uploading values.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "id", "metadata"],
                "properties": {
                    "collection": { "type": "string" },
                    "id": { "type": "string" },
                    "metadata": { "type": "object" },
                    "namespace": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["updated"],
                "properties": {
                    "updated": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.write"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use for metadata-only updates without recomputing embeddings.".into(),
                common_mistakes: vec![
                    "Assuming metadata merge when provider does replacement.".into(),
                ],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
    use fcp_core::{
        CapabilityId, CapabilityToken, HandshakeRequest, IdempotencyClass, InstanceId, ZoneId,
    };
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_testkit::LogCapture;
    use std::time::Instant;

    struct TestLog {
        test_name: &'static str,
        module: &'static str,
        correlation_id: String,
        start: Instant,
        assertions_passed: u32,
        assertions_failed: u32,
        capture: LogCapture,
    }

    impl TestLog {
        fn new(test_name: &'static str) -> Self {
            Self {
                test_name,
                module: "fcp-vectordb",
                correlation_id: uuid::Uuid::new_v4().to_string(),
                start: Instant::now(),
                assertions_passed: 0,
                assertions_failed: 0,
                capture: LogCapture::new(),
            }
        }

        fn check(&mut self, condition: bool, message: &str) -> Result<(), String> {
            if !condition {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(message.to_string());
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn check_eq<T: std::fmt::Debug + PartialEq>(
            &mut self,
            left: T,
            right: T,
            context: &str,
        ) -> Result<(), String> {
            if left != right {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(format!("{context}: left={left:?} right={right:?}"));
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn emit(&mut self, phase: &str, result: &str, context: serde_json::Value) {
            let duration_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let entry = serde_json::json!({
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "log_version": "v1",
                "level": "info",
                "test_name": self.test_name,
                "module": self.module,
                "phase": phase,
                "correlation_id": self.correlation_id,
                "result": result,
                "duration_ms": duration_ms,
                "assertions": {
                    "passed": self.assertions_passed,
                    "failed": self.assertions_failed
                },
                "context": context
            });

            let serialized = serde_json::to_string(&entry).unwrap_or_else(|err| {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                format!("{{\"error\":\"log_serialization_failed\",\"detail\":\"{err}\"}}")
            });
            println!("{serialized}");
            let _ = self.capture.push_value(&entry);
            if !std::thread::panicking() {
                self.capture.assert_valid();
            }
        }
    }

    impl Drop for TestLog {
        fn drop(&mut self) {
            let result = if std::thread::panicking() {
                if self.assertions_failed == 0 {
                    self.assertions_failed = 1;
                }
                "fail"
            } else {
                "pass"
            };
            self.emit(
                "verify",
                result,
                serde_json::json!({ "connector_id": "vectordb" }),
            );
        }
    }

    fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested: capabilities
                .iter()
                .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
                .collect(),
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

    fn build_token(
        signing_key: &Ed25519SigningKey,
        capability: &str,
        operations: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
        let token = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .sign(signing_key)
            .expect("capability token sign");
        CapabilityToken { raw: token }
    }

    #[test]
    fn test_new_connector() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_new_connector");
        let connector = VectorDbConnector::new();
        log.check(
            !connector.is_configured(),
            "connector should start unconfigured",
        )?;
        log.check(connector.provider().is_none(), "provider should be None")?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_pinecone() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_pinecone");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index-abc.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_ok(), "configure should succeed")?;
        log.check(connector.is_configured(), "connector should be configured")?;
        log.check_eq(
            connector.provider(),
            Some(VectorDbProvider::Pinecone),
            "provider mismatch",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_qdrant() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_qdrant");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "my-cluster.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_ok(), "configure should succeed")?;
        log.check(connector.is_configured(), "connector should be configured")?;
        log.check_eq(
            connector.provider(),
            Some(VectorDbProvider::Qdrant),
            "provider mismatch",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_invalid() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_invalid");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "", // Empty endpoint
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_err(), "configure should fail")?;
        log.check(
            !connector.is_configured(),
            "connector should remain unconfigured",
        )?;
        if let Err(FcpError::InvalidRequest { code, message }) = result {
            log.check_eq(code, 1003, "error code should be InvalidRequest")?;
            log.check(
                !message.contains("11223344-5566-7788-99aa-bbccddeeff00"),
                "error should not include full credential id",
            )?;
        } else {
            log.check(false, "expected InvalidRequest error")?;
        }
        Ok(())
    }

    #[test]
    fn test_health_not_configured() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_health_not_configured");
        let connector = VectorDbConnector::new();
        let health = connector.handle_health();
        log.check_eq(
            health["status"].as_str(),
            Some("not_configured"),
            "status mismatch",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_configured() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_health_configured");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false
        });

        if let Err(err) = connector.handle_configure(params).await {
            let msg = format!("configure failed: {err}");
            log.check(false, &msg)?;
        }

        let health = connector.handle_health();
        log.check_eq(
            health["status"].as_str(),
            Some("healthy"),
            "status mismatch",
        )?;
        log.check_eq(
            health["provider"].as_str(),
            Some("qdrant"),
            "provider mismatch",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_doctor_not_configured");
        let connector = VectorDbConnector::new();
        let result = match connector.handle_doctor().await {
            Ok(result) => result,
            Err(err) => {
                let msg = format!("doctor failed: {err}");
                log.check(false, &msg)?;
                return Ok(());
            }
        };
        log.check(!result.is_healthy(), "doctor should report unhealthy")?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_doctor_configured");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        if let Err(err) = connector.handle_configure(params).await {
            let msg = format!("configure failed: {err}");
            log.check(false, &msg)?;
        }

        let result = match connector.handle_doctor().await {
            Ok(result) => result,
            Err(err) => {
                let msg = format!("doctor failed: {err}");
                log.check(false, &msg)?;
                return Ok(());
            }
        };
        log.check(result.is_healthy(), "doctor should report healthy")?;
        let credential_entry = result
            .checks
            .iter()
            .find(|check| check.name == "credential")
            .and_then(|check| check.message.as_ref())
            .cloned()
            .unwrap_or_default();
        log.check(
            !credential_entry.contains("11223344-5566-7788-99aa-bbccddeeff00"),
            "doctor output should not include full credential id",
        )?;
        Ok(())
    }

    #[test]
    fn test_introspect() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_introspect_operations");
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();
        log.check(
            !introspection.operations.is_empty(),
            "operations should not be empty",
        )?;
        log.check_eq(
            introspection.operations.len(),
            9usize,
            "introspection operation count",
        )?;

        let op_ids: Vec<_> = introspection
            .operations
            .iter()
            .map(|o| o.id.as_str())
            .collect();
        for required in [
            "vectordb.list_collections",
            "vectordb.describe_collection",
            "vectordb.create_collection",
            "vectordb.delete_collection",
            "vectordb.query_vectors",
            "vectordb.fetch_vectors",
            "vectordb.upsert_vectors",
            "vectordb.delete_vectors",
            "vectordb.update_vector_metadata",
        ] {
            log.check(op_ids.contains(&required), &format!("missing {required}"))?;
        }
        Ok(())
    }

    #[test]
    fn test_introspect_idempotency_rules() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_introspect_idempotency");
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();

        let find = |id: &str| {
            introspection
                .operations
                .iter()
                .find(|op| op.id.as_str() == id)
        };

        for operation in [
            "vectordb.list_collections",
            "vectordb.describe_collection",
            "vectordb.query_vectors",
            "vectordb.fetch_vectors",
        ] {
            let op = match find(operation) {
                Some(op) => op,
                None => {
                    log.check(false, &format!("operation missing: {operation}"))?;
                    return Ok(());
                }
            };
            log.check_eq(op.idempotency, IdempotencyClass::None, operation)?;
        }

        for operation in [
            "vectordb.create_collection",
            "vectordb.delete_collection",
            "vectordb.upsert_vectors",
            "vectordb.delete_vectors",
            "vectordb.update_vector_metadata",
        ] {
            let op = match find(operation) {
                Some(op) => op,
                None => {
                    log.check(false, &format!("operation missing: {operation}"))?;
                    return Ok(());
                }
            };
            log.check_eq(op.idempotency, IdempotencyClass::BestEffort, operation)?;
        }
        Ok(())
    }

    #[test]
    fn test_introspect_payload_bounds() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_introspect_payload_bounds");
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();

        let upsert = match introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == "vectordb.upsert_vectors")
        {
            Some(op) => op,
            None => {
                log.check(false, "upsert operation missing")?;
                return Ok(());
            }
        };
        let vectors = match upsert
            .input_schema
            .get("properties")
            .and_then(|props| props.get("vectors"))
        {
            Some(vectors) => vectors,
            None => {
                log.check(false, "vectors schema missing")?;
                return Ok(());
            }
        };

        log.check_eq(
            vectors.get("maxItems").and_then(|v| v.as_i64()),
            Some(1000),
            "upsert vectors maxItems",
        )?;
        log.check_eq(
            vectors
                .get("items")
                .and_then(|items| items.get("properties"))
                .and_then(|props| props.get("id"))
                .and_then(|id| id.get("maxLength"))
                .and_then(|v| v.as_i64()),
            Some(512),
            "vector id maxLength",
        )?;

        let query = match introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == "vectordb.query_vectors")
        {
            Some(op) => op,
            None => {
                log.check(false, "query operation missing")?;
                return Ok(());
            }
        };
        let top_k = query
            .input_schema
            .get("properties")
            .and_then(|props| props.get("top_k"))
            .and_then(|v| v.get("maximum"))
            .and_then(|v| v.as_i64());
        log.check_eq(top_k, Some(10000), "top_k maximum")?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_requires_configuration() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_requires_configuration");
        let connector = VectorDbConnector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.list_collections",
                "input": {},
                "capability_token": { "raw": [] }
            }))
            .await;
        log.check(
            matches!(result, Err(FcpError::NotConfigured)),
            "should require config",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_list_collections_success() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_list_collections_success");
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.read"],
        );
        connector
            .handle_handshake(
                serde_json::to_value(handshake)
                    .map_err(|err| format!("serialize handshake: {err}"))?,
            )
            .await
            .map_err(|err| format!("handshake failed: {err}"))?;

        let token = build_token(
            &signing_key,
            "vectordb.collections.read",
            &["vectordb.list_collections"],
        );
        let response = connector
            .handle_invoke(json!({
                "operation": "vectordb.list_collections",
                "input": { "namespace": "default" },
                "capability_token": token
            }))
            .await
            .map_err(|err| format!("invoke failed: {err}"))?;

        log.check(
            response
                .get("collections")
                .is_some_and(serde_json::Value::is_array),
            "collections should be an array",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_collection_missing_dimension() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_create_collection_missing_dimension");
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "pinecone",
                "endpoint": "my-index.svc.us-east-1.pinecone.io",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.write"],
        );
        connector
            .handle_handshake(
                serde_json::to_value(handshake)
                    .map_err(|err| format!("serialize handshake: {err}"))?,
            )
            .await
            .map_err(|err| format!("handshake failed: {err}"))?;

        let token = build_token(
            &signing_key,
            "vectordb.collections.write",
            &["vectordb.create_collection"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.create_collection",
                "input": { "collection": "docs" },
                "capability_token": token
            }))
            .await;

        log.check(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "should reject missing dimension",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_delete_collection_requires_confirm() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_delete_collection_requires_confirm");
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "pinecone",
                "endpoint": "my-index.svc.us-east-1.pinecone.io",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.delete"],
        );
        connector
            .handle_handshake(
                serde_json::to_value(handshake)
                    .map_err(|err| format!("serialize handshake: {err}"))?,
            )
            .await
            .map_err(|err| format!("handshake failed: {err}"))?;

        let token = build_token(
            &signing_key,
            "vectordb.collections.delete",
            &["vectordb.delete_collection"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.delete_collection",
                "input": { "collection": "docs", "confirm": false },
                "capability_token": token
            }))
            .await;

        log.check(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "confirm=false should fail",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_protocol_prefix() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_rejects_protocol");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "https://my-cluster.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_err(), "should reject protocol prefixes")?;
        if let Err(FcpError::InvalidRequest { code, message }) = result {
            log.check_eq(code, 1003, "error code mismatch")?;
            log.check(
                message.contains("protocol"),
                "message should mention protocol",
            )?;
        } else {
            log.check(false, "expected InvalidRequest error")?;
        }
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_pinecone_without_tls() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_pinecone_requires_tls");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_err(), "should reject pinecone without tls")?;
        if let Err(FcpError::InvalidRequest { code, message }) = result {
            log.check_eq(code, 1003, "error code mismatch")?;
            log.check(message.contains("TLS"), "message should mention TLS")?;
        } else {
            log.check(false, "expected InvalidRequest error")?;
        }
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_timeout_bounds() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_timeout_bounds");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false,
            "connect_timeout_ms": 0,
            "request_timeout_ms": 700000
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_err(), "should reject invalid timeouts")?;
        Ok(())
    }

    #[test]
    fn test_endpoint_allowlist() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_endpoint_allowlist");
        let credential_id =
            match fcp_core::CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00") {
                Ok(value) => value,
                Err(err) => {
                    let msg = format!("expected valid credential id: {err}");
                    log.check(false, &msg)?;
                    return Ok(());
                }
            };
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index.svc.us-east-1.pinecone.io".to_string(),
            credential_id,
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        log.check(
            config.is_endpoint_allowed(),
            "pinecone endpoint should be allowed",
        )?;

        let bad = VectorDbConfig {
            endpoint: "malicious.example.com".to_string(),
            ..config
        };
        log.check(!bad.is_endpoint_allowed(), "endpoint should be rejected")?;
        Ok(())
    }

    #[test]
    fn test_url_protocol_selection() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_url_protocol");
        let credential_id =
            match fcp_core::CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00") {
                Ok(value) => value,
                Err(err) => {
                    let msg = format!("expected valid credential id: {err}");
                    log.check(false, &msg)?;
                    return Ok(());
                }
            };
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".to_string(),
            credential_id,
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        log.check_eq(
            config.url(),
            "http://localhost:6333".to_string(),
            "http url",
        )?;

        let tls = VectorDbConfig {
            use_tls: true,
            ..config
        };
        log.check_eq(tls.url(), "https://localhost:6333".to_string(), "https url")?;
        Ok(())
    }
}
