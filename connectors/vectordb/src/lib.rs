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

pub mod config;

use std::sync::Arc;

use fcp_core::{
    BaseConnector, CapabilityGrant, CapabilityVerifier, ConnectorId, EventCaps, FcpError,
    FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SessionId,
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

    /// Handle introspect method.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Introspection is inherently verbose
    pub fn handle_introspect(&self) -> Introspection {
        Introspection {
            operations: vec![
                // Collection operations
                OperationInfo {
                    id: OperationId::from_static("vectordb.list_collections"),
                    summary: "List all vector collections/indexes".into(),
                    description: Some(
                        "List all vector collections/indexes in the configured namespace".into(),
                    ),
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
                    capability: fcp_core::CapabilityId::from_static("vectordb.collections.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: fcp_core::AgentHint {
                        when_to_use: "Use to discover available collections before querying or inserting vectors.".into(),
                        common_mistakes: vec!["Forgetting namespace in multi-tenant setups.".into()],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("vectordb.query_vectors"),
                    summary: "Search for similar vectors".into(),
                    description: Some(
                        "Search for similar vectors using a query vector".into(),
                    ),
                    input_schema: json!({
                        "type": "object",
                        "required": ["collection", "vector"],
                        "properties": {
                            "collection": { "type": "string" },
                            "namespace": { "type": "string" },
                            "vector": {
                                "type": "array",
                                "items": { "type": "number" },
                                "description": "Query vector"
                            },
                            "top_k": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 10000,
                                "default": 10
                            },
                            "filter": {
                                "type": "object",
                                "description": "Metadata filter (provider-specific)"
                            },
                            "include_metadata": { "type": "boolean", "default": true },
                            "include_values": { "type": "boolean", "default": false }
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
                            }
                        }
                    }),
                    capability: fcp_core::CapabilityId::from_static("vectordb.vectors.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: fcp_core::AgentHint {
                        when_to_use: "Use to find similar items based on vector similarity. Core operation for RAG/semantic search.".into(),
                        common_mistakes: vec![
                            "Query vector dimension mismatch.".into(),
                            "Setting top_k too high.".into(),
                        ],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("vectordb.upsert_vectors"),
                    summary: "Insert or update vectors".into(),
                    description: Some(
                        "Insert or update vectors in a collection".into(),
                    ),
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
                                        "metadata": { "type": "object" }
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
                    capability: fcp_core::CapabilityId::from_static("vectordb.vectors.write"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: fcp_core::AgentHint {
                        when_to_use: "Use to add new vectors or update existing ones. Batch for efficiency (up to 1000).".into(),
                        common_mistakes: vec![
                            "Vector dimension mismatch.".into(),
                            "Exceeding batch size limits.".into(),
                        ],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: Some(fcp_core::ApprovalMode::Policy),
                },
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_connector() {
        let connector = VectorDbConnector::new();
        assert!(!connector.is_configured());
        assert!(connector.provider().is_none());
    }

    #[tokio::test]
    async fn test_configure_pinecone() {
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index-abc.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        assert!(result.is_ok());
        assert!(connector.is_configured());
        assert_eq!(connector.provider(), Some(VectorDbProvider::Pinecone));
    }

    #[tokio::test]
    async fn test_configure_qdrant() {
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "my-cluster.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        assert!(result.is_ok());
        assert!(connector.is_configured());
        assert_eq!(connector.provider(), Some(VectorDbProvider::Qdrant));
    }

    #[tokio::test]
    async fn test_configure_invalid() {
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "", // Empty endpoint
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        assert!(result.is_err());
        assert!(!connector.is_configured());
    }

    #[test]
    fn test_health_not_configured() {
        let connector = VectorDbConnector::new();
        let health = connector.handle_health();
        assert_eq!(health["status"], "not_configured");
    }

    #[tokio::test]
    async fn test_health_configured() {
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false
        });

        connector.handle_configure(params).await.unwrap();

        let health = connector.handle_health();
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["provider"], "qdrant");
    }

    #[tokio::test]
    async fn test_doctor_not_configured() {
        let connector = VectorDbConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert!(!result.is_healthy());
    }

    #[tokio::test]
    async fn test_doctor_configured() {
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        connector.handle_configure(params).await.unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert!(result.is_healthy());
    }

    #[test]
    fn test_introspect() {
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();
        assert!(!introspection.operations.is_empty());

        let op_ids: Vec<_> = introspection
            .operations
            .iter()
            .map(|o| o.id.as_str())
            .collect();
        assert!(op_ids.contains(&"vectordb.list_collections"));
        assert!(op_ids.contains(&"vectordb.query_vectors"));
        assert!(op_ids.contains(&"vectordb.upsert_vectors"));
    }
}
