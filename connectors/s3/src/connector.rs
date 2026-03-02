//! FCP S3 Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::S3Client, error::S3Error};

/// FCP S3 Connector.
pub struct S3Connector {
    base: Arc<BaseConnector>,
    pub(crate) client: Option<S3Client>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl S3Connector {
    /// Create a new S3 connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("s3"))),
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
        let access_key_id =
            params
                .get("access_key_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_key_id in configuration".into(),
                })?;

        let secret_access_key = params
            .get("secret_access_key")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing secret_access_key in configuration".into(),
            })?;

        let region = params
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1");

        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let mut client =
            S3Client::new(access_key_id, secret_access_key, region).map_err(|e| {
                FcpError::Internal {
                    message: format!("Failed to create HTTP client: {e}"),
                }
            })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("S3 connector configured");

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
            manifest_hash: "sha256:s3-connector-v1".into(),
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
                    "s3.put_object",
                    "Upload an object to S3",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key", "body"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" },
                            "body": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "etag": { "type": "string" } } }),
                    "s3.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Upload a file or data to an S3 bucket.".into(),
                        common_mistakes: vec!["Ensure the bucket exists before uploading.".into()],
                        examples: vec![
                            r#"{"bucket": "my-bucket", "key": "data.json", "body": "{}"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
                op_info(
                    "s3.get_object",
                    "Download an object from S3",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "body": { "type": "string" }, "content_type": { "type": "string" } } }),
                    "s3.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Download a file from an S3 bucket.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"bucket": "my-bucket", "key": "data.json"}"#.into()],
                        related: vec![CapabilityId::from_static("s3.put_object")],
                    },
                ),
                op_info(
                    "s3.delete_object",
                    "Delete an object from S3",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "deleted": { "type": "boolean" } } }),
                    "s3.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Delete a file from an S3 bucket. Irreversible.".into(),
                        common_mistakes: vec!["Double-check the key before deleting.".into()],
                        examples: vec![r#"{"bucket": "my-bucket", "key": "old-file.txt"}"#.into()],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
                op_info(
                    "s3.head_object",
                    "Get object metadata without downloading",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": {
                        "content_type": { "type": "string" },
                        "content_length": { "type": "integer" },
                        "etag": { "type": "string" },
                        "last_modified": { "type": "string" }
                    } }),
                    "s3.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check if an object exists or get its metadata.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"bucket": "my-bucket", "key": "data.json"}"#.into()],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
                op_info(
                    "s3.list_objects",
                    "List objects in a bucket",
                    json!({
                        "type": "object",
                        "required": ["bucket"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "prefix": { "type": "string" },
                            "max_keys": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": {
                        "contents": { "type": "array" },
                        "is_truncated": { "type": "boolean" }
                    } }),
                    "s3.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List files in an S3 bucket with optional prefix filter.".into(),
                        common_mistakes: vec!["Use prefix to narrow results for large buckets.".into()],
                        examples: vec![
                            r#"{"bucket": "my-bucket", "prefix": "logs/", "max_keys": 100}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
                op_info(
                    "s3.list_buckets",
                    "List all accessible buckets",
                    json!({ "type": "object", "properties": {} }),
                    json!({ "type": "object", "properties": { "buckets": { "type": "array" } } }),
                    "s3.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all S3 buckets accessible with current credentials.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("s3.list_objects")],
                    },
                ),
                op_info(
                    "s3.copy_object",
                    "Copy an object within or between buckets",
                    json!({
                        "type": "object",
                        "required": ["source_bucket", "source_key", "dest_bucket", "dest_key"],
                        "properties": {
                            "source_bucket": { "type": "string" },
                            "source_key": { "type": "string" },
                            "dest_bucket": { "type": "string" },
                            "dest_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "etag": { "type": "string" } } }),
                    "s3.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Copy an object to a new location without re-uploading.".into(),
                        common_mistakes: vec!["Source must exist; destination is overwritten.".into()],
                        examples: vec![
                            r#"{"source_bucket": "src", "source_key": "a.txt", "dest_bucket": "dst", "dest_key": "b.txt"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("s3.put_object"),
                            CapabilityId::from_static("s3.get_object"),
                        ],
                    },
                ),
                op_info(
                    "s3.generate_presigned_url",
                    "Generate a temporary presigned URL",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" },
                            "expires_in": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "url": { "type": "string" } } }),
                    "s3.read",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a temporary URL to share object access.".into(),
                        common_mistakes: vec!["URLs expire — set appropriate expiry time.".into()],
                        examples: vec![
                            r#"{"bucket": "my-bucket", "key": "report.pdf", "expires_in": 3600}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("s3.get_object")],
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
    pub async fn handle_simulate(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
            "s3.put_object" => self.invoke_put_object(input).await,
            "s3.get_object" => self.invoke_get_object(input).await,
            "s3.delete_object" => self.invoke_delete_object(input).await,
            "s3.head_object" => self.invoke_head_object(input).await,
            "s3.list_objects" => self.invoke_list_objects(input).await,
            "s3.list_buckets" => self.invoke_list_buckets().await,
            "s3.copy_object" => self.invoke_copy_object(input).await,
            "s3.generate_presigned_url" => self.invoke_generate_presigned_url(&input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_put_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        let body = require_str(&input, "body")?;
        let resp = client
            .put_object(bucket, key, body)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({ "etag": resp.etag }))
    }

    async fn invoke_get_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        let resp = client
            .get_object(bucket, key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({ "body": resp.body, "content_type": resp.content_type }))
    }

    async fn invoke_delete_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        client
            .delete_object(bucket, key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_head_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        let resp = client
            .head_object(bucket, key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_objects(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let prefix = input.get("prefix").and_then(|v| v.as_str());
        let max_keys = input.get("max_keys").and_then(|v| v.as_u64());
        let resp = client
            .list_objects(bucket, prefix, max_keys)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_buckets(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resp = client
            .list_buckets()
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_copy_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let source_bucket = require_str(&input, "source_bucket")?;
        let source_key = require_str(&input, "source_key")?;
        let dest_bucket = require_str(&input, "dest_bucket")?;
        let dest_key = require_str(&input, "dest_key")?;
        let resp = client
            .copy_object(source_bucket, source_key, dest_bucket, dest_key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({ "etag": resp.etag }))
    }

    fn invoke_generate_presigned_url(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(input, "bucket")?;
        let key = require_str(input, "key")?;
        let expires_in = input
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        let resp = client.generate_presigned_url(bucket, key, expires_in);
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("S3 connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for S3Connector {
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
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
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
        let mut connector = S3Connector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["s3.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = S3Connector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["s3.get_object"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "s3.get_object");
        let result = connector
            .handle_invoke(json!({
                "operation": "s3.get_object",
                "input": { "bucket": "test", "key": "file.txt" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = S3Connector::new();
        connector.client = Some(
            S3Client::new("test_key", "test_secret", "us-east-1")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["s3.put_object"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "s3.put_object");
        let result = connector
            .handle_invoke(json!({
                "operation": "s3.put_object",
                "input": { "bucket": "test", "key": "file.txt" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("body")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = S3Connector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"s3.put_object"));
        assert!(op_ids.contains(&"s3.get_object"));
        assert!(op_ids.contains(&"s3.delete_object"));
        assert!(op_ids.contains(&"s3.head_object"));
        assert!(op_ids.contains(&"s3.list_objects"));
        assert!(op_ids.contains(&"s3.list_buckets"));
        assert!(op_ids.contains(&"s3.copy_object"));
        assert!(op_ids.contains(&"s3.generate_presigned_url"));
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
