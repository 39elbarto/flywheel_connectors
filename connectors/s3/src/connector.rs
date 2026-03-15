//! FCP S3 Connector implementation.

use std::sync::Arc;

use fcp_core::ApprovalScope::Execution;
use fcp_core::{
    AgentHint, ApprovalMode, ApprovalToken, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityToken, CapabilityVerifier, ConnectorId, CredentialId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse,
};
use fcp_sdk::migration::ConnectorRuntime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, S3Auth, S3Client},
    error::S3Error,
};

/// Validated configuration for the S3 connector.
struct S3Config {
    auth: S3Auth,
    base_url: String,
}

#[derive(Debug, Clone)]
struct ExecutionApprovalContext {
    token_id: String,
}

impl S3Config {
    /// Parse and validate configuration from FCP params.
    ///
    /// Strict auth: exactly one of (`access_key_id` + `secret_access_key`) or `credential_id`.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_key_id = params
            .get("access_key_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        let secret_access_key = params
            .get("secret_access_key")
            .and_then(|v| v.as_str())
            .map(String::from);
        let region = params
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1")
            .to_string();
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

        let has_keys = access_key_id.is_some() || secret_access_key.is_some();
        let auth = match (has_keys, credential_id) {
            (true, None) => {
                let aki = access_key_id.ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_key_id (required with secret_access_key)".into(),
                })?;
                let sak = secret_access_key.ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing secret_access_key (required with access_key_id)".into(),
                })?;
                S3Auth::Keys {
                    access_key_id: aki,
                    secret_access_key: sak,
                    region,
                }
            }
            (false, Some(cid)) => S3Auth::CredentialId(cid),
            (true, Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Supply exactly one of (`access_key_id` + `secret_access_key`) or `credential_id`, not both".into(),
                });
            }
            (false, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing authentication: supply (`access_key_id` + `secret_access_key`) or `credential_id`".into(),
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

/// FCP S3 Connector.
pub struct S3Connector {
    base: Arc<BaseConnector>,
    config: Option<S3Config>,
    pub(crate) client: Option<S3Client>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    runtime: Option<ConnectorRuntime>,
}

impl S3Connector {
    /// Create a new S3 connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("s3"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            runtime: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = S3Config::from_params(&params)?;

        let client = S3Client::new_with_auth(config.auth.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?
            .with_base_url(&config.base_url);

        info!(auth = %config.auth.redacted_label(), "S3 connector configured");

        self.runtime = Some(fcp_sdk::migration::ConnectorRuntime::new(
            fcp_sdk::migration::ConnectorRuntimeConfig::default(),
        ));
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
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(config.auth.redacted_label());
            health["base_url"] = json!(config.base_url);
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
                message: format!("Base URL: {}", config.base_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "Base URL not set (not configured)".into(),
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
        let egress_target = self.config.as_ref().map_or("s3.amazonaws.com", |c| {
            c.base_url
                .strip_prefix("https://")
                .or_else(|| c.base_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .unwrap_or("s3.amazonaws.com")
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
                    message: "Direct keys mode – no proxy injection needed".into(),
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
                    json!({
                        "type": "object",
                        "required": ["deleted", "audit"],
                        "properties": {
                            "deleted": { "type": "boolean" },
                            "audit": { "type": "object" }
                        }
                    }),
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
                    "s3.create_bucket",
                    "Create a new S3 bucket",
                    json!({
                        "type": "object",
                        "required": ["bucket"],
                        "properties": {
                            "bucket": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["bucket", "created", "audit"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "created": { "type": "boolean" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "s3.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Provision a new bucket for controlled storage use.".into(),
                        common_mistakes: vec![
                            "Bucket names are globally unique in AWS S3.".into(),
                            "Creating buckets in the wrong region can break clients.".into(),
                        ],
                        examples: vec![r#"{"bucket": "project-logs-2026"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("s3.list_buckets"),
                            CapabilityId::from_static("s3.delete_bucket"),
                        ],
                    },
                ),
                op_info(
                    "s3.delete_bucket",
                    "Delete an empty S3 bucket",
                    json!({
                        "type": "object",
                        "required": ["bucket"],
                        "properties": {
                            "bucket": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["bucket", "deleted", "audit"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "deleted": { "type": "boolean" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "s3.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Remove an empty bucket that is no longer needed.".into(),
                        common_mistakes: vec![
                            "Delete all objects first or the request will fail.".into(),
                            "Verify no downstream workflows rely on this bucket.".into(),
                        ],
                        examples: vec![r#"{"bucket": "old-project-artifacts"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("s3.list_buckets"),
                            CapabilityId::from_static("s3.delete_object"),
                        ],
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
                    json!({
                        "type": "object",
                        "required": ["url", "audit"],
                        "properties": {
                            "url": { "type": "string" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "s3.read",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
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

        let execution_approval = Self::require_execution_approval(operation, &input, &params)?;

        match operation {
            "s3.put_object" => self.invoke_put_object(input).await,
            "s3.get_object" => self.invoke_get_object(input).await,
            "s3.delete_object" => {
                self.invoke_delete_object(input, execution_approval.as_ref())
                    .await
            }
            "s3.create_bucket" => {
                self.invoke_create_bucket(input, execution_approval.as_ref())
                    .await
            }
            "s3.delete_bucket" => {
                self.invoke_delete_bucket(input, execution_approval.as_ref())
                    .await
            }
            "s3.head_object" => self.invoke_head_object(input).await,
            "s3.list_objects" => self.invoke_list_objects(input).await,
            "s3.list_buckets" => self.invoke_list_buckets().await,
            "s3.copy_object" => self.invoke_copy_object(input).await,
            "s3.generate_presigned_url" => {
                self.invoke_generate_presigned_url(&input, execution_approval.as_ref())
            }
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    fn require_execution_approval(
        operation: &str,
        input: &serde_json::Value,
        params: &serde_json::Value,
    ) -> FcpResult<Option<ExecutionApprovalContext>> {
        if !requires_execution_approval(operation) {
            return Ok(None);
        }

        let approval_value = params
            .get("approval_token")
            .ok_or(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: format!(
                    "Operation '{operation}' requires an ApprovalToken with execution scope"
                ),
            })?;

        let approval: ApprovalToken =
            serde_json::from_value(approval_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid approval_token format: {e}"),
                }
            })?;

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        if !approval.is_valid(now_ms) {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token is expired or not yet valid".into(),
            });
        }

        let Execution(scope) = &approval.scope else {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token must use execution scope".into(),
            });
        };

        if scope.connector_id != "fcp.s3" {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token connector_id does not match fcp.s3".into(),
            });
        }

        if !operation_pattern_matches(&scope.method_pattern, operation) {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token execution scope does not allow this operation".into(),
            });
        }

        if scope.request_object_id.is_some() || scope.input_hash.is_some() {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token binds request_object_id/input_hash, unsupported in direct connector invocation".into(),
            });
        }

        if !scope.input_constraints.is_empty()
            && !scope
                .input_constraints
                .iter()
                .all(|constraint| input.pointer(&constraint.pointer) == Some(&constraint.expected))
        {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token input constraints do not match this invocation".into(),
            });
        }

        Ok(Some(ExecutionApprovalContext {
            token_id: approval.token_id,
        }))
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

    async fn invoke_delete_object(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        client
            .delete_object(bucket, key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({
            "deleted": true,
            "audit": dangerous_operation_audit("s3.delete_object", true, execution_approval),
        }))
    }

    async fn invoke_create_bucket(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let resp = client
            .create_bucket(bucket)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({
            "bucket": resp.bucket,
            "created": resp.created,
            "audit": dangerous_operation_audit("s3.create_bucket", true, execution_approval),
        }))
    }

    async fn invoke_delete_bucket(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let resp = client
            .delete_bucket(bucket)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({
            "bucket": resp.bucket,
            "deleted": resp.deleted,
            "audit": dangerous_operation_audit("s3.delete_bucket", true, execution_approval),
        }))
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
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(input, "bucket")?;
        let key = require_str(input, "key")?;
        let expires_in = input
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        let resp = client.generate_presigned_url(bucket, key, expires_in);
        Ok(json!({
            "url": resp.url,
            "audit": dangerous_operation_audit("s3.generate_presigned_url", false, execution_approval),
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("S3 connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
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

fn requires_execution_approval(operation: &str) -> bool {
    matches!(
        operation,
        "s3.delete_object" | "s3.create_bucket" | "s3.delete_bucket" | "s3.generate_presigned_url"
    )
}

fn operation_pattern_matches(pattern: &str, operation: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        operation.starts_with(prefix)
    } else {
        operation == pattern
    }
}

fn dangerous_operation_audit(
    operation: &str,
    side_effect: bool,
    execution_approval: Option<&ExecutionApprovalContext>,
) -> serde_json::Value {
    json!({
        "operation": operation,
        "dangerous": true,
        "side_effect": side_effect,
        "approval_token_id": execution_approval.map(|ctx| ctx.token_id.clone()),
        "timestamp": chrono::Utc::now().to_rfc3339(),
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
    let requires_approval = match safety_tier {
        SafetyTier::Risky => Some(ApprovalMode::Policy),
        SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden => {
            Some(ApprovalMode::ElevationToken)
        }
        SafetyTier::Safe => None,
    };

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
        requires_approval,
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
            "s3.get_object" | "s3.head_object" | "s3.list_objects" | "s3.list_buckets"
            | "s3.generate_presigned_url" => "s3.read",
            "s3.put_object" | "s3.create_bucket" | "s3.copy_object" => "s3.write",
            "s3.delete_object" | "s3.delete_bucket" => "s3.delete",
            _ => "s3.read",
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
        connector
            .handle_configure(json!({
                "access_key_id": "test_key",
                "secret_access_key": "test_secret",
                "region": "us-east-1",
                "base_url": "http://localhost:9999"
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
        assert!(op_ids.contains(&"s3.create_bucket"));
        assert!(op_ids.contains(&"s3.delete_bucket"));
        assert!(op_ids.contains(&"s3.head_object"));
        assert!(op_ids.contains(&"s3.list_objects"));
        assert!(op_ids.contains(&"s3.list_buckets"));
        assert!(op_ids.contains(&"s3.copy_object"));
        assert!(op_ids.contains(&"s3.generate_presigned_url"));
        assert_eq!(ops.len(), 10);
    }

    // ── Provisioning automation tests ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_keys() {
        let mut connector = S3Connector::new();
        let result = connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-west-2"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = S3Connector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "00000000-0000-0000-0000-000000000001"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth_modes() {
        let mut connector = S3Connector::new();
        let result = connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "credential_id": "00000000-0000-0000-0000-000000000001"
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
        let mut connector = S3Connector::new();
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
    async fn test_configure_rejects_partial_keys() {
        let mut connector = S3Connector::new();
        // Only access_key_id, no secret
        let result = connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("secret_access_key"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "secret",
                "region": "eu-west-1"
            }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert!(health["auth_mode"].as_str().unwrap().contains("keys:AKIA"));
        assert!(health["base_url"].as_str().is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = S3Connector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(
            checks
                .iter()
                .any(|c| c["name"] == "configuration" && c["status"] == "unhealthy")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "secret",
                "region": "us-east-1"
            }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|c| c["status"] == "healthy"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "credential_id": "00000000-0000-0000-0000-000000000001"
            }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert!(
            cred_check["message"]
                .as_str()
                .unwrap()
                .contains("Secretless")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = S3Connector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "credential_id": "00000000-0000-0000-0000-000000000001"
            }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_base_url() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "access_key_id": "test",
                "secret_access_key": "secret",
                "base_url": "http://localhost:9000"
            }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["base_url"], "http://localhost:9000");
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
