//! AWS connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::AwsClient;
use crate::types::AwsAuth;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// ── Operation IDs ──
const OP_S3_LIST_BUCKETS: &str = "aws.s3.list_buckets";
const OP_S3_LIST_OBJECTS: &str = "aws.s3.list_objects";
const OP_S3_GET_OBJECT: &str = "aws.s3.get_object";
const OP_S3_PUT_OBJECT: &str = "aws.s3.put_object";
const OP_S3_DELETE_OBJECT: &str = "aws.s3.delete_object";
const OP_EC2_DESCRIBE: &str = "aws.ec2.describe_instances";
const OP_EC2_START: &str = "aws.ec2.start_instance";
const OP_EC2_STOP: &str = "aws.ec2.stop_instance";
const OP_EC2_TERMINATE: &str = "aws.ec2.terminate_instance";
const OP_LAMBDA_LIST: &str = "aws.lambda.list_functions";
const OP_LAMBDA_INVOKE: &str = "aws.lambda.invoke";
const OP_STS_IDENTITY: &str = "aws.sts.get_caller_identity";
const OP_HEALTH: &str = "aws.health";

// ── Capability IDs ──
const CAP_S3_READ: &str = "aws.s3.read";
const CAP_S3_WRITE: &str = "aws.s3.write";
const CAP_EC2_READ: &str = "aws.ec2.read";
const CAP_EC2_WRITE: &str = "aws.ec2.write";
const CAP_LAMBDA_READ: &str = "aws.lambda.read";
const CAP_LAMBDA_WRITE: &str = "aws.lambda.write";
const CAP_IAM_READ: &str = "aws.iam.read";

#[derive(Clone, serde::Deserialize)]
pub struct AwsConfig {
    pub region: String,
    #[serde(flatten)]
    pub auth: AwsAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Override S3 endpoint (e.g. for LocalStack).
    #[serde(default)]
    pub s3_base_url: Option<String>,
    /// Override EC2 endpoint.
    #[serde(default)]
    pub ec2_base_url: Option<String>,
    /// Override Lambda endpoint.
    #[serde(default)]
    pub lambda_base_url: Option<String>,
    /// Override STS endpoint.
    #[serde(default)]
    pub sts_base_url: Option<String>,
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for AwsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsConfig")
            .field("region", &self.region)
            .field("auth", &self.auth)
            .finish()
    }
}

impl AwsConfig {
    fn validate(&self) -> Result<(), String> {
        if self.region.is_empty() {
            return Err("region is required".into());
        }
        if self.auth.access_key_id.is_empty() {
            return Err("access_key_id is required".into());
        }
        if self.auth.secret_access_key.is_empty() {
            return Err("secret_access_key is required".into());
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let config: Self = serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Invalid configuration: {e}"),
        })?;
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}
impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
pub struct AwsConnector {
    base: BaseConnector,
    config: Option<AwsConfig>,
    client: Option<AwsClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl AwsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.aws")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut h = Sha256::new();
        h.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                None
            } else {
                Some("Client not initialized".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.runtime.is_some(),
            message: if self.runtime.is_some() {
                None
            } else {
                Some("Runtime not initialized".into())
            },
            critical: true,
        });
        if let Some(cfg) = &self.config {
            checks.push(DoctorCheck {
                name: "region".into(),
                passed: !cfg.region.is_empty(),
                message: Some(format!("Region: {}", cfg.region)),
                critical: false,
            });
            if let Some(client) = &self.client {
                checks.push(DoctorCheck {
                    name: "credential_mode".into(),
                    passed: true,
                    message: Some(if client.is_secretless() {
                        "Secretless".into()
                    } else {
                        "Direct".into()
                    }),
                    critical: false,
                });
            }
        }
        DoctorResult::from_checks(checks)
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value = input
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Missing: {key}"),
            })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }
}

impl Default for AwsConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    let hint = |when: &str,
                mistakes: Vec<String>,
                examples: Vec<String>,
                related: Vec<&'static str>|
     -> AgentHint {
        AgentHint {
            when_to_use: when.into(),
            common_mistakes: mistakes,
            examples,
            related: related.into_iter().map(CapabilityId::from_static).collect(),
        }
    };
    vec![
        // ── S3 operations ──
        OperationInfo {
            id: OperationId::from_static(OP_S3_LIST_BUCKETS),
            summary: "List all S3 buckets".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_S3_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List all S3 buckets in the account",
                vec![],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_S3_LIST_OBJECTS),
            summary: "List objects in an S3 bucket".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_S3_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List objects/keys in a specific S3 bucket",
                vec!["Use bucket name not ARN".into()],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_S3_GET_OBJECT),
            summary: "Get an object from S3".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","key"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_S3_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Download/read an S3 object",
                vec!["Key is the full path including prefixes".into()],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_S3_PUT_OBJECT),
            summary: "Upload an object to S3".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","key","body"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_S3_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Upload/create an S3 object",
                vec!["Overwrites existing objects with same key".into()],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_S3_DELETE_OBJECT),
            summary: "Delete an object from S3".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","key"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_S3_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete an S3 object (irreversible without versioning)",
                vec!["Verify key before deleting".into()],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        // ── EC2 operations ──
        OperationInfo {
            id: OperationId::from_static(OP_EC2_DESCRIBE),
            summary: "Describe EC2 instances".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_EC2_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("List all EC2 instances", vec![], vec![], vec![CAP_EC2_READ]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_EC2_START),
            summary: "Start an EC2 instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["instance_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_EC2_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Start a stopped EC2 instance",
                vec!["Instance must be in stopped state".into()],
                vec![],
                vec![CAP_EC2_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_EC2_STOP),
            summary: "Stop an EC2 instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["instance_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_EC2_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Stop a running EC2 instance",
                vec!["May cause downtime".into()],
                vec![],
                vec![CAP_EC2_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_EC2_TERMINATE),
            summary: "Terminate an EC2 instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["instance_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_EC2_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently terminate an EC2 instance (irreversible, data loss)",
                vec!["Cannot be undone, all data on instance volumes lost".into()],
                vec![],
                vec![CAP_EC2_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        // ── Lambda operations ──
        OperationInfo {
            id: OperationId::from_static(OP_LAMBDA_LIST),
            summary: "List Lambda functions".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_LAMBDA_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List all Lambda functions",
                vec![],
                vec![],
                vec![CAP_LAMBDA_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_LAMBDA_INVOKE),
            summary: "Invoke a Lambda function".into(),
            description: None,
            input_schema: json!({"type":"object","required":["function_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_LAMBDA_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: hint(
                "Execute a Lambda function with a payload",
                vec!["Function must exist and be in Active state".into()],
                vec![],
                vec![CAP_LAMBDA_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        // ── STS operations ──
        OperationInfo {
            id: OperationId::from_static(OP_STS_IDENTITY),
            summary: "Get caller identity".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_IAM_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Check who the current credentials belong to",
                vec![],
                vec![],
                vec![],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        // ── Health ──
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check AWS API health".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_IAM_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Check AWS credentials and API health",
                vec![],
                vec![],
                vec![],
            ),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[async_trait]
impl FcpConnector for AwsConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = AwsConfig::from_value(config)?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = AwsClient::new(
            cfg.auth.clone(),
            &cfg.region,
            cfg.retry.clone(),
            cfg.s3_base_url.clone(),
            cfg.ec2_base_url.clone(),
            cfg.lambda_base_url.clone(),
            cfg.sts_base_url.clone(),
        )
        .await
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let caps = req
            .capabilities_requested
            .into_iter()
            .map(|c| CapabilityGrant {
                capability: c,
                operation: None,
            })
            .collect();
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: caps,
            session_id: SessionId::new(),
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
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snap = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snap.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Not configured",
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(SelfCheckReport::degraded("no_runtime", "No runtime"));
        };
        match client.health_check(runtime).await {
            Ok(h) if h.authenticated => Ok(SelfCheckReport::ok()),
            Ok(_) => Ok(SelfCheckReport::degraded(
                "auth_failed",
                "Authentication check failed",
            )),
            Err(e) if e.is_retryable() => Ok(SelfCheckReport::degraded(
                "self_check_retryable",
                e.to_string(),
            )),
            Err(e) => Ok(SelfCheckReport::failed("self_check_failed", e.to_string())),
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.runtime = None;
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }
    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl AwsConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_S3_LIST_BUCKETS | OP_S3_LIST_OBJECTS | OP_S3_GET_OBJECT => {
                    CapabilityId::from_static(CAP_S3_READ)
                }
                OP_S3_PUT_OBJECT | OP_S3_DELETE_OBJECT => CapabilityId::from_static(CAP_S3_WRITE),
                OP_EC2_DESCRIBE => CapabilityId::from_static(CAP_EC2_READ),
                OP_EC2_START | OP_EC2_STOP | OP_EC2_TERMINATE => {
                    CapabilityId::from_static(CAP_EC2_WRITE)
                }
                OP_LAMBDA_LIST => CapabilityId::from_static(CAP_LAMBDA_READ),
                OP_LAMBDA_INVOKE => CapabilityId::from_static(CAP_LAMBDA_WRITE),
                OP_STS_IDENTITY | OP_HEALTH => CapabilityId::from_static(CAP_IAM_READ),
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            verifier.verify(&req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing AWS client".into(),
        })?;

        let output = match operation {
            OP_S3_LIST_BUCKETS => {
                let buckets = client
                    .s3_list_buckets(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&buckets).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_S3_LIST_OBJECTS => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let prefix = req.input.get("prefix").and_then(|v| v.as_str());
                let objects = client
                    .s3_list_objects(runtime, bucket, prefix)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&objects).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_S3_GET_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let key = Self::require_str(&req.input, "key")?;
                let obj = client
                    .s3_get_object(runtime, bucket, key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&obj).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_S3_PUT_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let key = Self::require_str(&req.input, "key")?;
                let body = Self::require_str(&req.input, "body")?;
                let content_type = req.input.get("content_type").and_then(|v| v.as_str());
                let r = client
                    .s3_put_object(runtime, bucket, key, body, content_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_S3_DELETE_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let key = Self::require_str(&req.input, "key")?;
                let r = client
                    .s3_delete_object(runtime, bucket, key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_EC2_DESCRIBE => {
                let instances = client
                    .ec2_describe_instances(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&instances).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_EC2_START => {
                let instance_id = Self::require_str(&req.input, "instance_id")?;
                let r = client
                    .ec2_start_instance(runtime, instance_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_EC2_STOP => {
                let instance_id = Self::require_str(&req.input, "instance_id")?;
                let r = client
                    .ec2_stop_instance(runtime, instance_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_EC2_TERMINATE => {
                let instance_id = Self::require_str(&req.input, "instance_id")?;
                let r = client
                    .ec2_terminate_instance(runtime, instance_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_LAMBDA_LIST => {
                let functions = client
                    .lambda_list_functions(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&functions).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_LAMBDA_INVOKE => {
                let function_name = Self::require_str(&req.input, "function_name")?;
                let payload = req
                    .input
                    .get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let r = client
                    .lambda_invoke(runtime, function_name, &payload)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_STS_IDENTITY => {
                let identity = client
                    .sts_get_caller_identity(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&identity).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let h = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"authenticated": h.authenticated, "account": h.account, "arn": h.arn})
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{CapabilityToken, RequestId, ZoneId};

    fn tc() -> serde_json::Value {
        json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1"
        })
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_S3_READ),
                CapabilityId::from_static(CAP_S3_WRITE),
                CapabilityId::from_static(CAP_EC2_READ),
                CapabilityId::from_static(CAP_EC2_WRITE),
                CapabilityId::from_static(CAP_LAMBDA_READ),
                CapabilityId::from_static(CAP_IAM_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn invoke_req(op: &'static str, input: serde_json::Value) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("r1"),
            connector_id: ConnectorId::from_static("fcp.aws"),
            operation: OperationId::from_static(op),
            zone_id: ZoneId::work(),
            input,
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    #[test]
    fn new_ok() {
        assert!(AwsConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(AwsConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(AwsConnector::manifest_hash(), AwsConnector::manifest_hash());
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_empty_region() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "k",
                    "secret_access_key": "s",
                    "region": ""
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_empty_access_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "",
                    "secret_access_key": "s",
                    "region": "us-east-1"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_empty_secret_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "k",
                    "secret_access_key": "",
                    "region": "us-east-1"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_bad_json() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn doctor_unconfigured() {
        assert!(!AwsConnector::new().doctor().passed);
    }

    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .passed
        );
    }

    #[test]
    fn introspect_ops_count() {
        assert_eq!(AwsConnector::new().introspect().operations.len(), 13);
    }

    #[test]
    fn ops_all_have_hints() {
        for op in operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{}", op.id);
        }
    }

    #[test]
    fn dangerous_ops_need_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Dangerous {
                assert!(op.requires_approval.is_some(), "{}", op.id);
            }
        }
    }

    #[test]
    fn safe_ops_no_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Safe {
                assert!(op.requires_approval.is_none(), "{}", op.id);
            }
        }
    }

    #[test]
    fn invoke_unknown() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("aws.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_bucket() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_S3_LIST_OBJECTS, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_S3_GET_OBJECT, json!({"bucket": "b"})))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_instance_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_EC2_START, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_function_name() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_LAMBDA_INVOKE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            AwsConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.aws"),
                    OperationId::from_static(OP_S3_LIST_BUCKETS),
                    ZoneId::work(),
                    json!({}),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .unwrap()
        .unwrap();
        assert!(r.would_succeed);
    }

    #[test]
    fn subscribe_unsupported() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                AwsConnector::new()
                    .subscribe(SubscribeRequest {
                        r#type: "subscribe".into(),
                        id: RequestId::new("sub1"),
                        topics: vec![],
                        since: None,
                        max_events_per_sec: None,
                        batch_ms: None,
                        window_size: None,
                        capability_token: None,
                    })
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn shutdown_ok() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 10_000,
                drain: false,
                reason: None,
            })
            .await
            .unwrap();
        })
        .unwrap();
    }

    #[test]
    fn handshake_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req()).await.unwrap()
        })
        .unwrap();
        assert_eq!(r.status, "accepted");
        assert_eq!(r.capabilities_granted.len(), 6);
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            AwsConnector::require_str(&json!({"k":"v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(AwsConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(AwsConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(AwsConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h =
            fcp_async_core::runtime::block_on_sync(async { AwsConnector::new().health().await })
                .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }

    #[test]
    fn session_token_config() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "k",
                    "secret_access_key": "s",
                    "region": "us-east-1",
                    "session_token": "tok"
                }))
                .await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn custom_timeout_config() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "k",
                    "secret_access_key": "s",
                    "region": "us-west-2",
                    "request_timeout_ms": 60000
                }))
                .await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn connector_id_is_fcp_aws() {
        let c = AwsConnector::new();
        assert_eq!(c.id().as_str(), "fcp.aws");
    }

    #[test]
    fn ops_s3_read_capability() {
        let ops = operations_info();
        let s3_reads: Vec<_> = ops
            .iter()
            .filter(|op| op.capability.as_str() == CAP_S3_READ)
            .collect();
        assert_eq!(s3_reads.len(), 3);
        for op in &s3_reads {
            assert_eq!(op.safety_tier, SafetyTier::Safe);
        }
    }

    #[test]
    fn ops_ec2_write_has_correct_risk() {
        let ops = operations_info();
        let ec2_start = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EC2_START)
            .unwrap();
        assert_eq!(ec2_start.risk_level, RiskLevel::Medium);
        assert_eq!(ec2_start.safety_tier, SafetyTier::Risky);

        let ec2_terminate = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EC2_TERMINATE)
            .unwrap();
        assert_eq!(ec2_terminate.risk_level, RiskLevel::Critical);
        assert_eq!(ec2_terminate.safety_tier, SafetyTier::Dangerous);
    }

    #[test]
    fn ops_lambda_invoke_best_effort() {
        let ops = operations_info();
        let lambda_invoke = ops
            .iter()
            .find(|op| op.id.as_str() == OP_LAMBDA_INVOKE)
            .unwrap();
        assert_eq!(lambda_invoke.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn invoke_before_handshake_fails() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            // No handshake
            c.invoke(invoke_req(OP_S3_LIST_BUCKETS, json!({}))).await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn invoke_before_configure_fails() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let c = AwsConnector::new();
            c.invoke(invoke_req(OP_S3_LIST_BUCKETS, json!({}))).await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn doctor_check_names() {
        let d = AwsConnector::new().doctor();
        let names: Vec<_> = d.checks.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"configuration"));
        assert!(names.contains(&"client"));
        assert!(names.contains(&"runtime"));
    }

    #[test]
    fn doctor_configured_has_region_check() {
        let d = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.doctor()
        })
        .unwrap();
        let names: Vec<_> = d.checks.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"region"));
        assert!(names.contains(&"credential_mode"));
    }

    #[test]
    fn event_caps_no_streaming() {
        let intro = AwsConnector::new().introspect();
        let ec = intro.event_caps.unwrap();
        assert!(!ec.streaming);
        assert!(!ec.replay);
        assert!(!ec.requires_ack);
    }

    #[test]
    fn config_debug_redacts() {
        let cfg = AwsConfig::from_value(tc()).unwrap();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!debug.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn self_check_unconfigured() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            AwsConnector::new().self_check().await
        })
        .unwrap()
        .unwrap();
        assert!(r.status != fcp_core::SelfCheckStatus::Ok);
    }

    #[test]
    fn invoke_s3_put_missing_body() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(
                    OP_S3_PUT_OBJECT,
                    json!({"bucket": "b", "key": "k"}),
                ))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_s3_delete_missing_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_S3_DELETE_OBJECT, json!({"bucket": "b"})))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_ec2_stop_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_EC2_STOP, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_ec2_terminate_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_EC2_TERMINATE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }
}
