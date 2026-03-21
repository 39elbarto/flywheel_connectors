//! Zoom connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::ZoomClient;
use crate::types::{CreateMeetingRequest, UpdateMeetingRequest};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_MEETINGS_LIST: &str = "zoom.meetings.list";
const OP_MEETINGS_GET: &str = "zoom.meetings.get";
const OP_MEETINGS_CREATE: &str = "zoom.meetings.create";
const OP_MEETINGS_UPDATE: &str = "zoom.meetings.update";
const OP_MEETINGS_DELETE: &str = "zoom.meetings.delete";
const OP_USERS_LIST: &str = "zoom.users.list";
const OP_USERS_GET: &str = "zoom.users.get";
const OP_RECORDINGS_LIST: &str = "zoom.recordings.list";
const OP_WEBINARS_LIST: &str = "zoom.webinars.list";
const OP_HEALTH: &str = "zoom.health";

// Capability IDs
const CAP_MEETINGS_READ: &str = "zoom.meetings.read";
const CAP_MEETINGS_WRITE: &str = "zoom.meetings.write";
const CAP_USERS_READ: &str = "zoom.users.read";
const CAP_RECORDINGS_READ: &str = "zoom.recordings.read";
const CAP_WEBINARS_READ: &str = "zoom.webinars.read";

/// Zoom connector configuration.
#[derive(Clone, Deserialize)]
struct ZoomConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    account_id: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for ZoomConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoomConfig")
            .field("base_url", &self.base_url)
            .field("account_id", &"[REDACTED]")
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://api.zoom.us/v2".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

// Doctor types
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

/// Zoom connector state.
#[derive(Debug)]
pub struct ZoomConnector {
    base: BaseConnector,
    config: Option<ZoomConfig>,
    client: Option<ZoomClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl ZoomConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.zoom")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(config) = &self.config {
            let scheme = if config.base_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL ({scheme}): {}", config.base_url)),
                critical: false,
            });

            let allowed_hosts = ["api.zoom.us"];
            let host_part = config
                .base_url
                .split("://")
                .nth(1)
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            let host_ok = host_part == "localhost"
                || host_part == "127.0.0.1"
                || allowed_hosts.contains(&host_part);
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Base URL matches allowed host (api.zoom.us)".into()
                } else {
                    format!("Base URL {} does not match allowed hosts", config.base_url)
                }),
                critical: true,
            });

            let secretless = self.client.as_ref().is_some_and(|c| c.is_secretless());
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !secretless,
                message: Some(if secretless {
                    "Credential injection required via egress proxy".into()
                } else {
                    "Server-to-Server OAuth credentials configured".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for ZoomConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_MEETINGS_LIST),
            summary: "List meetings for a user".into(),
            description: Some("Lists all meetings scheduled by a user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_id": { "type": "string", "description": "User ID or email (default: 'me')", "default": "me" },
                    "page_size": { "type": "integer", "description": "Number of records per page (max 300)", "default": 30 },
                    "next_page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "meetings": { "type": "array" },
                    "total_records": { "type": "integer" },
                    "next_page_token": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MEETINGS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When listing meetings scheduled by a Zoom user".into(),
                common_mistakes: vec![
                    "Use 'me' as user_id for the authenticated user".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_MEETINGS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MEETINGS_GET),
            summary: "Get a meeting by ID".into(),
            description: Some("Retrieves details of a specific meeting".into()),
            input_schema: json!({
                "type": "object",
                "required": ["meeting_id"],
                "properties": {
                    "meeting_id": { "type": "string", "description": "The meeting ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "integer" },
                    "topic": { "type": "string" },
                    "start_time": { "type": "string" },
                    "duration": { "type": "integer" },
                    "join_url": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MEETINGS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When retrieving details of a specific Zoom meeting".into(),
                common_mistakes: vec![
                    "Meeting ID must be a numeric string".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_MEETINGS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MEETINGS_CREATE),
            summary: "Create a new meeting".into(),
            description: Some("Creates a new meeting for a user".into()),
            input_schema: json!({
                "type": "object",
                "required": ["topic"],
                "properties": {
                    "user_id": { "type": "string", "default": "me" },
                    "topic": { "type": "string" },
                    "type": { "type": "integer", "description": "1=instant, 2=scheduled, 3=recurring no time, 8=recurring fixed" },
                    "start_time": { "type": "string", "format": "date-time" },
                    "duration": { "type": "integer", "description": "Duration in minutes" },
                    "timezone": { "type": "string" },
                    "agenda": { "type": "string" },
                    "password": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "integer" },
                    "join_url": { "type": "string" },
                    "start_url": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MEETINGS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When creating a new Zoom meeting".into(),
                common_mistakes: vec![
                    "start_time must be in ISO 8601 format".into(),
                    "For instant meetings use type=1; for scheduled use type=2".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MEETINGS_UPDATE),
            summary: "Update an existing meeting".into(),
            description: Some("Updates the details of a scheduled meeting".into()),
            input_schema: json!({
                "type": "object",
                "required": ["meeting_id"],
                "properties": {
                    "meeting_id": { "type": "string" },
                    "topic": { "type": "string" },
                    "type": { "type": "integer" },
                    "start_time": { "type": "string", "format": "date-time" },
                    "duration": { "type": "integer" },
                    "timezone": { "type": "string" },
                    "agenda": { "type": "string" },
                    "password": { "type": "string" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MEETINGS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When updating an existing Zoom meeting".into(),
                common_mistakes: vec![
                    "Only provided fields are updated; omitted fields keep their current values".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_MEETINGS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MEETINGS_DELETE),
            summary: "Delete a meeting".into(),
            description: Some("Permanently deletes a meeting".into()),
            input_schema: json!({
                "type": "object",
                "required": ["meeting_id"],
                "properties": {
                    "meeting_id": { "type": "string", "description": "The meeting ID to delete" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MEETINGS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When permanently deleting a Zoom meeting".into(),
                common_mistakes: vec![
                    "This action is irreversible".into(),
                    "Deleting a recurring meeting deletes all occurrences".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USERS_LIST),
            summary: "List users in the account".into(),
            description: Some("Lists all users in the Zoom account".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page_size": { "type": "integer", "default": 30 },
                    "next_page_token": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "users": { "type": "array" },
                    "total_records": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When listing all users in the Zoom account".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_USERS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USERS_GET),
            summary: "Get a user by ID".into(),
            description: Some("Retrieves details of a specific Zoom user".into()),
            input_schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "User ID or email" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "email": { "type": "string" },
                    "first_name": { "type": "string" },
                    "last_name": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When retrieving details of a specific Zoom user".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_USERS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RECORDINGS_LIST),
            summary: "List cloud recordings for a user".into(),
            description: Some("Lists all cloud recordings for a user within a date range".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_id": { "type": "string", "default": "me" },
                    "from": { "type": "string", "format": "date", "description": "Start date (YYYY-MM-DD)" },
                    "to": { "type": "string", "format": "date", "description": "End date (YYYY-MM-DD)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "meetings": { "type": "array" },
                    "total_records": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_RECORDINGS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When listing cloud recordings for a Zoom user".into(),
                common_mistakes: vec![
                    "Date range maximum is 30 days".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WEBINARS_LIST),
            summary: "List webinars for a user".into(),
            description: Some("Lists all webinars for a user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_id": { "type": "string", "default": "me" },
                    "page_size": { "type": "integer", "default": 30 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "webinars": { "type": "array" },
                    "total_records": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WEBINARS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When listing webinars for a Zoom user".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check Zoom API connectivity".into(),
            description: Some("Validates API reachability and authentication".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When checking if the Zoom API is reachable and credentials are valid".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

#[async_trait]
impl FcpConnector for ZoomConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: ZoomConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Zoom config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = ZoomClient::new(
            &config.base_url,
            &config.account_id,
            &config.client_id,
            &config.client_secret,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Zoom client: {e}"),
        })?;

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
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
        let mut snapshot = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        if client.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with empty credentials; egress proxy injection required",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(err) => {
                if err.is_retryable() {
                    Ok(SelfCheckReport::degraded(
                        "self_check_retryable",
                        err.to_string(),
                    ))
                } else {
                    Ok(SelfCheckReport::failed(
                        "self_check_failed",
                        err.to_string(),
                    ))
                }
            }
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

impl ZoomConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_MEETINGS_LIST | OP_MEETINGS_GET => CapabilityId::from_static(CAP_MEETINGS_READ),
            OP_MEETINGS_CREATE | OP_MEETINGS_UPDATE | OP_MEETINGS_DELETE => {
                CapabilityId::from_static(CAP_MEETINGS_WRITE)
            }
            OP_USERS_LIST | OP_USERS_GET | OP_HEALTH => {
                CapabilityId::from_static(CAP_USERS_READ)
            }
            OP_RECORDINGS_LIST => CapabilityId::from_static(CAP_RECORDINGS_READ),
            OP_WEBINARS_LIST => CapabilityId::from_static(CAP_WEBINARS_READ),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Zoom client missing after configure".into(),
        })?;

        let output = match operation {
            OP_MEETINGS_LIST => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("me");
                let page_size = req
                    .input
                    .get("page_size")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let next_page_token = req
                    .input
                    .get("next_page_token")
                    .and_then(|v| v.as_str());

                let list = client
                    .list_meetings(runtime, user_id, page_size, next_page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_MEETINGS_GET => {
                let meeting_id = req
                    .input
                    .get("meeting_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'meeting_id' field".into(),
                    })?;
                let meeting = client
                    .get_meeting(runtime, meeting_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(meeting).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_MEETINGS_CREATE => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("me");
                let topic = req
                    .input
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'topic' field".into(),
                    })?;

                let create_req = CreateMeetingRequest {
                    topic: topic.to_string(),
                    meeting_type: req.input.get("type").and_then(|v| v.as_u64()).map(|v| v as u8),
                    start_time: req.input.get("start_time").and_then(|v| v.as_str()).map(String::from),
                    duration: req.input.get("duration").and_then(|v| v.as_u64()).map(|v| v as u32),
                    timezone: req.input.get("timezone").and_then(|v| v.as_str()).map(String::from),
                    agenda: req.input.get("agenda").and_then(|v| v.as_str()).map(String::from),
                    password: req.input.get("password").and_then(|v| v.as_str()).map(String::from),
                };

                let meeting = client
                    .create_meeting(runtime, user_id, &create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(meeting).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_MEETINGS_UPDATE => {
                let meeting_id = req
                    .input
                    .get("meeting_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'meeting_id' field".into(),
                    })?;

                let update_req = UpdateMeetingRequest {
                    topic: req.input.get("topic").and_then(|v| v.as_str()).map(String::from),
                    meeting_type: req.input.get("type").and_then(|v| v.as_u64()).map(|v| v as u8),
                    start_time: req.input.get("start_time").and_then(|v| v.as_str()).map(String::from),
                    duration: req.input.get("duration").and_then(|v| v.as_u64()).map(|v| v as u32),
                    timezone: req.input.get("timezone").and_then(|v| v.as_str()).map(String::from),
                    agenda: req.input.get("agenda").and_then(|v| v.as_str()).map(String::from),
                    password: req.input.get("password").and_then(|v| v.as_str()).map(String::from),
                };

                client
                    .update_meeting(runtime, meeting_id, &update_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "status": "updated" })
            }
            OP_MEETINGS_DELETE => {
                let meeting_id = req
                    .input
                    .get("meeting_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'meeting_id' field".into(),
                    })?;

                client
                    .delete_meeting(runtime, meeting_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "status": "deleted" })
            }
            OP_USERS_LIST => {
                let page_size = req
                    .input
                    .get("page_size")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let next_page_token = req
                    .input
                    .get("next_page_token")
                    .and_then(|v| v.as_str());

                let list = client
                    .list_users(runtime, page_size, next_page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_USERS_GET => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'user_id' field".into(),
                    })?;
                let user = client
                    .get_user(runtime, user_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(user).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_RECORDINGS_LIST => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("me");
                let from = req.input.get("from").and_then(|v| v.as_str());
                let to = req.input.get("to").and_then(|v| v.as_str());

                let list = client
                    .list_recordings(runtime, user_id, from, to)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_WEBINARS_LIST => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("me");
                let page_size = req
                    .input
                    .get("page_size")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);

                let list = client
                    .list_webinars(runtime, user_id, page_size)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_HEALTH => {
                client
                    .health_check()
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "status": "ok" })
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

    fn all_caps() -> Vec<CapabilityId> {
        vec![
            CapabilityId::from_static(CAP_MEETINGS_READ),
            CapabilityId::from_static(CAP_MEETINGS_WRITE),
            CapabilityId::from_static(CAP_USERS_READ),
            CapabilityId::from_static(CAP_RECORDINGS_READ),
            CapabilityId::from_static(CAP_WEBINARS_READ),
        ]
    }

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: all_caps(),
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    fn test_config() -> serde_json::Value {
        json!({
            "account_id": "acc_123",
            "client_id": "cid_test",
            "client_secret": "csec_test"
        })
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = ZoomConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = ZoomConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = ZoomConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = ZoomConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = ZoomConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = ZoomConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = ZoomConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_MEETINGS_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = ZoomConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 10);
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_MEETINGS_LIST));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_MEETINGS_GET));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_MEETINGS_CREATE));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_MEETINGS_UPDATE));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_MEETINGS_DELETE));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_USERS_LIST));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_USERS_GET));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_RECORDINGS_LIST));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_WEBINARS_LIST));
        assert!(intro.operations.iter().any(|op| op.id.as_str() == OP_HEALTH));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "zoom.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = ZoomConnector::new();
        let req = base_invoke(connector.id(), OP_MEETINGS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector.invoke(base_invoke(connector.id(), OP_MEETINGS_LIST)).await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_meetings_get_missing_id() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_MEETINGS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_meetings_create_missing_topic() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_MEETINGS_CREATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_meetings_update_missing_id() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_MEETINGS_UPDATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_meetings_delete_missing_id() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_MEETINGS_DELETE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_users_get_missing_id() {
        let mut connector = ZoomConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_USERS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_meetings_list_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_MEETINGS_LIST).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
        assert_eq!(op.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_meetings_create_is_risky() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_MEETINGS_CREATE).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_meetings_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_MEETINGS_DELETE).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = ZoomConnector::manifest_hash();
        let hash2 = ZoomConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = ZoomConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = ZoomConfig {
            base_url: default_base_url(),
            account_id: "secret_account".into(),
            client_id: "secret_client".into(),
            client_secret: "secret_value".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_account"));
        assert!(!debug_output.contains("secret_client"));
        assert!(!debug_output.contains("secret_value"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_health_op_is_safe_with_strict_idempotency() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_default_connector() {
        let connector = ZoomConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.zoom");
    }

    #[test]
    fn test_capability_mapping() {
        let ops = operations_info();
        let meetings_list = ops.iter().find(|op| op.id.as_str() == OP_MEETINGS_LIST).unwrap();
        assert_eq!(meetings_list.capability.as_str(), CAP_MEETINGS_READ);

        let meetings_create = ops.iter().find(|op| op.id.as_str() == OP_MEETINGS_CREATE).unwrap();
        assert_eq!(meetings_create.capability.as_str(), CAP_MEETINGS_WRITE);

        let users_list = ops.iter().find(|op| op.id.as_str() == OP_USERS_LIST).unwrap();
        assert_eq!(users_list.capability.as_str(), CAP_USERS_READ);

        let recordings = ops.iter().find(|op| op.id.as_str() == OP_RECORDINGS_LIST).unwrap();
        assert_eq!(recordings.capability.as_str(), CAP_RECORDINGS_READ);

        let webinars = ops.iter().find(|op| op.id.as_str() == OP_WEBINARS_LIST).unwrap();
        assert_eq!(webinars.capability.as_str(), CAP_WEBINARS_READ);
    }
}
