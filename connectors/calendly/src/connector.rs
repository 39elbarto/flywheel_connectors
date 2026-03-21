//! Calendly connector implementation.

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

use crate::client::CalendlyClient;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_EVENTS_LIST: &str = "calendly.events.list";
const OP_EVENTS_GET: &str = "calendly.events.get";
const OP_EVENT_TYPES_LIST: &str = "calendly.event_types.list";
const OP_INVITEES_LIST: &str = "calendly.invitees.list";
const OP_SCHEDULING_LINKS_CREATE: &str = "calendly.scheduling_links.create";
const OP_EVENTS_CANCEL: &str = "calendly.events.cancel";
const OP_USER_GET: &str = "calendly.user.get";
const OP_AVAILABILITY_LIST: &str = "calendly.availability.list";
const OP_HEALTH: &str = "calendly.health";

// Capability IDs
const CAP_EVENTS_READ: &str = "calendly.events.read";
const CAP_EVENTS_WRITE: &str = "calendly.events.write";
const CAP_SCHEDULING_READ: &str = "calendly.scheduling.read";
const CAP_SCHEDULING_WRITE: &str = "calendly.scheduling.write";
const CAP_USER_READ: &str = "calendly.user.read";

/// Calendly connector configuration.
#[derive(Clone, Deserialize)]
struct CalendlyConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for CalendlyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CalendlyConfig")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://api.calendly.com".into()
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

/// Calendly connector state.
#[derive(Debug)]
pub struct CalendlyConnector {
    base: BaseConnector,
    config: Option<CalendlyConfig>,
    client: Option<CalendlyClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl CalendlyConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.calendly")),
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

            let allowed_hosts = ["api.calendly.com"];
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
                    "Base URL matches allowed host (api.calendly.com)".into()
                } else {
                    format!(
                        "Base URL {} does not match allowed hosts",
                        config.base_url
                    )
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
                    "Personal access token configured".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for CalendlyConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_EVENTS_LIST),
            summary: "List scheduled events".into(),
            description: Some("Lists scheduled events for the authenticated user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_uri": { "type": "string", "description": "User URI (defaults to authenticated user)" },
                    "count": { "type": "integer", "description": "Number of results per page (max 100)", "default": 20 },
                    "page_token": { "type": "string", "description": "Pagination token" },
                    "status": { "type": "string", "enum": ["active", "canceled"], "description": "Filter by event status" },
                    "min_start_time": { "type": "string", "description": "ISO 8601 min start time" },
                    "max_start_time": { "type": "string", "description": "ISO 8601 max start time" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "collection": { "type": "array" },
                    "pagination": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list scheduled events for a user or organization".into(),
                common_mistakes: vec![
                    "user_uri must be a full Calendly URI, not just a UUID".into(),
                    "Dates must be in ISO 8601 format".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_EVENTS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EVENTS_GET),
            summary: "Get a single event".into(),
            description: Some("Retrieves details about a specific scheduled event".into()),
            input_schema: json!({
                "type": "object",
                "required": ["event_uuid"],
                "properties": {
                    "event_uuid": { "type": "string", "description": "Event UUID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "resource": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific scheduled event".into(),
                common_mistakes: vec![
                    "Use the event UUID, not the full URI".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_EVENTS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EVENT_TYPES_LIST),
            summary: "List event types".into(),
            description: Some("Lists available event types for the authenticated user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_uri": { "type": "string", "description": "User URI (defaults to authenticated user)" },
                    "count": { "type": "integer", "description": "Number of results per page" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "collection": { "type": "array" },
                    "pagination": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to see available event types for scheduling".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SCHEDULING_LINKS_CREATE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INVITEES_LIST),
            summary: "List event invitees".into(),
            description: Some("Lists invitees for a specific scheduled event".into()),
            input_schema: json!({
                "type": "object",
                "required": ["event_uuid"],
                "properties": {
                    "event_uuid": { "type": "string", "description": "Event UUID" },
                    "count": { "type": "integer", "description": "Number of results per page" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "collection": { "type": "array" },
                    "pagination": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to see who is invited to a scheduled event".into(),
                common_mistakes: vec![
                    "Use the event UUID, not the full URI".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_EVENTS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SCHEDULING_LINKS_CREATE),
            summary: "Create a scheduling link".into(),
            description: Some("Creates a shareable single-use or multi-use scheduling link".into()),
            input_schema: json!({
                "type": "object",
                "required": ["owner_uri", "owner_type"],
                "properties": {
                    "owner_uri": { "type": "string", "description": "Event type URI that owns the link" },
                    "owner_type": { "type": "string", "enum": ["EventType"], "description": "Owner type" },
                    "max_event_count": { "type": "integer", "description": "Max bookings (1 for single-use)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "resource": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SCHEDULING_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to create a shareable scheduling link for an event type".into(),
                common_mistakes: vec![
                    "owner_uri must be a full Calendly event type URI".into(),
                    "owner_type must be 'EventType'".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_EVENT_TYPES_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EVENTS_CANCEL),
            summary: "Cancel a scheduled event".into(),
            description: Some("Cancels a scheduled event with an optional reason".into()),
            input_schema: json!({
                "type": "object",
                "required": ["event_uuid"],
                "properties": {
                    "event_uuid": { "type": "string", "description": "Event UUID to cancel" },
                    "reason": { "type": "string", "description": "Cancellation reason" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to cancel a scheduled event".into(),
                common_mistakes: vec![
                    "Cancelled events cannot be uncancelled".into(),
                    "This sends cancellation notifications to all invitees".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_EVENTS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USER_GET),
            summary: "Get current user".into(),
            description: Some("Retrieves the current authenticated user's profile".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "resource": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USER_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need the current user's profile, URI, or organization".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_AVAILABILITY_LIST),
            summary: "List availability schedules".into(),
            description: Some("Lists availability schedules for a user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_uri": { "type": "string", "description": "User URI (defaults to authenticated user)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "collection": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SCHEDULING_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to check a user's availability schedules".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_EVENT_TYPES_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Calendly health check".into(),
            description: Some("Checks Calendly API reachability and authentication".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USER_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to verify that the Calendly API is reachable".into(),
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
impl FcpConnector for CalendlyConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: CalendlyConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Calendly config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = CalendlyClient::new(
            &config.base_url,
            &config.access_token,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Calendly client: {e}"),
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
                "Configured with empty token; egress proxy injection required",
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

impl CalendlyConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_EVENTS_LIST | OP_EVENTS_GET | OP_EVENT_TYPES_LIST | OP_INVITEES_LIST => {
                CapabilityId::from_static(CAP_EVENTS_READ)
            }
            OP_EVENTS_CANCEL => CapabilityId::from_static(CAP_EVENTS_WRITE),
            OP_SCHEDULING_LINKS_CREATE => CapabilityId::from_static(CAP_SCHEDULING_WRITE),
            OP_AVAILABILITY_LIST => CapabilityId::from_static(CAP_SCHEDULING_READ),
            OP_USER_GET | OP_HEALTH => CapabilityId::from_static(CAP_USER_READ),
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
            message: "Calendly client missing after configure".into(),
        })?;

        let output = match operation {
            OP_EVENTS_LIST => {
                // Resolve user_uri: use input or fetch current user
                let user_uri = if let Some(uri) = req.input.get("user_uri").and_then(|v| v.as_str())
                {
                    uri.to_string()
                } else {
                    let user = client
                        .get_current_user(runtime)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    user.resource.uri
                };
                let count = req.input.get("count").and_then(|v| v.as_u64()).map(|v| v as u32);
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let status = req.input.get("status").and_then(|v| v.as_str());
                let min_start = req
                    .input
                    .get("min_start_time")
                    .and_then(|v| v.as_str());
                let max_start = req
                    .input
                    .get("max_start_time")
                    .and_then(|v| v.as_str());

                let resp = client
                    .list_events(runtime, &user_uri, count, page_token, status, min_start, max_start)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize events: {e}"),
                })?
            }
            OP_EVENTS_GET => {
                let event_uuid =
                    req.input
                        .get("event_uuid")
                        .and_then(|v| v.as_str())
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'event_uuid' field".into(),
                        })?;
                let resp = client
                    .get_event(runtime, event_uuid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize event: {e}"),
                })?
            }
            OP_EVENT_TYPES_LIST => {
                let user_uri = if let Some(uri) = req.input.get("user_uri").and_then(|v| v.as_str())
                {
                    uri.to_string()
                } else {
                    let user = client
                        .get_current_user(runtime)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    user.resource.uri
                };
                let count = req.input.get("count").and_then(|v| v.as_u64()).map(|v| v as u32);
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_event_types(runtime, &user_uri, count, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize event types: {e}"),
                })?
            }
            OP_INVITEES_LIST => {
                let event_uuid =
                    req.input
                        .get("event_uuid")
                        .and_then(|v| v.as_str())
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'event_uuid' field".into(),
                        })?;
                let count = req.input.get("count").and_then(|v| v.as_u64()).map(|v| v as u32);
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_invitees(runtime, event_uuid, count, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize invitees: {e}"),
                })?
            }
            OP_SCHEDULING_LINKS_CREATE => {
                let owner_uri =
                    req.input
                        .get("owner_uri")
                        .and_then(|v| v.as_str())
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'owner_uri' field".into(),
                        })?;
                let owner_type =
                    req.input
                        .get("owner_type")
                        .and_then(|v| v.as_str())
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'owner_type' field".into(),
                        })?;
                let max_event_count = req
                    .input
                    .get("max_event_count")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let resp = client
                    .create_scheduling_link(runtime, owner_uri, owner_type, max_event_count)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize scheduling link: {e}"),
                })?
            }
            OP_EVENTS_CANCEL => {
                let event_uuid =
                    req.input
                        .get("event_uuid")
                        .and_then(|v| v.as_str())
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'event_uuid' field".into(),
                        })?;
                let reason = req.input.get("reason").and_then(|v| v.as_str());
                client
                    .cancel_event(runtime, event_uuid, reason)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "status": "cancelled" })
            }
            OP_USER_GET => {
                let resp = client
                    .get_current_user(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize user: {e}"),
                })?
            }
            OP_AVAILABILITY_LIST => {
                let user_uri = if let Some(uri) = req.input.get("user_uri").and_then(|v| v.as_str())
                {
                    uri.to_string()
                } else {
                    let user = client
                        .get_current_user(runtime)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    user.resource.uri
                };
                let resp = client
                    .list_availability(runtime, &user_uri)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize availability: {e}"),
                })?
            }
            OP_HEALTH => {
                client.health_check().await.map_err(|e| e.to_fcp_error())?;
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

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_EVENTS_READ),
                CapabilityId::from_static(CAP_EVENTS_WRITE),
                CapabilityId::from_static(CAP_SCHEDULING_READ),
                CapabilityId::from_static(CAP_SCHEDULING_WRITE),
                CapabilityId::from_static(CAP_USER_READ),
            ],
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

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = CalendlyConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = CalendlyConnector::new();
        let config = json!({
            "access_token": "test_token"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = CalendlyConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = CalendlyConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({
                "access_token": "tok"
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = CalendlyConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = CalendlyConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = CalendlyConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_EVENTS_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = CalendlyConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 9);
        for op_id in &[
            OP_EVENTS_LIST,
            OP_EVENTS_GET,
            OP_EVENT_TYPES_LIST,
            OP_INVITEES_LIST,
            OP_SCHEDULING_LINKS_CREATE,
            OP_EVENTS_CANCEL,
            OP_USER_GET,
            OP_AVAILABILITY_LIST,
            OP_HEALTH,
        ] {
            assert!(
                intro.operations.iter().any(|op| op.id.as_str() == *op_id),
                "Missing operation: {op_id}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "calendly.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = CalendlyConnector::new();
        let req = base_invoke(connector.id(), OP_EVENTS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_events_get_missing_uuid() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_EVENTS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_invitees_list_missing_uuid() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_INVITEES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_cancel_missing_uuid() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_EVENTS_CANCEL);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_scheduling_link_missing_fields() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_SCHEDULING_LINKS_CREATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 9);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_events_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EVENTS_LIST)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_scheduling_links_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SCHEDULING_LINKS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_events_cancel_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EVENTS_CANCEL)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = CalendlyConnector::manifest_hash();
        let hash2 = CalendlyConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = CalendlyConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_EVENTS_LIST))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = CalendlyConfig {
            base_url: default_base_url(),
            access_token: "super_secret_token".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super_secret_token"),
            "Debug output must not contain the raw access_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for sensitive fields"
        );
    }

    #[test]
    fn test_health_operation_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_HEALTH)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_user_get_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_USER_GET)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_availability_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_AVAILABILITY_LIST)
            .unwrap();
        assert_eq!(
            op.capability,
            CapabilityId::from_static(CAP_SCHEDULING_READ)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_base_url() {
        let mut connector = CalendlyConnector::new();
        let config = json!({
            "access_token": "tok",
            "base_url": "https://custom.api.calendly.com"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_timeout() {
        let mut connector = CalendlyConnector::new();
        let config = json!({
            "access_token": "tok",
            "request_timeout_ms": 60000
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_connector_default() {
        let connector = CalendlyConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.calendly");
    }

    #[test]
    fn test_capability_mapping() {
        let ops = operations_info();
        for op in &ops {
            let cap_str = op.capability.as_str();
            assert!(
                cap_str.starts_with("calendly."),
                "Capability {cap_str} should start with 'calendly.'"
            );
        }
    }
}
