//! Signal connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::bridge::BridgeManager;
use crate::client::SignalClient;
use crate::types::{
    GroupLookupRequest, IdentityRequest, ReceiveMessagesRequest, SendMessageRequest, SignalConfig,
    SignalEnvelope, TrustIdentityRequest, is_loopback_host,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_SEND_MESSAGE: &str = "signal.send_message";
const OP_RECEIVE_MESSAGES: &str = "signal.receive_messages";
const OP_LIST_GROUPS: &str = "signal.list_groups";
const OP_GET_GROUP: &str = "signal.get_group";
const OP_GET_IDENTITY: &str = "signal.get_identity";
const OP_TRUST_IDENTITY: &str = "signal.trust_identity";

// Capability IDs
const CAP_SEND: &str = "signal.send";
const CAP_READ: &str = "signal.read";
const CAP_ADMIN: &str = "signal.admin";

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

/// Signal connector state.
#[derive(Debug)]
pub struct SignalConnector {
    base: BaseConnector,
    config: Option<SignalConfig>,
    client: Option<SignalClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    bridge: Option<BridgeManager>,
}

impl SignalConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.signal")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            bridge: None,
        }
    }

    /// Return a reference to the bridge manager, if initialized.
    #[must_use]
    pub const fn bridge(&self) -> Option<&BridgeManager> {
        self.bridge.as_ref()
    }

    /// Return a mutable reference to the bridge manager, if initialized.
    pub const fn bridge_mut(&mut self) -> Option<&mut BridgeManager> {
        self.bridge.as_mut()
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn bridge_ref(&self) -> FcpResult<&BridgeManager> {
        self.bridge.as_ref().ok_or(FcpError::NotConfigured)
    }

    fn validate_attachment_payloads(&self, attachments: &[String]) -> FcpResult<()> {
        let bridge = self.bridge_ref()?;
        for attachment in attachments {
            bridge
                .decode_attachment(attachment)
                .map_err(|error| error.to_fcp_error())?;
        }
        Ok(())
    }

    async fn ensure_bridge_ready(&self, client: &SignalClient) -> FcpResult<()> {
        let bridge = self.bridge_ref()?;
        if bridge.health_check_due() {
            bridge
                .health_check(client)
                .await
                .map_err(|error| error.to_fcp_error())?;
            return Ok(());
        }

        if bridge.is_connected() {
            return Ok(());
        }

        let retry_after_ms = bridge.current_backoff_ms();
        Err(FcpError::External {
            service: "signal".into(),
            message: format!(
                "Signal bridge reconnect backoff active; retry after {retry_after_ms}ms"
            ),
            status_code: None,
            retryable: true,
            retry_after: Some(Duration::from_millis(retry_after_ms)),
        })
    }

    fn remember_receive_cursor(&self, envelopes: &[SignalEnvelope]) -> Option<String> {
        let Ok(bridge) = self.bridge_ref() else {
            return None;
        };

        let cursor = envelopes
            .iter()
            .filter_map(|envelope| {
                envelope.timestamp.or_else(|| {
                    envelope
                        .data_message
                        .as_ref()
                        .and_then(|message| message.timestamp)
                })
            })
            .max()
            .map(|timestamp| timestamp.to_string());

        if let Some(cursor) = cursor.as_ref() {
            bridge.advance_cursor(cursor.clone());
        }

        cursor
    }

    async fn maybe_sync_groups_after_receive(
        &self,
        client: &SignalClient,
        runtime: &ConnectorRuntime,
        envelopes: &[SignalEnvelope],
    ) {
        let Some(bridge) = self.bridge.as_ref() else {
            return;
        };

        let saw_group_event = envelopes.iter().any(|envelope| {
            envelope
                .data_message
                .as_ref()
                .and_then(|message| message.group_info.as_ref())
                .is_some()
        });

        if bridge.group_sync_due() || saw_group_event {
            if let Err(error) = bridge.sync_groups(client, runtime).await {
                warn!(error = %error, "Signal group sync failed after receive poll");
            }
        }
    }

    /// Run connector diagnostics.
    #[allow(clippy::too_many_lines)]
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

        let bridge_ok = self.bridge.is_some();
        checks.push(DoctorCheck {
            name: "bridge_manager".into(),
            passed: bridge_ok,
            message: Some(
                self.bridge
                    .as_ref()
                    .map_or_else(
                        || "Bridge manager not initialized".into(),
                        |bridge| {
                            let diag = bridge.diagnostic_summary();
                            format!(
                                "Bridge: {} (poll={}ms, health_check={}ms, cached_groups={}, receive_cursor={})",
                                diag.status_summary,
                                diag.poll_interval_ms,
                                diag.health_check_interval_ms,
                                diag.cached_group_count,
                                if diag.has_receive_cursor {
                                    "present"
                                } else {
                                    "none"
                                }
                            )
                        },
                    ),
            ),
            critical: false,
        });

        if let Some(bridge) = &self.bridge {
            let diag = bridge.diagnostic_summary();
            if diag.consecutive_failures > 0 {
                checks.push(DoctorCheck {
                    name: "bridge_health".into(),
                    passed: diag.connected,
                    message: Some(format!(
                        "Daemon unreachable ({} failures, backoff {}ms)",
                        diag.consecutive_failures, diag.current_backoff_ms
                    )),
                    critical: false,
                });
            }
        }

        if let Some(config) = &self.config {
            let daemon_url = config.normalized_daemon_url();
            let phone_number = config.normalized_phone_number();
            let scheme = if daemon_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "daemon_url".into(),
                passed: true,
                message: Some(format!("Daemon URL ({scheme}): {daemon_url}")),
                critical: false,
            });

            let host = config.daemon_host();
            let host_ok = host.as_deref().is_some_and(is_loopback_host);
            let host_part = host.unwrap_or_else(|| "<unparseable>".into());
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Daemon URL is local loopback (localhost, 127.0.0.1, or ::1)".into()
                } else {
                    format!(
                        "Daemon URL host '{host_part}' is not loopback; keep signal-cli on the same machine or behind an explicit trust boundary"
                    )
                }),
                critical: false,
            });

            // Validate phone number format
            let phone_ok = phone_number.starts_with('+')
                && phone_number.len() >= 8
                && phone_number[1..].chars().all(|c| c.is_ascii_digit());
            checks.push(DoctorCheck {
                name: "phone_number".into(),
                passed: phone_ok,
                message: Some(if phone_ok {
                    format!(
                        "Phone number: {}...{}",
                        &phone_number[..4],
                        &phone_number[phone_number.len() - 2..]
                    )
                } else {
                    format!("Phone number '{phone_number}' does not look like valid E.164")
                }),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for SignalConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_SEND_MESSAGE),
            summary: "Send a Signal message".into(),
            description: Some(
                "Sends a message to one or more Signal recipients using E.164 numbers, usernames, or group IDs"
                    .into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["recipients", "message"],
                "properties": {
                    "recipients": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Signal recipients as E.164 numbers, usernames, or group IDs"
                    },
                    "message": { "type": "string", "description": "Message text" },
                    "attachments": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Base64-encoded attachment data"
                    },
                    "quote_timestamp": {
                        "type": "integer",
                        "description": "Timestamp of message to reply to"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "timestamp": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a Signal message to contacts, usernames, or groups".into(),
                common_mistakes: vec![
                    "Use E.164 format for phone-number recipients (for example, +15551234567)".into(),
                    "Do not mix phone numbers, usernames, and group IDs in the same request".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_RECEIVE_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RECEIVE_MESSAGES),
            summary: "Receive pending Signal messages".into(),
            description: Some("Polls the signal-cli daemon for new incoming messages".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Long-poll timeout in seconds (defaults to the connector config)",
                        "minimum": 1
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "messages": {
                        "type": "array",
                        "items": { "type": "object" }
                    },
                    "count": { "type": "integer" },
                    "receive_cursor": {
                        "type": ["string", "null"],
                        "description": "Highest observed message timestamp cached as the next receive cursor"
                    },
                    "cached_group_count": {
                        "type": "integer",
                        "description": "Number of Signal groups cached after the receive poll"
                    }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to check for new incoming Signal messages".into(),
                common_mistakes: vec![
                    "Messages are consumed on read; re-calling will not return the same messages".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_MESSAGE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_GROUPS),
            summary: "List Signal groups".into(),
            description: Some("Lists all groups the registered number is a member of".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "groups": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string" },
                                "name": { "type": "string" },
                                "members": { "type": "array", "items": { "type": "string" } }
                            }
                        }
                    }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to see what Signal groups are available".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_GROUP)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_GROUP),
            summary: "Get Signal group details".into(),
            description: Some("Gets detailed information about a specific Signal group".into()),
            input_schema: json!({
                "type": "object",
                "required": ["group_id"],
                "properties": {
                    "group_id": { "type": "string", "description": "Base64-encoded group ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "members": { "type": "array", "items": { "type": "string" } },
                    "admins": { "type": "array", "items": { "type": "string" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific Signal group".into(),
                common_mistakes: vec![
                    "Group ID must be the base64-encoded group identifier".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_LIST_GROUPS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_IDENTITY),
            summary: "Get Signal identity info".into(),
            description: Some("Gets identity and trust information for a Signal number".into()),
            input_schema: json!({
                "type": "object",
                "required": ["number"],
                "properties": {
                    "number": { "type": "string", "description": "Phone number (E.164)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "number": { "type": "string" },
                    "uuid": { "type": "string" },
                    "trust_level": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to check trust status of a Signal contact".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_TRUST_IDENTITY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_TRUST_IDENTITY),
            summary: "Trust a Signal identity".into(),
            description: Some("Marks a Signal contact's identity key as trusted/verified".into()),
            input_schema: json!({
                "type": "object",
                "required": ["number"],
                "properties": {
                    "number": { "type": "string", "description": "Phone number (E.164)" },
                    "verified_safety_number": {
                        "type": "string",
                        "description": "Preferred explicit safety number to trust"
                    },
                    "trust_all_known_keys": {
                        "type": "boolean",
                        "description": "Trust every known key for the recipient; only appropriate for test environments"
                    }
                },
                "oneOf": [
                    { "required": ["verified_safety_number"] },
                    { "required": ["trust_all_known_keys"] }
                ]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you need to mark a Signal contact as trusted after verifying their identity".into(),
                common_mistakes: vec![
                    "Prefer verified_safety_number over trust_all_known_keys=true; the latter is only recommended for testing".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_IDENTITY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
    ]
}

fn parse_input<T>(input: &serde_json::Value, operation: &str) -> FcpResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(input.clone()).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("invalid {operation} input: {error}"),
    })
}

#[async_trait]
impl FcpConnector for SignalConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = SignalConfig::from_value(config)?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = SignalClient::new(&config).map_err(|e| FcpError::Internal {
            message: format!("Failed to create Signal client: {e}"),
        })?;

        // Initialize bridge manager with default config
        let bridge = BridgeManager::new((&config).into()).map_err(|e| FcpError::Internal {
            message: format!("Failed to initialize Signal bridge state: {e}"),
        })?;
        self.bridge = Some(bridge);

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
        if let Some(bridge) = &self.bridge {
            let diag = bridge.diagnostic_summary();
            if diag.consecutive_failures > 0 {
                snapshot.status = HealthState::Degraded {
                    reason: format!(
                        "signal daemon unreachable ({} consecutive failures, backoff {}ms)",
                        diag.consecutive_failures, diag.current_backoff_ms
                    ),
                };
            }
            snapshot.details = Some(json!({ "bridge": diag }));
        }
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

        match if let Some(bridge) = &self.bridge {
            bridge.health_check(client).await
        } else {
            client.health_check().await
        } {
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
        if let Some(bridge) = &mut self.bridge {
            bridge.reset();
        }
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

impl SignalConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let operation = req.operation.as_str();

        if let Some(verifier) = &self.verifier {
            let required_cap = match operation {
                OP_SEND_MESSAGE => CapabilityId::from_static(CAP_SEND),
                OP_RECEIVE_MESSAGES | OP_LIST_GROUPS | OP_GET_GROUP | OP_GET_IDENTITY => {
                    CapabilityId::from_static(CAP_READ)
                }
                OP_TRUST_IDENTITY => CapabilityId::from_static(CAP_ADMIN),
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        let runtime = self.runtime.as_ref().ok_or(FcpError::NotConfigured)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;

        let output = match operation {
            OP_SEND_MESSAGE => {
                let input: SendMessageRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                self.validate_attachment_payloads(&input.attachments)?;
                self.ensure_bridge_ready(client).await?;

                let resp = client
                    .send_message(runtime, &input)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_RECEIVE_MESSAGES => {
                let input: ReceiveMessagesRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                let timeout = input
                    .timeout_seconds
                    .unwrap_or_else(|| config.default_receive_timeout_seconds());
                self.ensure_bridge_ready(client).await?;

                let envelopes = client
                    .receive_messages(runtime, timeout)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let cursor = self.remember_receive_cursor(&envelopes);
                self.maybe_sync_groups_after_receive(client, runtime, &envelopes)
                    .await;
                let cached_group_count = self
                    .bridge
                    .as_ref()
                    .map_or(0, |bridge| bridge.cached_groups().len());

                json!({
                    "messages": envelopes,
                    "count": envelopes.len(),
                    "receive_cursor": cursor,
                    "cached_group_count": cached_group_count
                })
            }
            OP_LIST_GROUPS => {
                self.ensure_bridge_ready(client).await?;
                let groups = if let Some(bridge) = &self.bridge {
                    bridge
                        .sync_groups(client, runtime)
                        .await
                        .map_err(|error| error.to_fcp_error())?
                } else {
                    client
                        .list_groups(runtime)
                        .await
                        .map_err(|error| error.to_fcp_error())?
                };

                json!({ "groups": groups })
            }
            OP_GET_GROUP => {
                let input: GroupLookupRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                self.ensure_bridge_ready(client).await?;

                let group = client
                    .get_group(runtime, &input.group_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                if let Some(bridge) = &self.bridge {
                    bridge.upsert_group(group.clone());
                }

                serde_json::to_value(&group).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize group: {e}"),
                })?
            }
            OP_GET_IDENTITY => {
                let input: IdentityRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                self.ensure_bridge_ready(client).await?;

                let identity = client
                    .get_identity(runtime, &input.number)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&identity).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize identity: {e}"),
                })?
            }
            OP_TRUST_IDENTITY => {
                let input: TrustIdentityRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                self.ensure_bridge_ready(client).await?;

                client
                    .trust_identity(runtime, &input)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                json!({ "status": "trusted" })
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
    use base64::Engine;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SEND),
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_ADMIN),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn signed_token_for(
        capability: &'static str,
        operation: &'static str,
    ) -> (HandshakeRequest, CapabilityToken) {
        let signing_key = Ed25519SigningKey::generate();
        let host_public_key = signing_key.verifying_key().to_bytes();
        let now = Utc::now();
        let expires = now + ChronoDuration::hours(1);

        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id(capability)
                .zone_id("z:work")
                .principal("user:test")
                .operations(&[operation])
                .issuer("node:test")
                .validity(now, expires)
                .sign(&signing_key)
                .expect("signed capability token"),
        );

        let mut handshake = base_handshake();
        handshake.host_public_key = host_public_key;
        handshake.capabilities_requested = vec![CapabilityId::from_static(capability)];

        (handshake, token)
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
        let mut connector = SignalConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = SignalConnector::new();
        let config = json!({
            "phone_number": "+15551234567"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = SignalConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_invalid_phone_number() {
        let mut connector = SignalConnector::new();
        let result = connector
            .configure(json!({
                "phone_number": "alice"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = SignalConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = SignalConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_normalizes_padded_runtime_strings() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "daemon_url": "  http://localhost:8080/  ",
                "phone_number": "  +15551234567  "
            }))
            .await
            .unwrap();

        let report = connector.doctor();
        assert!(report.passed);
        let daemon_check = report
            .checks
            .iter()
            .find(|check| check.name == "daemon_url")
            .expect("daemon_url check");
        assert_eq!(
            daemon_check.message.as_deref(),
            Some("Daemon URL (http): http://localhost:8080")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_accepts_ipv6_loopback_daemon_url() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "daemon_url": "http://[::1]:8080",
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        let report = connector.doctor();
        let network_check = report
            .checks
            .iter()
            .find(|check| check.name == "network_constraints")
            .expect("network_constraints check");
        assert!(network_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = SignalConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = SignalConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = SignalConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 6);
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_SEND_MESSAGE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_RECEIVE_MESSAGES)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_LIST_GROUPS)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_GROUP)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_IDENTITY)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_TRUST_IDENTITY)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "signal.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = SignalConnector::new();
        let req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_recipients() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        req.input = json!({ "message": "hello" }); // missing 'recipients'
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 6);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_send_message_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_list_groups_is_safe() {
        let ops = operations_info();
        let list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_LIST_GROUPS)
            .unwrap();
        assert_eq!(list.safety_tier, SafetyTier::Safe);
        assert_eq!(list.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_trust_identity_is_dangerous() {
        let ops = operations_info();
        let trust = ops
            .iter()
            .find(|op| op.id.as_str() == OP_TRUST_IDENTITY)
            .unwrap();
        assert_eq!(trust.safety_tier, SafetyTier::Dangerous);
        assert_eq!(trust.idempotency, IdempotencyClass::BestEffort);
        assert!(matches!(
            trust.requires_approval,
            Some(ApprovalMode::Interactive)
        ));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = SignalConnector::manifest_hash();
        let hash2 = SignalConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = SignalConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn test_receive_messages_schema_includes_bridge_metadata() {
        let receive = operations_info()
            .into_iter()
            .find(|op| op.id.as_str() == OP_RECEIVE_MESSAGES)
            .expect("receive_messages operation");

        let properties = receive
            .output_schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .expect("receive_messages output properties");
        assert!(properties.contains_key("receive_cursor"));
        assert!(properties.contains_key("cached_group_count"));
    }

    // -- Bridge integration tests --

    #[test]
    fn test_bridge_none_before_configure() {
        let connector = SignalConnector::new();
        assert!(connector.bridge().is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_bridge_initialized_after_configure() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        assert!(connector.bridge().is_some());
        let bridge = connector.bridge().unwrap();
        assert!(!bridge.is_connected());
        assert_eq!(bridge.consecutive_failures(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_applies_bridge_overrides() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567",
                "poll_interval_ms": 9_000,
                "max_reconnect_delay_ms": 45_000,
                "health_check_interval_ms": 12_000,
                "max_attachment_bytes": 2_048
            }))
            .await
            .unwrap();

        let bridge = connector.bridge().unwrap();
        assert_eq!(bridge.config().poll_interval_ms, 9_000);
        assert_eq!(bridge.config().max_reconnect_delay_ms, 45_000);
        assert_eq!(bridge.config().health_check_interval_ms, 12_000);
        assert_eq!(bridge.config().max_attachment_bytes, 2_048);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_includes_bridge_check() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
        let bridge_check = report
            .checks
            .iter()
            .find(|check| check.name == "bridge_manager")
            .expect("bridge_manager check");
        assert!(bridge_check.passed);
        assert!(bridge_check.message.as_deref().unwrap().contains("Bridge:"));
    }

    #[test]
    fn test_doctor_no_bridge_check_before_configure() {
        let connector = SignalConnector::new();
        let report = connector.doctor();
        let bridge_check = report
            .checks
            .iter()
            .find(|check| check.name == "bridge_manager")
            .expect("bridge_manager check");
        assert!(!bridge_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_shows_bridge_failures() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        // Simulate bridge failures
        connector.bridge().unwrap().record_health_failure();
        connector.bridge().unwrap().record_health_failure();

        let report = connector.doctor();
        let health_check = report
            .checks
            .iter()
            .find(|check| check.name == "bridge_health")
            .expect("bridge_health check");
        assert!(!health_check.passed);
        assert!(
            health_check
                .message
                .as_deref()
                .unwrap()
                .contains("2 failures")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_degrades_after_bridge_failures() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        connector.bridge().unwrap().record_health_failure();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
        assert_eq!(
            health.details.unwrap()["bridge"]["consecutive_failures"],
            serde_json::json!(1)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_resets_bridge() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        // Set some bridge state
        connector.bridge().unwrap().advance_cursor("12345".into());
        connector.bridge().unwrap().record_health_success();
        assert!(connector.bridge().unwrap().is_connected());

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 5_000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .unwrap();

        // Bridge should be reset
        assert!(!connector.bridge().unwrap().is_connected());
        assert!(connector.bridge().unwrap().receive_cursor().is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_reports_bridge_unreachable() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        // Simulate many consecutive failures
        for _ in 0..5 {
            connector.bridge().unwrap().record_health_failure();
        }

        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_bridge_accessor_methods() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        let bridge = connector.bridge().unwrap();
        assert_eq!(bridge.config().poll_interval_ms, 5_000);
        assert_eq!(bridge.config().max_reconnect_delay_ms, 60_000);
        assert_eq!(bridge.config().health_check_interval_ms, 30_000);
        assert!(bridge.cached_groups().is_empty());
        assert!(bridge.group_sync_due());
        assert!(bridge.health_check_due());
        assert!(!bridge.should_poll());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_receive_messages_updates_cursor_and_group_cache() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/about"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/receive/%2B15551234567"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "timestamp": 1_700_000_001_000_u64,
                        "dataMessage": {
                            "timestamp": 1_700_000_001_000_u64,
                            "message": "hello",
                            "groupInfo": {
                                "id": "group-1",
                                "name": "Bridge group",
                                "members": ["+15551111111"],
                                "admins": ["+15551111111"]
                            },
                            "attachments": []
                        }
                    }
                ])),
            )
            .mount(&mock_server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/groups/%2B15551234567"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "id": "group-1",
                        "name": "Bridge group",
                        "members": ["+15551111111"],
                        "admins": ["+15551111111"]
                    }
                ])),
            )
            .mount(&mock_server)
            .await;

        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "daemon_url": mock_server.uri(),
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        let (handshake, token) = signed_token_for(CAP_READ, OP_RECEIVE_MESSAGES);
        connector.handshake(handshake).await.unwrap();

        let mut req = base_invoke(connector.id(), OP_RECEIVE_MESSAGES);
        req.capability_token = token;
        req.input = json!({ "timeout_seconds": 1 });

        let response = connector.invoke(req).await.unwrap();
        let result = response.result.expect("receive response");
        assert_eq!(result["count"], serde_json::json!(1));
        assert_eq!(result["receive_cursor"], serde_json::json!("1700000001000"));
        assert_eq!(result["cached_group_count"], serde_json::json!(1));
        assert_eq!(
            connector.bridge().unwrap().receive_cursor().as_deref(),
            Some("1700000001000")
        );
        assert_eq!(connector.bridge().unwrap().cached_groups().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_send_message_rejects_oversized_attachment_before_network() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567",
                "max_attachment_bytes": 4
            }))
            .await
            .unwrap();
        let (handshake, token) = signed_token_for(CAP_SEND, OP_SEND_MESSAGE);
        connector.handshake(handshake).await.unwrap();

        let attachment = base64::engine::general_purpose::STANDARD.encode(b"too-large");
        let mut req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        req.capability_token = token;
        req.input = json!({
            "recipients": ["+15559876543"],
            "message": "hello",
            "attachments": [attachment]
        });

        let error = connector.invoke(req).await.unwrap_err();
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
