//! WhatsApp connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, InvokeRequest, InvokeResponse, Introspection, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::WhatsAppClient;
use crate::webhook::WhatsAppWebhook;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_SEND_TEXT: &str = "whatsapp.send_text";
const OP_SEND_TEMPLATE: &str = "whatsapp.send_template";
const OP_GET_PROFILE: &str = "whatsapp.get_profile";
const OP_WEBHOOK_VERIFY: &str = "whatsapp.webhook_verify";
const OP_WEBHOOK_RECEIVE: &str = "whatsapp.webhook_receive";

// Capability IDs
const CAP_SEND: &str = "whatsapp.send";
const CAP_READ: &str = "whatsapp.read";
const CAP_WEBHOOK: &str = "whatsapp.webhook";

/// WhatsApp connector configuration.
#[derive(Debug, Clone, Deserialize)]
struct WhatsAppConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    phone_number_id: String,
    access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
    /// Meta app secret for webhook signature verification (HMAC-SHA256).
    #[serde(default)]
    app_secret: Option<String>,
    /// Token for webhook challenge-response verification.
    #[serde(default)]
    webhook_verify_token: Option<String>,
}

fn default_base_url() -> String {
    "https://graph.facebook.com/v21.0".into()
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

/// WhatsApp connector state.
#[derive(Debug)]
pub struct WhatsAppConnector {
    base: BaseConnector,
    config: Option<WhatsAppConfig>,
    client: Option<WhatsAppClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    webhook: Option<WhatsAppWebhook>,
}

impl WhatsAppConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.whatsapp")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            webhook: None,
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

            let allowed_hosts = ["graph.facebook.com"];
            // Extract host from URL: skip scheme, take up to next '/' or ':'
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
                    "Base URL matches allowed host (graph.facebook.com)".into()
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
                    "Direct access token configured".into()
                }),
                critical: false,
            });

            let webhook_ok = self.webhook.is_some();
            checks.push(DoctorCheck {
                name: "webhook".into(),
                passed: webhook_ok,
                message: Some(if webhook_ok {
                    "Webhook handler configured (app_secret + verify_token)".into()
                } else {
                    "Webhook not configured (set app_secret and webhook_verify_token to enable)".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for WhatsAppConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_SEND_TEXT),
            summary: "Send a text message via WhatsApp".into(),
            description: Some("Sends a text message to a WhatsApp user by phone number".into()),
            input_schema: json!({
                "type": "object",
                "required": ["to", "text"],
                "properties": {
                    "to": { "type": "string", "description": "Recipient phone number (E.164 format)" },
                    "text": { "type": "string", "description": "Message text (max 4096 chars)" },
                    "preview_url": { "type": "boolean", "default": false }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" },
                    "wa_id": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a plain text message to a WhatsApp user".into(),
                common_mistakes: vec![
                    "Phone numbers must be in E.164 format (e.g., 15551234567)".into(),
                    "Text messages are limited to 4096 characters".into(),
                    "Business-initiated messages require an approved template within 24h window".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_TEMPLATE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEND_TEMPLATE),
            summary: "Send a template message via WhatsApp".into(),
            description: Some("Sends a pre-approved template message to a WhatsApp user".into()),
            input_schema: json!({
                "type": "object",
                "required": ["to", "template_name"],
                "properties": {
                    "to": { "type": "string", "description": "Recipient phone number (E.164)" },
                    "template_name": { "type": "string", "description": "Approved template name" },
                    "language_code": { "type": "string", "description": "e.g., en_US (defaults to en_US)", "default": "en_US" },
                    "components": { "type": "array", "description": "Template parameter components" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" },
                    "wa_id": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When sending business-initiated messages outside 24h conversation window".into(),
                common_mistakes: vec![
                    "Template must be pre-approved by Meta".into(),
                    "Language code must match an approved translation".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_TEXT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_PROFILE),
            summary: "Get WhatsApp Business profile".into(),
            description: Some("Retrieves the business profile for the configured phone number".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "about": { "type": "string" },
                    "description": { "type": "string" },
                    "address": { "type": "string" },
                    "vertical": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to check or display the business profile".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WEBHOOK_VERIFY),
            summary: "Verify a WhatsApp webhook challenge".into(),
            description: Some("Handles Meta's challenge-response verification for webhook registration".into()),
            input_schema: json!({
                "type": "object",
                "required": ["hub_mode", "hub_verify_token", "hub_challenge"],
                "properties": {
                    "hub_mode": { "type": "string", "description": "Must be 'subscribe'" },
                    "hub_verify_token": { "type": "string", "description": "Token to verify" },
                    "hub_challenge": { "type": "string", "description": "Challenge string to echo back" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "challenge": { "type": "string", "description": "Echoed challenge for Meta" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WEBHOOK),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When Meta sends a GET request to verify your webhook URL".into(),
                common_mistakes: vec![
                    "webhook_verify_token must match the token configured in Meta's dashboard".into(),
                    "hub.mode must be 'subscribe'".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_WEBHOOK_RECEIVE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WEBHOOK_RECEIVE),
            summary: "Receive and verify a WhatsApp webhook notification".into(),
            description: Some("Verifies HMAC-SHA256 signature, parses incoming messages and status updates, applies replay detection".into()),
            input_schema: json!({
                "type": "object",
                "required": ["headers", "body"],
                "properties": {
                    "headers": {
                        "type": "object",
                        "description": "HTTP headers including X-Hub-Signature-256",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": { "type": "string", "description": "Raw request body (JSON string)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "events": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string" },
                                "event_type": { "type": "string" },
                                "payload": { "type": "object" }
                            }
                        }
                    },
                    "event_count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WEBHOOK),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When Meta sends a POST with incoming messages or status updates".into(),
                common_mistakes: vec![
                    "Body must be the raw JSON string, not pre-parsed".into(),
                    "X-Hub-Signature-256 header is required for verification".into(),
                    "app_secret must be configured for webhook verification to work".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_WEBHOOK_VERIFY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

#[async_trait]
impl FcpConnector for WhatsAppConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: WhatsAppConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid WhatsApp config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = WhatsAppClient::new(
            &config.base_url,
            &config.phone_number_id,
            &config.access_token,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create WhatsApp client: {e}"),
        })?;

        self.client = Some(client);

        // Initialize webhook handler if app_secret and verify_token are configured
        if let (Some(app_secret), Some(verify_token)) =
            (&config.app_secret, &config.webhook_verify_token)
        {
            self.webhook = Some(WhatsAppWebhook::new(
                app_secret.as_bytes(),
                verify_token.clone(),
            ));
        }

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

impl WhatsAppConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let operation = req.operation.as_str();

        if let Some(verifier) = &self.verifier {
            let required_cap = match operation {
                OP_SEND_TEXT | OP_SEND_TEMPLATE => CapabilityId::from_static(CAP_SEND),
                OP_GET_PROFILE => CapabilityId::from_static(CAP_READ),
                OP_WEBHOOK_VERIFY | OP_WEBHOOK_RECEIVE => {
                    CapabilityId::from_static(CAP_WEBHOOK)
                }
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    })
                }
            };
            verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        let runtime = self.runtime.as_ref().ok_or(FcpError::NotConfigured)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let output = match operation {
            OP_SEND_TEXT => {
                let to = req.input.get("to").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'to' field".into(),
                    },
                )?;
                let text = req.input.get("text").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'text' field".into(),
                    },
                )?;

                let resp = client
                    .send_text_message(runtime, to, text)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                json!({
                    "message_id": resp.messages.first().map(|m| m.id.as_str()).unwrap_or(""),
                    "wa_id": resp.contacts.first().map(|c| c.wa_id.as_str()).unwrap_or("")
                })
            }
            OP_SEND_TEMPLATE => {
                let to = req.input.get("to").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'to' field".into(),
                    },
                )?;
                let template_name = req
                    .input
                    .get("template_name")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'template_name' field".into(),
                    })?;
                let language_code = req
                    .input
                    .get("language_code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("en_US");
                let components: Vec<serde_json::Value> = req
                    .input
                    .get("components")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let resp = client
                    .send_template_message(runtime, to, template_name, language_code, &components)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                json!({
                    "message_id": resp.messages.first().map(|m| m.id.as_str()).unwrap_or(""),
                    "wa_id": resp.contacts.first().map(|c| c.wa_id.as_str()).unwrap_or("")
                })
            }
            OP_GET_PROFILE => {
                let resp = client
                    .get_profile(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize profile: {e}"),
                })?
            }
            OP_WEBHOOK_VERIFY => {
                let webhook = self.webhook.as_ref().ok_or(FcpError::InvalidRequest {
                    code: 1008,
                    message: "Webhook not configured (set app_secret and webhook_verify_token)"
                        .into(),
                })?;
                let mode = req
                    .input
                    .get("hub_mode")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'hub_mode' field".into(),
                    })?;
                let token = req
                    .input
                    .get("hub_verify_token")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'hub_verify_token' field".into(),
                    })?;
                let challenge = req
                    .input
                    .get("hub_challenge")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'hub_challenge' field".into(),
                    })?;

                let result = webhook.verify_challenge(mode, token, challenge).map_err(
                    |_| FcpError::Unauthorized {
                        code: 2002,
                        message: "Webhook challenge verification failed".into(),
                    },
                )?;
                json!({ "challenge": result })
            }
            OP_WEBHOOK_RECEIVE => {
                let webhook = self.webhook.as_ref().ok_or(FcpError::InvalidRequest {
                    code: 1008,
                    message: "Webhook not configured (set app_secret and webhook_verify_token)"
                        .into(),
                })?;

                let headers_value = req.input.get("headers").ok_or(FcpError::InvalidRequest {
                    code: 1005,
                    message: "Missing 'headers' field".into(),
                })?;
                let headers: std::collections::HashMap<String, String> =
                    serde_json::from_value(headers_value.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid headers: {e}"),
                        }
                    })?;

                let body_str = req
                    .input
                    .get("body")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'body' field (must be raw JSON string)".into(),
                    })?;

                let events =
                    webhook
                        .verify_and_parse(&headers, body_str.as_bytes())
                        .map_err(|e| FcpError::InvalidRequest {
                            code: 1007,
                            message: format!("Webhook verification failed: {e}"),
                        })?;

                // Apply replay detection to each event
                let mut accepted = Vec::new();
                for event in &events {
                    if webhook.claim_event(&event.id).is_ok() {
                        accepted.push(json!({
                            "id": event.id,
                            "event_type": event.event_type,
                            "payload": event.payload,
                        }));
                    }
                }

                json!({
                    "events": accepted,
                    "event_count": accepted.len(),
                })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                })
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
                CapabilityId::from_static(CAP_SEND),
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WEBHOOK),
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
        let mut connector = WhatsAppConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = WhatsAppConnector::new();
        let config = json!({
            "phone_number_id": "123456",
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
        let mut connector = WhatsAppConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = WhatsAppConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = WhatsAppConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = WhatsAppConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = WhatsAppConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_TEXT),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = WhatsAppConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 5);
        assert!(intro
            .operations
            .iter()
            .any(|op| op.id.as_str() == OP_SEND_TEXT));
        assert!(intro
            .operations
            .iter()
            .any(|op| op.id.as_str() == OP_SEND_TEMPLATE));
        assert!(intro
            .operations
            .iter()
            .any(|op| op.id.as_str() == OP_GET_PROFILE));
        assert!(intro
            .operations
            .iter()
            .any(|op| op.id.as_str() == OP_WEBHOOK_VERIFY));
        assert!(intro
            .operations
            .iter()
            .any(|op| op.id.as_str() == OP_WEBHOOK_RECEIVE));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "whatsapp.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = WhatsAppConnector::new();
        let req = base_invoke(connector.id(), OP_SEND_TEXT);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_to_field() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_SEND_TEXT);
        req.input = json!({ "text": "hello" }); // missing 'to'
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_send_text_is_risky() {
        let ops = operations_info();
        let send_text = ops.iter().find(|op| op.id.as_str() == OP_SEND_TEXT).unwrap();
        assert_eq!(send_text.safety_tier, SafetyTier::Risky);
        assert_eq!(send_text.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_get_profile_is_safe() {
        let ops = operations_info();
        let get_profile = ops
            .iter()
            .find(|op| op.id.as_str() == OP_GET_PROFILE)
            .unwrap();
        assert_eq!(get_profile.safety_tier, SafetyTier::Safe);
        assert_eq!(get_profile.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = WhatsAppConnector::manifest_hash();
        let hash2 = WhatsAppConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        // WhatsApp is request-response, not streaming
        let connector = WhatsAppConnector::new();
        let intro = connector.introspect();
        assert!(
            !intro.event_caps.as_ref().unwrap().streaming
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_webhook() {
        let mut connector = WhatsAppConnector::new();
        let config = json!({
            "phone_number_id": "123456",
            "access_token": "test_token",
            "app_secret": "test_app_secret",
            "webhook_verify_token": "test_verify_token"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.webhook.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_without_webhook() {
        let mut connector = WhatsAppConnector::new();
        let config = json!({
            "phone_number_id": "123456",
            "access_token": "test_token"
        });
        connector.configure(config).await.unwrap();
        assert!(connector.webhook.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_verify_success() {
        // Test webhook challenge verification via the webhook handler directly
        // (invoke path goes through CapabilityVerifier which requires real token signing)
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok",
                "app_secret": "secret",
                "webhook_verify_token": "my_token"
            }))
            .await
            .unwrap();

        let webhook = connector.webhook.as_ref().unwrap();
        let result = webhook.verify_challenge("subscribe", "my_token", "challenge_123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "challenge_123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_verify_wrong_token() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok",
                "app_secret": "secret",
                "webhook_verify_token": "my_token"
            }))
            .await
            .unwrap();

        let webhook = connector.webhook.as_ref().unwrap();
        let result = webhook.verify_challenge("subscribe", "wrong_token", "challenge_123");
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_receive_without_webhook_configured() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();

        let mut req = base_invoke(connector.id(), OP_WEBHOOK_RECEIVE);
        req.input = json!({
            "headers": {},
            "body": "{}"
        });
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_operations_have_ai_hints() {
        let ops = operations_info();
        let verify_op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WEBHOOK_VERIFY)
            .unwrap();
        assert!(!verify_op.ai_hints.when_to_use.is_empty());

        let receive_op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WEBHOOK_RECEIVE)
            .unwrap();
        assert!(!receive_op.ai_hints.when_to_use.is_empty());
    }

    #[test]
    fn test_doctor_with_webhook() {
        let mut connector = WhatsAppConnector::new();
        // Simulate having webhook configured by manually setting it
        connector.webhook = Some(crate::webhook::WhatsAppWebhook::new(
            b"secret",
            "token".to_string(),
        ));
        connector.config = Some(WhatsAppConfig {
            base_url: default_base_url(),
            phone_number_id: "123".into(),
            access_token: "tok".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
            app_secret: Some("secret".into()),
            webhook_verify_token: Some("token".into()),
        });
        connector.client = Some(
            WhatsAppClient::new(&default_base_url(), "123", "tok", HttpRetryConfig::default())
                .unwrap(),
        );
        connector.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default(),
        ));
        let report = connector.doctor();
        assert!(report.passed);
        let webhook_check = report.checks.iter().find(|c| c.name == "webhook").unwrap();
        assert!(webhook_check.passed);
    }
}
