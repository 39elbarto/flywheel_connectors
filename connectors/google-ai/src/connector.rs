//! FCP Google AI Connector implementation.

use std::sync::Arc;

use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, CredentialId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::{DEFAULT_BASE_URL, GoogleAiAuth, GoogleAiClient};
use crate::error::GoogleAiError;
use crate::types::{
    CancelTuningOperationRequest, CreateTunedModelRequest, GetTunedModelRequest,
    GetTuningOperationRequest, GoogleLiveBrowserSessionRequest, ListTunedModelsRequest,
};

const GOOGLE_AI_ALLOWED_HOST: &str = "generativelanguage.googleapis.com";

fn invalid_base_url(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn validate_google_ai_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid_base_url("base_url must not be empty"));
    }

    let parsed =
        Url::parse(trimmed).map_err(|_| invalid_base_url("base_url must be an absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid_base_url("base_url must use http or https"));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_base_url("base_url must not contain userinfo"));
    }

    if parsed.query().is_some() {
        return Err(invalid_base_url("base_url must not contain a query string"));
    }

    if parsed.fragment().is_some() {
        return Err(invalid_base_url("base_url must not contain a fragment"));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_base_url("base_url must include a host"))?;
    let is_local = is_local_test_host(host);

    if parsed.scheme() == "http" && !is_local {
        return Err(invalid_base_url(
            "base_url must use https unless targeting localhost",
        ));
    }

    if !is_local && !host.eq_ignore_ascii_case(GOOGLE_AI_ALLOWED_HOST) {
        return Err(invalid_base_url(format!(
            "base_url host must be {GOOGLE_AI_ALLOWED_HOST} or localhost"
        )));
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

/// Parsed and validated Google AI connector configuration.
#[derive(Debug, Clone)]
struct GoogleAiConfig {
    auth: GoogleAiAuth,
    base_url: String,
}

impl GoogleAiConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

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

        let auth = match (api_key, credential_id) {
            (Some(key), None) => GoogleAiAuth::ApiKey(key),
            (None, Some(cred_id)) => GoogleAiAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let base_url = match params.get("base_url") {
            Some(value) => validate_google_ai_base_url(
                value
                    .as_str()
                    .ok_or_else(|| invalid_base_url("base_url must be a string"))?,
            )?,
            None => DEFAULT_BASE_URL.to_string(),
        };

        Ok(Self { auth, base_url })
    }
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP Google AI Connector.
pub struct GoogleAiConnector {
    base: Arc<BaseConnector>,
    config: Option<GoogleAiConfig>,
    client: Option<GoogleAiClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GoogleAiConnector {
    /// Create a new Google AI connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("google-ai"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Return the connector instance ID used for bound capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = GoogleAiConfig::from_params(&params)?;

        let client =
            GoogleAiClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_base_url(&config.base_url);

        let auth_label = config.auth.redacted_label();
        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_label, "Google AI connector configured");

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
            manifest_hash: "sha256:google-ai-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 10,
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
        let configured = self.config.is_some();
        let auth = self
            .config
            .as_ref()
            .map_or_else(|| "unconfigured".to_string(), |c| c.auth.redacted_label());
        let base_url = self
            .config
            .as_ref()
            .map_or_else(|| DEFAULT_BASE_URL.to_string(), |c| c.base_url.clone());
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "auth": auth,
            "base_url": base_url,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor checks.
    ///
    /// Returns a structured readiness report without leaking secrets.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // Check 1: Configuration loaded
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

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        // Check 2: HTTP client initialized
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        // Check 3: Base URL scheme
        let scheme = if config.base_url.starts_with("https://") {
            "https"
        } else if config.base_url.starts_with("http://") {
            "http"
        } else {
            "unknown"
        };
        checks.push(DoctorCheck {
            name: "base_url".into(),
            passed: true,
            message: Some(format!("Base URL ({scheme}): {}", config.base_url)),
            critical: false,
        });

        // Check 4: Auth mode
        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth: {}", config.auth.redacted_label())),
            critical: false,
        });

        // Check 5: Network constraints
        let host_ok = Url::parse(&config.base_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .is_some_and(|host| {
                is_local_test_host(&host) || host.eq_ignore_ascii_case(GOOGLE_AI_ALLOWED_HOST)
            });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: host_ok,
            message: Some(if host_ok {
                "Base URL matches allowed host (generativelanguage.googleapis.com)".into()
            } else {
                format!(
                    "Base URL {} does not match allowed hosts: {:?}",
                    config.base_url,
                    [GOOGLE_AI_ALLOWED_HOST]
                )
            }),
            critical: true,
        });

        // Check 6: Credential injection status
        let secretless = config.auth.is_secretless();
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !secretless,
            message: Some(if secretless {
                "Credential injection required via egress proxy".into()
            } else {
                "Direct API key configured".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
    ///
    /// Performs a safe, read-only API call (list models) to validate the API key
    /// is valid and the Google AI API is reachable.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // If using credential_id, we can't validate directly
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
                    "google-ai.generate_content",
                    "Generate content from a Gemini model (non-streaming)",
                    json!({
                        "type": "object",
                        "required": ["contents"],
                        "properties": {
                            "model": { "type": "string", "default": "gemini-2.0-flash" },
                            "contents": { "type": "array", "minItems": 1 },
                            "generation_config": { "type": "object" },
                            "safety_settings": { "type": "array" },
                            "system_instruction": { "type": "object" },
                            "tools": { "type": "array" },
                            "tool_config": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["candidates", "usage_metadata"],
                        "properties": {
                            "candidates": { "type": "array" },
                            "usage_metadata": { "type": "object" },
                            "model_version": { "type": "string" }
                        }
                    }),
                    "google-ai.generate",
                    RiskLevel::Medium,
                    SafetyTier::Safe,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Generate text from a Gemini model. Use for single-turn or multi-turn conversations.".into(),
                        common_mistakes: vec![
                            "Passing a string instead of contents array [{role, parts}].".into(),
                            "Not specifying maxOutputTokens in generation_config.".into(),
                        ],
                        examples: vec![
                            r#"{"contents": [{"role": "user", "parts": [{"text": "Explain quantum computing"}]}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("google-ai.generate_content_stream"),
                            CapabilityId::from_static("google-ai.count_tokens"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.generate_content_stream",
                    "Generate content with streaming token delivery",
                    json!({
                        "type": "object",
                        "required": ["contents"],
                        "properties": {
                            "model": { "type": "string", "default": "gemini-2.0-flash" },
                            "contents": { "type": "array", "minItems": 1 },
                            "generation_config": { "type": "object" },
                            "safety_settings": { "type": "array" },
                            "system_instruction": { "type": "object" },
                            "tools": { "type": "array" },
                            "tool_config": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["candidates"],
                        "properties": {
                            "candidates": { "type": "array" },
                            "usage_metadata": { "type": "object" }
                        }
                    }),
                    "google-ai.generate",
                    RiskLevel::Medium,
                    SafetyTier::Safe,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Stream generation tokens incrementally for long outputs or real-time display.".into(),
                        common_mistakes: vec![
                            "Not handling partial chunks.".into(),
                        ],
                        examples: vec![
                            r#"{"model": "gemini-2.0-flash", "contents": [{"role": "user", "parts": [{"text": "Write a story"}]}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("google-ai.generate_content"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.live.create_browser_session",
                    "Create a constrained Google Live browser session token",
                    json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "default": crate::types::GOOGLE_LIVE_DEFAULT_MODEL
                            },
                            "voice": {
                                "type": "string",
                                "default": crate::types::GOOGLE_LIVE_DEFAULT_VOICE
                            },
                            "instructions": { "type": "string" },
                            "tools": { "type": "array" },
                            "temperature": { "type": "number" },
                            "prefix_padding_ms": { "type": "integer" },
                            "silence_duration_ms": { "type": "integer" },
                            "start_sensitivity": { "type": "string", "enum": ["low", "high"] },
                            "end_sensitivity": { "type": "string", "enum": ["low", "high"] },
                            "activity_handling": {
                                "type": "string",
                                "enum": ["start-of-activity-interrupts", "no-interruption"]
                            },
                            "turn_coverage": {
                                "type": "string",
                                "enum": ["only-activity", "all-input", "audio-activity-and-all-video"]
                            },
                            "automatic_activity_detection_disabled": { "type": "boolean" },
                            "enable_affective_dialog": { "type": "boolean" },
                            "session_resumption": { "type": "boolean", "default": true },
                            "context_window_compression": { "type": "boolean", "default": true },
                            "thinking_level": {
                                "type": "string",
                                "enum": ["minimal", "low", "medium", "high"]
                            },
                            "thinking_budget": { "type": "integer" },
                            "expire_time": { "type": "string" },
                            "new_session_expire_time": { "type": "string" },
                            "uses": { "type": "integer", "default": 1 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": [
                            "provider",
                            "transport",
                            "protocol",
                            "clientSecret",
                            "websocketUrl",
                            "audio",
                            "initialMessage",
                            "model",
                            "voice",
                            "expiresAt"
                        ],
                        "properties": {
                            "provider": { "type": "string" },
                            "transport": { "type": "string" },
                            "protocol": { "type": "string" },
                            "clientSecret": { "type": "string" },
                            "websocketUrl": { "type": "string" },
                            "audio": { "type": "object" },
                            "initialMessage": { "type": "object" },
                            "model": { "type": "string" },
                            "voice": { "type": "string" },
                            "expiresAt": { "type": "integer" },
                            "newSessionExpiresAt": { "type": "integer" },
                            "provenance": { "type": "object" }
                        }
                    }),
                    "google-ai.live_voice",
                    RiskLevel::High,
                    SafetyTier::Safe,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Mint a short-lived browser token for direct Google Live audio over BidiGenerateContentConstrained.".into(),
                        common_mistakes: vec![
                            "Using the generic generate_content_stream operation for realtime audio; Live is a separate bidirectional WebSocket protocol.".into(),
                            "Changing api_version away from v1alpha; ephemeral Live tokens are constrained to v1alpha.".into(),
                            "Logging clientSecret or treating it as a durable API key.".into(),
                        ],
                        examples: vec![
                            r#"{"voice": "Kore", "instructions": "Speak briefly.", "tools": [{"name": "lookup", "description": "Look something up", "parameters": {"type": "object"}}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("google-ai.generate_content_stream"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.embed_content",
                    "Generate embeddings for text content",
                    json!({
                        "type": "object",
                        "required": ["content"],
                        "properties": {
                            "model": { "type": "string", "default": "text-embedding-004" },
                            "content": { "type": "object" },
                            "task_type": { "type": "string" },
                            "title": { "type": "string" },
                            "output_dimensionality": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["embedding"],
                        "properties": {
                            "embedding": { "type": "object" }
                        }
                    }),
                    "google-ai.embed",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Generate text embeddings for semantic search, clustering, or classification.".into(),
                        common_mistakes: vec![
                            "Not specifying task_type.".into(),
                        ],
                        examples: vec![
                            r#"{"content": {"parts": [{"text": "What is machine learning?"}]}, "task_type": "RETRIEVAL_QUERY"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("google-ai.batch_embed_contents"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.batch_embed_contents",
                    "Generate embeddings for multiple content items in a single request",
                    json!({
                        "type": "object",
                        "required": ["requests"],
                        "properties": {
                            "model": { "type": "string", "default": "text-embedding-004" },
                            "requests": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["embeddings"],
                        "properties": {
                            "embeddings": { "type": "array" }
                        }
                    }),
                    "google-ai.embed",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Embed multiple texts in a single batch request for efficiency.".into(),
                        common_mistakes: vec![
                            "Exceeding batch size limits (typically 100 items).".into(),
                        ],
                        examples: vec![
                            r#"{"requests": [{"content": {"parts": [{"text": "doc 1"}]}}, {"content": {"parts": [{"text": "doc 2"}]}}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("google-ai.embed_content"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.count_tokens",
                    "Count tokens for content without generating a response",
                    json!({
                        "type": "object",
                        "required": ["contents"],
                        "properties": {
                            "model": { "type": "string", "default": "gemini-2.0-flash" },
                            "contents": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["total_tokens"],
                        "properties": {
                            "total_tokens": { "type": "integer" }
                        }
                    }),
                    "google-ai.models",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Count tokens before sending a generation request to estimate cost or check context limits.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"contents": [{"role": "user", "parts": [{"text": "Hello"}]}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("google-ai.generate_content"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.list_models",
                    "List available Gemini models and their capabilities",
                    json!({
                        "type": "object",
                        "properties": {
                            "page_size": { "type": "integer" },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["models"],
                        "properties": {
                            "models": { "type": "array" },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    "google-ai.models",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover available models and their capabilities, context sizes, and supported generation methods.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![
                            CapabilityId::from_static("google-ai.get_model"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.get_model",
                    "Get detailed information about a specific model",
                    json!({
                        "type": "object",
                        "required": ["model"],
                        "properties": {
                            "model": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "supported_generation_methods"],
                        "properties": {
                            "name": { "type": "string" },
                            "display_name": { "type": "string" },
                            "input_token_limit": { "type": "integer" },
                            "output_token_limit": { "type": "integer" },
                            "supported_generation_methods": { "type": "array" }
                        }
                    }),
                    "google-ai.models",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get details for a specific model including token limits and supported methods.".into(),
                        common_mistakes: vec![
                            "Using display name instead of resource name (must be 'models/gemini-2.0-flash').".into(),
                        ],
                        examples: vec![r#"{"model": "models/gemini-2.0-flash"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("google-ai.list_models"),
                        ],
                    },
                ),
                op_info_with_approval(
                    "google-ai.tuning.create",
                    "Create a tuned model training job",
                    json!({
                        "type": "object",
                        "required": ["source_model", "tuning_task"],
                        "properties": {
                            "tuned_model_id": {
                                "type": "string",
                                "description": "Optional stable ID to assign to the tuned model"
                            },
                            "display_name": {
                                "type": "string",
                                "description": "Human-friendly display name for the tuned model"
                            },
                            "description": {
                                "type": "string",
                                "description": "Optional description for operators and future readers"
                            },
                            "source_model": {
                                "type": "string",
                                "description": "Base model resource to tune, for example models/gemini-1.5-flash-001"
                            },
                            "tuning_task": {
                                "type": "object",
                                "required": ["training_data"],
                                "properties": {
                                    "training_data": {
                                        "type": "object",
                                        "required": ["examples"],
                                        "properties": {
                                            "examples": {
                                                "type": "array",
                                                "minItems": 1
                                            }
                                        }
                                    },
                                    "hyperparameters": {
                                        "type": "object"
                                    }
                                }
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "done"],
                        "properties": {
                            "name": { "type": "string" },
                            "done": { "type": "boolean" },
                            "metadata": { "type": "object" },
                            "response": { "type": "object" },
                            "error": { "type": "object" },
                            "provenance": { "type": "object" }
                        }
                    }),
                    "google-ai.tuning",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    Some(ApprovalMode::ElevationToken),
                    AgentHint {
                        when_to_use: "Start a new tuned model training job when you have curated prompt/output pairs and explicit approval for the spend and side effects.".into(),
                        common_mistakes: vec![
                            "Submitting empty or low-quality training examples.".into(),
                            "Treating training as instantaneous instead of polling the returned long-running operation.".into(),
                        ],
                        examples: vec![
                            r#"{"tuned_model_id": "support-bot", "source_model": "models/gemini-1.5-flash-001", "tuning_task": {"training_data": {"examples": [{"text_input": "Refund request", "output": "billing"}]}}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("google-ai.tuning.get_operation"),
                            CapabilityId::from_static("google-ai.tuning.cancel"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.tuning.list",
                    "List tuned models visible to the current credential",
                    json!({
                        "type": "object",
                        "properties": {
                            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["tuned_models"],
                        "properties": {
                            "tuned_models": { "type": "array" },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    "google-ai.tuning",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover tuned models before invoking or auditing them.".into(),
                        common_mistakes: vec![
                            "Forgetting to follow next_page_token when more results exist.".into(),
                        ],
                        examples: vec![r"{}".into(), r#"{"page_size": 25}"#.into()],
                        related: vec![
                            CapabilityId::from_static("google-ai.tuning.get"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.tuning.get",
                    "Get metadata for one tuned model",
                    json!({
                        "type": "object",
                        "required": ["tuned_model"],
                        "properties": {
                            "tuned_model": {
                                "type": "string",
                                "description": "Tuned model resource name, for example tunedModels/support-bot"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string" },
                            "display_name": { "type": "string" },
                            "state": { "type": "string" },
                            "source_model": { "type": "string" },
                            "tuning_task": { "type": "object" }
                        }
                    }),
                    "google-ai.tuning",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect one tuned model's state, source model, and tuning metadata.".into(),
                        common_mistakes: vec![
                            "Passing only a short nickname instead of the tuned model resource name when multiple similar models exist.".into(),
                        ],
                        examples: vec![r#"{"tuned_model": "tunedModels/support-bot"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("google-ai.tuning.list"),
                            CapabilityId::from_static("google-ai.tuning.get_operation"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.tuning.get_operation",
                    "Get the status of a long-running tuned model operation",
                    json!({
                        "type": "object",
                        "required": ["operation"],
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "Full operation resource, for example tunedModels/support-bot/operations/op-123"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "done"],
                        "properties": {
                            "name": { "type": "string" },
                            "done": { "type": "boolean" },
                            "metadata": { "type": "object" },
                            "response": { "type": "object" },
                            "error": { "type": "object" },
                            "provenance": { "type": "object" }
                        }
                    }),
                    "google-ai.tuning",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Poll a training operation until it completes or fails.".into(),
                        common_mistakes: vec![
                            "Polling the tuned model instead of the operation returned by create.".into(),
                        ],
                        examples: vec![r#"{"operation": "tunedModels/support-bot/operations/op-123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("google-ai.tuning.create"),
                            CapabilityId::from_static("google-ai.tuning.cancel"),
                        ],
                    },
                ),
                op_info_with_approval(
                    "google-ai.tuning.cancel",
                    "Cancel a running tuned model operation",
                    json!({
                        "type": "object",
                        "required": ["operation"],
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "Full operation resource, for example tunedModels/support-bot/operations/op-123"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["status", "operation"],
                        "properties": {
                            "status": { "type": "string" },
                            "operation": { "type": "string" },
                            "provenance": { "type": "object" }
                        }
                    }),
                    "google-ai.tuning",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    Some(ApprovalMode::ElevationToken),
                    AgentHint {
                        when_to_use: "Stop a tuned model job that is no longer desired or was started with the wrong dataset.".into(),
                        common_mistakes: vec![
                            "Cancelling the wrong operation when multiple jobs exist.".into(),
                        ],
                        examples: vec![r#"{"operation": "tunedModels/support-bot/operations/op-123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("google-ai.tuning.get_operation"),
                        ],
                    },
                ),
                op_info(
                    "google-ai.get_usage",
                    "Return local usage and cost totals for the current connector session",
                    json!({ "type": "object", "properties": {} }),
                    json!({
                        "type": "object",
                        "required": ["total_input_tokens", "total_output_tokens", "requests_total", "requests_error"],
                        "properties": {
                            "total_input_tokens": { "type": "integer" },
                            "total_output_tokens": { "type": "integer" },
                            "requests_total": { "type": "integer" },
                            "requests_error": { "type": "integer" }
                        }
                    }),
                    "google-ai.usage",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect connector token usage counters for the current session.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![
                            CapabilityId::from_static("google-ai.generate_content"),
                        ],
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
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
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
            // dja9u.1.a: verify_bound returns CapabilityToken<BoundVerified>;
            // discarded here because invoke has no downstream that consumes
            // the typestate yet, but the call enforces the typestate handoff.
            let _bound = verifier.verify_bound(token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "google-ai.generate_content" => self.invoke_generate_content(input).await,
            "google-ai.generate_content_stream" => self.invoke_generate_content_stream(input).await,
            "google-ai.live.create_browser_session" => {
                self.invoke_live_create_browser_session(input).await
            }
            "google-ai.embed_content" => self.invoke_embed_content(input).await,
            "google-ai.batch_embed_contents" => self.invoke_batch_embed_contents(input).await,
            "google-ai.count_tokens" => self.invoke_count_tokens(input).await,
            "google-ai.list_models" => self.invoke_list_models(input).await,
            "google-ai.get_model" => self.invoke_get_model(input).await,
            "google-ai.tuning.create" => self.invoke_create_tuned_model(input).await,
            "google-ai.tuning.list" => self.invoke_list_tuned_models(input).await,
            "google-ai.tuning.get" => self.invoke_get_tuned_model(input).await,
            "google-ai.tuning.get_operation" => self.invoke_get_tuning_operation(input).await,
            "google-ai.tuning.cancel" => self.invoke_cancel_tuning_operation(input).await,
            "google-ai.get_usage" => self.invoke_get_usage(),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_generate_content(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("gemini-2.0-flash");

        let resp = client
            .generate_content(model, &input)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;

        let has_tool_calls = resp.candidates.iter().any(|c| {
            c.content.as_ref().is_some_and(|content| {
                content
                    .parts
                    .iter()
                    .any(|p| matches!(p, crate::types::Part::FunctionCall { .. }))
            })
        });

        let mut result = serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })?;
        result["provenance"] = json!({
            "source": "google-ai",
            "model": model,
            "integrity": "untrusted",
            "has_tool_calls": has_tool_calls,
            "chunk_count": 1,
        });
        Ok(result)
    }

    async fn invoke_generate_content_stream(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("gemini-2.0-flash");

        let chunks = client
            .generate_content_stream(model, &input)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;

        // Merge all chunks into a combined response
        let chunk_count = chunks.len();
        let mut all_candidates = Vec::new();
        let mut final_usage = None;
        for chunk in chunks {
            all_candidates.extend(chunk.candidates);
            if chunk.usage_metadata.is_some() {
                final_usage = chunk.usage_metadata;
            }
        }

        let has_tool_calls = all_candidates.iter().any(|c| {
            c.content.as_ref().is_some_and(|content| {
                content
                    .parts
                    .iter()
                    .any(|p| matches!(p, crate::types::Part::FunctionCall { .. }))
            })
        });

        Ok(json!({
            "candidates": all_candidates,
            "usage_metadata": final_usage,
            "provenance": {
                "source": "google-ai",
                "model": model,
                "integrity": "untrusted",
                "has_tool_calls": has_tool_calls,
                "chunk_count": chunk_count,
            },
        }))
    }

    async fn invoke_live_create_browser_session(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request: GoogleLiveBrowserSessionRequest =
            parse_request(input, "create Google Live browser session")?;
        request
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1003,
                message,
            })?;

        let response = client
            .create_live_browser_session(&request)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        info!(
            model = %response.model,
            voice = %response.voice,
            "created Google Live browser session token"
        );
        let mut result = serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })?;
        result["provenance"] = json!({
            "source": "google-ai",
            "action": "live.create_browser_session",
            "api_version": crate::types::GOOGLE_LIVE_BROWSER_API_VERSION,
            "integrity": "untrusted",
            "client_secret_redacted_in_logs": true,
        });
        Ok(result)
    }

    async fn invoke_embed_content(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("text-embedding-004");

        let resp = client
            .embed_content(model, &input)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_batch_embed_contents(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("text-embedding-004");

        let resp = client
            .batch_embed_contents(model, &input)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_count_tokens(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("gemini-2.0-flash");

        let resp = client
            .count_tokens(model, &input)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        Ok(json!({ "total_tokens": resp.total_tokens }))
    }

    async fn invoke_list_models(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let resp = client
            .list_models(page_size, page_token)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_model(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let model = require_str(&input, "model")?;

        let resp = client
            .get_model(model)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_create_tuned_model(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request: CreateTunedModelRequest = parse_request(input, "create tuned model")?;
        request
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1003,
                message,
            })?;

        let response = client
            .create_tuned_model(&request)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        info!(
            operation = %response.name,
            source_model = %request.source_model,
            "submitted Google AI tuned model create request"
        );
        let mut result = serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })?;
        result["provenance"] = json!({
            "source": "google-ai",
            "action": "tuning.create",
            "source_model": request.source_model,
            "integrity": "untrusted",
        });
        Ok(result)
    }

    async fn invoke_list_tuned_models(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request: ListTunedModelsRequest = parse_request(input, "list tuned models")?;
        request
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1003,
                message,
            })?;

        let response = client
            .list_tuned_models(&request)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_tuned_model(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request: GetTunedModelRequest = parse_request(input, "get tuned model")?;
        request
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1003,
                message,
            })?;

        let response = client
            .get_tuned_model(&request)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_tuning_operation(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request: GetTuningOperationRequest = parse_request(input, "get tuning operation")?;
        request
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1003,
                message,
            })?;

        let response = client
            .get_tuning_operation(&request)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        let mut result = serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })?;
        result["provenance"] = json!({
            "source": "google-ai",
            "action": "tuning.get_operation",
            "integrity": "untrusted",
        });
        Ok(result)
    }

    async fn invoke_cancel_tuning_operation(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request: CancelTuningOperationRequest =
            parse_request(input, "cancel tuning operation")?;
        request
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1003,
                message,
            })?;

        client
            .cancel_tuning_operation(&request)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        info!(operation = %request.operation, "requested Google AI tuned model cancel");
        Ok(json!({
            "status": "cancel_requested",
            "operation": request.operation,
            "provenance": {
                "source": "google-ai",
                "action": "tuning.cancel",
                "integrity": "untrusted",
            }
        }))
    }

    fn invoke_get_usage(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let usage = client.get_usage();
        Ok(json!({
            "total_input_tokens": usage.input_tokens,
            "total_output_tokens": usage.output_tokens,
            "requests_total": usage.requests_total,
            "requests_error": usage.requests_error,
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Google AI connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GoogleAiConnector {
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

fn parse_request<T>(input: serde_json::Value, label: &str) -> FcpResult<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    serde_json::from_value(input).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid {label} input: {e}"),
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
    op_info_with_approval(
        id,
        summary,
        input_schema,
        output_schema,
        capability,
        risk_level,
        safety_tier,
        idempotency,
        None,
        ai_hints,
    )
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info_with_approval(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    requires_approval: Option<ApprovalMode>,
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
        requires_approval,
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
    use fcp_manifest::{ConnectorManifest, NetworkConstraints};
    use std::path::PathBuf;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        op: &str,
        instance_id: &str,
    ) -> CapabilityToken {
        let cap = match op {
            "google-ai.generate_content" | "google-ai.generate_content_stream" => {
                "google-ai.generate"
            }
            "google-ai.live.create_browser_session" => "google-ai.live_voice",
            "google-ai.embed_content" | "google-ai.batch_embed_contents" => "google-ai.embed",
            "google-ai.count_tokens" | "google-ai.list_models" | "google-ai.get_model" => {
                "google-ai.models"
            }
            "google-ai.tuning.create"
            | "google-ai.tuning.list"
            | "google-ai.tuning.get"
            | "google-ai.tuning.get_operation"
            | "google-ai.tuning.cancel" => "google-ai.tuning",
            "google-ai.get_usage" => "google-ai.usage",
            _ => "google-ai.generate",
        };
        let now = Utc::now();
        let constraints = fcp_prelude::CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor)
            .expect("serialize test constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn invalid_request_message(err: FcpError) -> String {
        match err {
            FcpError::InvalidRequest { message, .. } => message,
            other => format!("unexpected error variant: {other:?}"),
        }
    }

    const GOOGLE_AI_EXTERNAL_NETWORK_OPS: &[&str] = &[
        "google-ai.batch_embed_contents",
        "google-ai.count_tokens",
        "google-ai.embed_content",
        "google-ai.generate_content",
        "google-ai.generate_content_stream",
        "google-ai.live.create_browser_session",
        "google-ai.get_model",
        "google-ai.list_models",
        "google-ai.tuning.create",
        "google-ai.tuning.list",
        "google-ai.tuning.get",
        "google-ai.tuning.get_operation",
        "google-ai.tuning.cancel",
    ];

    fn operation_network_constraints<'a>(
        manifest: &'a ConnectorManifest,
        operation: &str,
    ) -> &'a NetworkConstraints {
        manifest
            .provides
            .operations
            .get(operation)
            .unwrap_or_else(|| panic!("manifest missing operation {operation}"))
            .network_constraints
            .as_ref()
            .unwrap_or_else(|| panic!("{operation} missing network_constraints"))
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = GoogleAiConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["google-ai.generate"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = GoogleAiConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
        assert_eq!(result["auth"], "unconfigured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_configured_with_api_key() {
        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "base_url": "http://localhost:9999/v1beta"
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert_eq!(result["auth"], "api_key:redacted");
    }

    // ── Provisioning: strict auth mode validation ──────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_api_key_mode() {
        let mut connector = GoogleAiConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "test-key-123" }))
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["status"], "configured");
        assert!(connector.config.is_some());
        assert!(!connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id_mode() {
        let mut connector = GoogleAiConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await;
        assert!(result.is_ok());
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_ambiguous_auth_rejected() {
        let mut connector = GoogleAiConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "test-key",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
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
    async fn test_configure_missing_auth_rejected() {
        let mut connector = GoogleAiConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing api_key or credential_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_invalid_credential_id_rejected() {
        let mut connector = GoogleAiConnector::new();
        let result = connector
            .handle_configure(json!({ "credential_id": "not-a-uuid" }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("valid UUID"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_empty_api_key_rejected() {
        let mut connector = GoogleAiConnector::new();
        let result = connector.handle_configure(json!({ "api_key": "  " })).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing api_key or credential_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn validate_base_url_accepts_google_ai_and_local_test_hosts() {
        assert_eq!(
            validate_google_ai_base_url("https://generativelanguage.googleapis.com/v1beta/")
                .unwrap(),
            "https://generativelanguage.googleapis.com/v1beta"
        );
        assert_eq!(
            validate_google_ai_base_url("http://localhost:9999/v1beta").unwrap(),
            "http://localhost:9999/v1beta"
        );
        assert_eq!(
            validate_google_ai_base_url("http://127.0.0.1:9999/v1beta").unwrap(),
            "http://127.0.0.1:9999/v1beta"
        );
        assert_eq!(
            validate_google_ai_base_url("http://[::1]:9999/v1beta").unwrap(),
            "http://[::1]:9999/v1beta"
        );
    }

    #[test]
    fn validate_base_url_rejects_unsafe_components() {
        for (raw, expected) in [
            (
                "https://evil.example.com/v1beta",
                "generativelanguage.googleapis.com",
            ),
            (
                "https://evil.example.com/generativelanguage.googleapis.com/v1beta",
                "generativelanguage.googleapis.com",
            ),
            (
                "http://generativelanguage.googleapis.com/v1beta",
                "https unless targeting localhost",
            ),
            (
                "https://attacker:pw@generativelanguage.googleapis.com/v1beta",
                "userinfo",
            ),
            (
                "https://generativelanguage.googleapis.com/v1beta?key=leak",
                "query string",
            ),
            (
                "https://generativelanguage.googleapis.com/v1beta#fragment",
                "fragment",
            ),
            ("", "empty"),
            ("not a url", "absolute URL"),
        ] {
            let err = validate_google_ai_base_url(raw).unwrap_err();
            let message = invalid_request_message(err);
            assert!(
                message.contains(expected),
                "expected {raw:?} error {message:?} to contain {expected:?}"
            );
        }
    }

    #[test]
    fn configure_params_rejects_non_string_base_url() {
        let err = GoogleAiConfig::from_params(&json!({
            "api_key": "test-key",
            "base_url": 123
        }))
        .unwrap_err();

        let message = invalid_request_message(err);
        assert!(message.contains("base_url must be a string"));
    }

    // ── Doctor checks ──────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = GoogleAiConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(!checks.is_empty());
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_api_key() {
        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "base_url": "http://localhost:9999/v1beta"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        // Localhost passes network constraint, direct API key passes injection check
        let checks = result["checks"].as_array().unwrap();
        let config_check = checks
            .iter()
            .find(|c| c["name"] == "configuration")
            .unwrap();
        assert_eq!(config_check["passed"], true);

        let auth_check = checks.iter().find(|c| c["name"] == "auth_mode").unwrap();
        assert!(
            auth_check["message"]
                .as_str()
                .unwrap()
                .contains("api_key:redacted")
        );

        let injection_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(injection_check["passed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        // credential_id mode → credential_injection check is non-critical fail → degraded
        assert_eq!(result["status"], "degraded");

        let checks = result["checks"].as_array().unwrap();
        let injection_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(injection_check["passed"], false);
        assert!(
            injection_check["message"]
                .as_str()
                .unwrap()
                .contains("egress proxy")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_bad_host() {
        let mut connector = GoogleAiConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "test-key",
                "base_url": "https://evil.example.com/v1"
            }))
            .await;
        assert!(result.is_err());
        let message = invalid_request_message(result.unwrap_err());
        assert!(message.contains("generativelanguage.googleapis.com"));
    }

    // ── Self-check ─────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = GoogleAiConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_mode() {
        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "models": [{"name": "models/gemini-2.0-flash"}]
            })))
            .mount(&mock_server)
            .await;

        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "base_url": format!("{}/v1beta", mock_server.uri())
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_auth_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&mock_server)
            .await;

        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "bad-key",
                "base_url": format!("{}/v1beta", mock_server.uri())
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "self_check_failed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_retryable_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .mount(&mock_server)
            .await;

        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "base_url": format!("{}/v1beta", mock_server.uri())
            }))
            .await
            .unwrap();

        // Override retry config to avoid test slowness
        if let Some(client) = &mut connector.client {
            *client = GoogleAiClient::new_with_auth(GoogleAiAuth::ApiKey("test-key".into()))
                .unwrap()
                .with_base_url(&format!("{}/v1beta", mock_server.uri()))
                .with_retry_config(0);
        }

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "self_check_retryable");
    }

    // ── Original tests (invoke, introspect, manifest) ──────────────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = GoogleAiConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["google-ai.generate_content"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "google-ai.generate_content",
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "google-ai.generate_content",
                "input": { "contents": [{"role": "user", "parts": [{"text": "Hello"}]}] },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_usage_without_config() {
        let mut connector = GoogleAiConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["google-ai.get_usage"]
            }))
            .await
            .unwrap();

        let token =
            generate_valid_token(&signing_key, "google-ai.get_usage", connector.instance_id());
        let result = connector
            .handle_invoke(json!({
                "operation": "google-ai.get_usage",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "base_url": "http://localhost:9999/v1beta"
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
                "capabilities_requested": ["google-ai.get_model"]
            }))
            .await
            .unwrap();

        let token =
            generate_valid_token(&signing_key, "google-ai.get_model", connector.instance_id());
        let result = connector
            .handle_invoke(json!({
                "operation": "google-ai.get_model",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("model")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = GoogleAiConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"google-ai.generate_content"));
        assert!(op_ids.contains(&"google-ai.generate_content_stream"));
        assert!(op_ids.contains(&"google-ai.live.create_browser_session"));
        assert!(op_ids.contains(&"google-ai.embed_content"));
        assert!(op_ids.contains(&"google-ai.batch_embed_contents"));
        assert!(op_ids.contains(&"google-ai.count_tokens"));
        assert!(op_ids.contains(&"google-ai.list_models"));
        assert!(op_ids.contains(&"google-ai.get_model"));
        assert!(op_ids.contains(&"google-ai.tuning.create"));
        assert!(op_ids.contains(&"google-ai.tuning.list"));
        assert!(op_ids.contains(&"google-ai.tuning.get"));
        assert!(op_ids.contains(&"google-ai.tuning.get_operation"));
        assert!(op_ids.contains(&"google-ai.tuning.cancel"));
        assert!(op_ids.contains(&"google-ai.get_usage"));
        assert_eq!(ops.len(), 14);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_tuned_model_validates_examples() {
        let mut connector = GoogleAiConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "base_url": "http://127.0.0.1:9/v1beta"
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
                "capabilities_requested": ["google-ai.tuning"]
            }))
            .await
            .unwrap();
        let token = generate_valid_token(
            &signing_key,
            "google-ai.tuning.create",
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "google-ai.tuning.create",
                "input": {
                    "source_model": "models/gemini-1.5-flash-001",
                    "tuning_task": {
                        "training_data": {
                            "examples": []
                        }
                    }
                },
                "capability_token": token
            }))
            .await;

        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("at least one example"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_tuning_dangerous_ops_require_approval_metadata() {
        let connector = GoogleAiConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for id in ["google-ai.tuning.create", "google-ai.tuning.cancel"] {
            let op = ops
                .iter()
                .find(|op| op["id"] == id)
                .unwrap_or_else(|| panic!("missing op {id}"));
            assert_eq!(op["requires_approval"], "elevation_token");
        }
    }

    #[test]
    fn manifest_declares_per_operation_network_constraints() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");

        assert_eq!(
            manifest.provides.operations.len(),
            GOOGLE_AI_EXTERNAL_NETWORK_OPS.len() + 1,
            "manifest operation set should stay aligned with Google AI egress coverage"
        );

        for operation in GOOGLE_AI_EXTERNAL_NETWORK_OPS {
            let constraints = operation_network_constraints(&manifest, operation);
            assert_eq!(
                constraints.host_allow,
                vec!["generativelanguage.googleapis.com".to_owned()],
                "{operation} should be pinned to the Google AI API host"
            );
            assert_eq!(constraints.port_allow, vec![443], "{operation}");
            assert!(constraints.require_sni, "{operation}");
            assert!(constraints.deny_localhost, "{operation}");
            assert!(constraints.deny_private_ranges, "{operation}");
            assert!(constraints.deny_tailnet_ranges, "{operation}");
            assert!(constraints.deny_ip_literals, "{operation}");
            assert!(constraints.require_host_canonicalization, "{operation}");
        }

        let constraints = operation_network_constraints(&manifest, "google-ai.get_usage");
        assert_eq!(constraints.host_allow, vec!["none.invalid".to_owned()]);
        assert_eq!(constraints.port_allow, vec![0]);
        assert!(!constraints.require_sni);
        assert_eq!(constraints.dns_max_ips, 0);
        assert_eq!(constraints.max_redirects, 0);
        assert!(constraints.deny_localhost);
        assert!(constraints.deny_private_ranges);
        assert!(constraints.deny_tailnet_ranges);
        assert!(constraints.deny_ip_literals);
        assert!(constraints.require_host_canonicalization);
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
