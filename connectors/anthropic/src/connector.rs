//! FCP Anthropic Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{AnthropicAuth, AnthropicClient, DEFAULT_API_VERSION, DEFAULT_BASE_URL},
    error::AnthropicError,
    types::{Message, Model, Role, Tool, ToolChoice, Usage},
};

/// Parsed and validated Anthropic connector configuration.
#[derive(Debug, Clone)]
struct AnthropicConfig {
    auth: AnthropicAuth,
    base_url: String,
    api_version: Option<String>,
}

impl AnthropicConfig {
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
            (Some(key), None) => AnthropicAuth::ApiKey(key),
            (None, Some(cred_id)) => AnthropicAuth::CredentialId(cred_id),
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

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .map_or_else(
                || Ok(DEFAULT_BASE_URL.to_string()),
                validate_anthropic_base_url,
            )?;

        let api_version = match params.get("api_version") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "api_version must be a string".into(),
                })?;
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            None => None,
        };

        Ok(Self {
            auth,
            base_url,
            api_version,
        })
    }
}

fn validate_anthropic_base_url(base_url: &str) -> FcpResult<String> {
    let parsed =
        parse_anthropic_base_url(base_url).map_err(|message| FcpError::InvalidRequest {
            code: 1003,
            message,
        })?;

    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn parse_anthropic_base_url(base_url: &str) -> Result<Url, String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err("base_url must not be empty".into());
    }

    let parsed = Url::parse(trimmed).map_err(|err| format!("Invalid base_url: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    let normalized_host = host
        .trim()
        .trim_end_matches('.')
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    let local = matches!(normalized_host.as_str(), "localhost" | "127.0.0.1" | "::1");
    let allowed_host = normalized_host == "api.anthropic.com" || local;
    let valid_scheme = if local {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };
    if !allowed_host || !valid_scheme {
        return Err(format!(
            "base_url must use https and api.anthropic.com (localhost/127.0.0.1/::1 allowed over http/https for tests): {trimmed}"
        ));
    }

    let root_path = matches!(parsed.path(), "" | "/");
    if !root_path || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must be an origin without path, query, or fragment: {trimmed}"
        ));
    }

    Ok(parsed)
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    /// Overall status.
    status: DoctorStatus,
    /// Individual check results.
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    /// All checks passed.
    Healthy,
    /// Some non-critical checks failed.
    Degraded,
    /// Critical checks failed.
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    /// Check name.
    name: String,
    /// Check passed.
    passed: bool,
    /// Check message.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Whether this check is critical.
    critical: bool,
}

impl DoctorResult {
    /// Create a new doctor result from checks.
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

/// FCP Anthropic Connector.
pub struct AnthropicConnector {
    base: Arc<BaseConnector>,
    config: Option<AnthropicConfig>,
    client: Option<AnthropicClient>,
    total_cost: AtomicU64, // Store as fixed-point (cost * 1_000_000_000)
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl AnthropicConnector {
    /// Create a new Anthropic connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("anthropic"))),
            config: None,
            client: None,
            total_cost: AtomicU64::new(0),
            verifier: None,
            session_id: None,
        }
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.base.metrics().requests_total
    }

    /// Get total errors.
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.base.metrics().requests_error
    }

    /// Get total cost in dollars.
    #[must_use]
    pub fn total_cost(&self) -> f64 {
        self.total_cost.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
    }

    /// Track cost from usage.
    fn track_cost(&self, usage: &Usage, model: Model) {
        let cost = usage.calculate_cost(model);
        let cost_fixed = (cost * 1_000_000_000.0) as u64;
        self.total_cost.fetch_add(cost_fixed, Ordering::Relaxed);
    }

    /// Handle configure method.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration parameters are invalid or the HTTP client
    /// cannot be created.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = AnthropicConfig::from_params(&params)?;

        let client = AnthropicClient::new_with_auth_and_version(
            config.auth.clone(),
            config.api_version.as_deref(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;
        let client = client.with_base_url(&config.base_url);

        let auth_label = config.auth.redacted_label();
        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_label, "Anthropic connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake request is malformed or serialization fails.
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
            manifest_hash: "sha256:anthropic-connector-v1".into(),
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
    ///
    /// # Errors
    ///
    /// Returns an error if health status serialization fails (should not happen).
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
        let api_version = self.client.as_ref().map_or_else(
            || DEFAULT_API_VERSION.to_string(),
            |client| client.api_version().to_string(),
        );
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "auth": auth,
            "base_url": base_url,
            "api_version": api_version,
            "metrics": {
                "requests_total": self.total_requests(),
                "requests_error": self.total_errors(),
                "total_cost_usd": self.total_cost()
            }
        }))
    }

    /// Handle doctor checks.
    ///
    /// Returns a structured readiness report without leaking secrets.
    ///
    /// # Errors
    ///
    /// Returns an error if the doctor result cannot be serialized.
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
        let parsed_base_url = Url::parse(&config.base_url).ok();
        let scheme = parsed_base_url
            .as_ref()
            .map_or("unknown", |parsed| parsed.scheme());

        checks.push(DoctorCheck {
            name: "base_url".into(),
            passed: parsed_base_url.is_some(),
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

        checks.push(DoctorCheck {
            name: "api_version".into(),
            passed: true,
            message: Some(format!(
                "Anthropic API version: {}",
                self.client
                    .as_ref()
                    .map_or(DEFAULT_API_VERSION, AnthropicClient::api_version)
            )),
            critical: false,
        });

        // Check 5: Network constraints - host must be api.anthropic.com (or test override)
        let network_validation = parse_anthropic_base_url(&config.base_url);
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: network_validation.is_ok(),
            message: Some(match network_validation {
                Ok(_) => "Base URL matches Anthropic endpoint policy".into(),
                Err(message) => message,
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
    /// Performs a safe, read-only API call to validate the API key is valid
    /// and the Anthropic API is reachable. Does not leak secrets in the report.
    ///
    /// # Errors
    ///
    /// Returns an error if the self-check report cannot be serialized.
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
    ///
    /// # Errors
    ///
    /// Returns an error if introspection serialization fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("anthropic.message"),
                    summary: "Send a message to Claude".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["claude-opus-4-5-20251101", "claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-5-sonnet-20241022"],
                                "default": "claude-sonnet-4-20250514"
                            },
                            "messages": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "role": { "type": "string", "enum": ["user", "assistant"] },
                                        "content": { "type": "string" }
                                    },
                                    "required": ["role", "content"]
                                }
                            },
                            "system": { "type": "string" },
                            "max_tokens": { "type": "integer", "default": 4096 },
                            "temperature": { "type": "number", "minimum": 0, "maximum": 1 }
                        },
                        "required": ["messages"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "content": { "type": "string" },
                            "model": { "type": "string" },
                            "stop_reason": { "type": "string" },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "input_tokens": { "type": "integer" },
                                    "output_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("anthropic.message"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to Claude and get a response.".into(),
                        common_mistakes: vec![
                            "Not providing messages array".into(),
                            "Exceeding context length".into(),
                        ],
                        examples: vec![
                            r#"{"messages": [{"role": "user", "content": "Hello!"}]}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("anthropic.chat"),
                    summary: "Simple chat with Claude (single message)".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["claude-opus-4-5-20251101", "claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-5-sonnet-20241022"],
                                "default": "claude-sonnet-4-20250514"
                            },
                            "message": { "type": "string" },
                            "system": { "type": "string" },
                            "max_tokens": { "type": "integer", "default": 4096 }
                        },
                        "required": ["message"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "response": { "type": "string" },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "input_tokens": { "type": "integer" },
                                    "output_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("anthropic.chat"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Simple single-turn chat with Claude.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"message": "What is 2+2?"}"#.into()],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("anthropic.message.stream"),
                    summary: "Stream a message response from Claude via SSE".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["claude-opus-4-5-20251101", "claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-5-sonnet-20241022"],
                                "default": "claude-sonnet-4-20250514"
                            },
                            "messages": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "role": { "type": "string", "enum": ["user", "assistant"] },
                                        "content": { "type": "string" }
                                    },
                                    "required": ["role", "content"]
                                }
                            },
                            "system": { "type": "string" },
                            "max_tokens": { "type": "integer", "default": 4096 },
                            "temperature": { "type": "number", "minimum": 0, "maximum": 1 },
                            "tools": { "type": "array", "description": "Optional tool definitions" },
                            "tool_choice": { "type": "object", "description": "Optional tool selection policy" }
                        },
                        "required": ["messages"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "content": { "type": "string" },
                            "content_blocks": { "type": "array" },
                            "model": { "type": "string" },
                            "stop_reason": { "type": "string" },
                            "streamed": { "type": "boolean" },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "input_tokens": { "type": "integer" },
                                    "output_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("anthropic.message.stream"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Stream Claude responses token-by-token via SSE for lower latency."
                                .into(),
                        common_mistakes: vec![
                            "Not handling SSE events incrementally.".into(),
                            "Not providing messages array.".into(),
                        ],
                        examples: vec![
                            r#"{"messages": [{"role": "user", "content": "Write a poem"}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("anthropic.message"),
                            CapabilityId::from_static("anthropic.chat"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("anthropic.get_usage"),
                    summary: "Get current usage and cost statistics".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {}
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "total_input_tokens": { "type": "integer" },
                            "total_output_tokens": { "type": "integer" },
                            "total_cost_usd": { "type": "number" },
                            "requests_total": { "type": "integer" },
                            "requests_error": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("anthropic.get_usage"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Check usage and costs for this session.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
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
    ///
    /// # Errors
    ///
    /// Returns an error if the simulate request is malformed or serialization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is invalid, capability token verification
    /// fails, required parameters are missing, or the API call fails.
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

        // Extract and verify capability token
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

        // Verify token
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

        let mut resource_uris = Vec::new();
        if operation == "anthropic.message"
            || operation == "anthropic.message.stream"
            || operation == "anthropic.chat"
        {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("claude-sonnet-4-20250514");
            resource_uris.push(format!("anthropic:model:{model}"));
        }

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "anthropic.message" => self.invoke_message(input).await,
            "anthropic.message.stream" => self.invoke_message_stream(input).await,
            "anthropic.chat" => self.invoke_chat(input).await,
            "anthropic.get_usage" => self.invoke_get_usage().await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("claude-sonnet-4-20250514");

        let model = match model_str {
            "claude-opus-4-5-20251101" => Model::ClaudeOpus4_5,
            "claude-sonnet-4-20250514" => Model::ClaudeSonnet4,
            "claude-3-5-haiku-20241022" => Model::Claude3_5Haiku,
            "claude-3-5-sonnet-20241022" => Model::Claude3_5Sonnet,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown model: {model_str}"),
                });
            }
        };

        // Parse messages
        let messages_json = input.get("messages").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing messages".into(),
        })?;

        let messages: Vec<Message> =
            serde_json::from_value(messages_json.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid messages format: {e}"),
                }
            })?;

        if messages.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Messages array cannot be empty".into(),
            });
        }

        let system = input.get("system").and_then(|v| v.as_str());
        let max_tokens = match input.get("max_tokens").and_then(|v| v.as_u64()) {
            Some(v) if v > u64::from(u32::MAX) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("max_tokens value {} exceeds maximum {}", v, u32::MAX),
                });
            }
            Some(v) => v as u32,
            None => 4096,
        };
        let temperature = input.get("temperature").and_then(|v| v.as_f64());

        // Parse tools if provided
        let tools: Option<Vec<Tool>> = input
            .get("tools")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid tools format: {e}"),
            })?;

        let tool_choice: Option<ToolChoice> = input
            .get("tool_choice")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid tool_choice format: {e}"),
            })?;

        let response = client
            .message(
                model,
                messages,
                max_tokens,
                system,
                temperature,
                tools,
                tool_choice,
            )
            .await
            .map_err(|e: AnthropicError| e.to_fcp_error())?;

        let cost = response.usage.calculate_cost(model);
        self.track_cost(&response.usage, model);

        // Build structured content blocks preserving tool_use
        let content_blocks: Vec<serde_json::Value> = response
            .content
            .iter()
            .map(|b| match b {
                crate::types::ResponseContentBlock::Text { text } => {
                    json!({"type": "text", "text": text})
                }
                crate::types::ResponseContentBlock::ToolUse { id, name, input } => {
                    json!({"type": "tool_use", "id": id, "name": name, "input": input})
                }
            })
            .collect();

        // Extract text for convenience field
        let text_content: String = response
            .content
            .iter()
            .filter_map(|b| b.as_text())
            .collect::<Vec<_>>()
            .join("");

        let has_tool_calls = response
            .content
            .iter()
            .any(|b| matches!(b, crate::types::ResponseContentBlock::ToolUse { .. }));

        Ok(json!({
            "id": response.id,
            "content": text_content,
            "content_blocks": content_blocks,
            "model": response.model,
            "stop_reason": response.stop_reason,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            },
            "cost_usd": cost,
            "provenance": {
                "source": "anthropic",
                "model": model_str,
                "integrity": "untrusted",
                "has_tool_calls": has_tool_calls,
                "chunk_count": 1,
                "taint": ["AI_GENERATED"]
            }
        }))
    }

    async fn invoke_message_stream(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use futures_util::StreamExt;
        use std::pin::pin;

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("claude-sonnet-4-20250514");

        let model = match model_str {
            "claude-opus-4-5-20251101" => Model::ClaudeOpus4_5,
            "claude-sonnet-4-20250514" => Model::ClaudeSonnet4,
            "claude-3-5-haiku-20241022" => Model::Claude3_5Haiku,
            "claude-3-5-sonnet-20241022" => Model::Claude3_5Sonnet,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown model: {model_str}"),
                });
            }
        };

        let messages_json = input.get("messages").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing messages".into(),
        })?;

        let messages: Vec<Message> =
            serde_json::from_value(messages_json.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid messages format: {e}"),
                }
            })?;

        if messages.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Messages array cannot be empty".into(),
            });
        }

        let system = input.get("system").and_then(|v| v.as_str());
        let max_tokens = match input.get("max_tokens").and_then(|v| v.as_u64()) {
            Some(v) if v > u64::from(u32::MAX) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("max_tokens value {} exceeds maximum {}", v, u32::MAX),
                });
            }
            Some(v) => v as u32,
            None => 4096,
        };
        let temperature = input.get("temperature").and_then(|v| v.as_f64());

        let tools: Option<Vec<Tool>> = input
            .get("tools")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid tools format: {e}"),
            })?;

        let tool_choice: Option<ToolChoice> = input
            .get("tool_choice")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid tool_choice format: {e}"),
            })?;

        // Use the streaming API and assemble the final response
        let stream = client
            .message_stream(
                model,
                messages,
                max_tokens,
                system,
                temperature,
                tools,
                tool_choice,
            )
            .await
            .map_err(|e: AnthropicError| e.to_fcp_error())?;
        let mut stream = pin!(stream);

        let mut message_id = String::new();
        let mut response_model = String::new();
        let mut stop_reason: Option<String> = None;
        let mut usage = Usage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };

        // Accumulate content blocks from the stream
        #[allow(clippy::items_after_statements)]
        struct BlockAccumulator {
            block_type: String,
            text: String,
            tool_id: String,
            tool_name: String,
            tool_input_json: String,
            closed: bool,
        }

        #[allow(clippy::items_after_statements)]
        fn invalid_stream_error(message: impl Into<String>) -> FcpError {
            FcpError::External {
                service: "anthropic".into(),
                message: message.into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            }
        }

        #[allow(clippy::items_after_statements)]
        fn block_slot(index: u32) -> Result<usize, FcpError> {
            usize::try_from(index).map_err(|_| {
                invalid_stream_error(format!(
                    "Anthropic stream block index {index} does not fit into usize"
                ))
            })
        }

        #[allow(clippy::items_after_statements)]
        fn stop_reason_value(reason: crate::types::StopReason) -> Result<String, FcpError> {
            match serde_json::to_value(reason) {
                Ok(serde_json::Value::String(value)) => Ok(value),
                Ok(other) => Err(invalid_stream_error(format!(
                    "Anthropic stop reason serialized to non-string value: {other}"
                ))),
                Err(error) => Err(invalid_stream_error(format!(
                    "Failed to serialize Anthropic stop reason: {error}"
                ))),
            }
        }

        #[allow(clippy::items_after_statements)]
        fn parse_tool_input_json(raw: &str) -> Result<serde_json::Value, FcpError> {
            if raw.is_empty() {
                return Ok(json!({}));
            }
            serde_json::from_str(raw).map_err(|error| {
                invalid_stream_error(format!(
                    "Anthropic stream emitted invalid tool input JSON: {error}"
                ))
            })
        }

        let mut blocks: Vec<Option<BlockAccumulator>> = Vec::new();

        while let Some(event_result) = stream.next().await {
            let event = event_result.map_err(|e: AnthropicError| e.to_fcp_error())?;

            match event {
                crate::types::StreamEvent::MessageStart { message: msg } => {
                    message_id = msg.id;
                    response_model = msg.model;
                    usage = msg.usage;
                }
                crate::types::StreamEvent::ContentBlockStart {
                    index,
                    content_block,
                } => {
                    let block_index = block_slot(index)?;
                    if blocks.len() <= block_index {
                        blocks.resize_with(block_index + 1, || None);
                    }
                    if blocks[block_index].is_some() {
                        return Err(invalid_stream_error(format!(
                            "Anthropic stream reopened content block at index {index}"
                        )));
                    }
                    let block = match content_block {
                        crate::types::ContentBlockStartData::Text { text } => BlockAccumulator {
                            block_type: "text".into(),
                            text,
                            tool_id: String::new(),
                            tool_name: String::new(),
                            tool_input_json: String::new(),
                            closed: false,
                        },
                        crate::types::ContentBlockStartData::ToolUse { id, name, .. } => {
                            BlockAccumulator {
                                block_type: "tool_use".into(),
                                text: String::new(),
                                tool_id: id,
                                tool_name: name,
                                tool_input_json: String::new(),
                                closed: false,
                            }
                        }
                    };
                    blocks[block_index] = Some(block);
                }
                crate::types::StreamEvent::ContentBlockDelta { index, delta } => {
                    let block_index = block_slot(index)?;
                    let block = blocks
                        .get_mut(block_index)
                        .and_then(Option::as_mut)
                        .ok_or_else(|| {
                            invalid_stream_error(format!(
                                "Anthropic stream delta referenced unknown content block at index {index}"
                            ))
                        })?;
                    if block.closed {
                        return Err(invalid_stream_error(format!(
                            "Anthropic stream delta arrived after content block stop at index {index}"
                        )));
                    }
                    match delta {
                        crate::types::ContentDelta::TextDelta { text } => {
                            if block.block_type != "text" {
                                return Err(invalid_stream_error(format!(
                                    "Anthropic stream sent text delta for non-text block at index {index}"
                                )));
                            }
                            block.text.push_str(&text);
                        }
                        crate::types::ContentDelta::InputJsonDelta { partial_json } => {
                            if block.block_type != "tool_use" {
                                return Err(invalid_stream_error(format!(
                                    "Anthropic stream sent tool JSON delta for non-tool block at index {index}"
                                )));
                            }
                            block.tool_input_json.push_str(&partial_json);
                        }
                    }
                }
                crate::types::StreamEvent::MessageDelta {
                    delta,
                    usage: delta_usage,
                } => {
                    if let Some(sr) = delta.stop_reason {
                        stop_reason = Some(stop_reason_value(sr)?);
                    }
                    usage.output_tokens = delta_usage.output_tokens;
                }
                crate::types::StreamEvent::ContentBlockStop { index } => {
                    let block_index = block_slot(index)?;
                    let block = blocks
                        .get_mut(block_index)
                        .and_then(Option::as_mut)
                        .ok_or_else(|| {
                            invalid_stream_error(format!(
                                "Anthropic stream stopped unknown content block at index {index}"
                            ))
                        })?;
                    if block.closed {
                        return Err(invalid_stream_error(format!(
                            "Anthropic stream stopped content block twice at index {index}"
                        )));
                    }
                    block.closed = true;
                }
                crate::types::StreamEvent::MessageStop | crate::types::StreamEvent::Ping => {}
                crate::types::StreamEvent::Error { error } => {
                    return Err(FcpError::External {
                        service: "anthropic".into(),
                        message: error.message,
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    });
                }
            }
        }

        let cost = usage.calculate_cost(model);
        self.track_cost(&usage, model);

        // Build content blocks
        let content_blocks: Vec<serde_json::Value> = blocks
            .iter()
            .filter_map(Option::as_ref)
            .map(|b| {
                if b.block_type == "tool_use" {
                    parse_tool_input_json(&b.tool_input_json).map(|parsed_input| {
                        json!({"type": "tool_use", "id": b.tool_id, "name": b.tool_name, "input": parsed_input})
                    })
                } else {
                    Ok(json!({"type": "text", "text": b.text}))
                }
            })
            .collect::<Result<_, _>>()?;

        let text_content: String = blocks
            .iter()
            .filter_map(Option::as_ref)
            .filter(|b| b.block_type == "text")
            .map(|b| b.text.as_str())
            .collect::<Vec<_>>()
            .join("");

        let has_tool_calls = blocks
            .iter()
            .filter_map(Option::as_ref)
            .any(|b| b.block_type == "tool_use");
        let chunk_count = content_blocks.len();

        Ok(json!({
            "id": message_id,
            "content": text_content,
            "content_blocks": content_blocks,
            "model": response_model,
            "stop_reason": stop_reason,
            "usage": {
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens
            },
            "cost_usd": cost,
            "streamed": true,
            "provenance": {
                "source": "anthropic",
                "model": model_str,
                "integrity": "untrusted",
                "has_tool_calls": has_tool_calls,
                "chunk_count": chunk_count,
                "taint": ["AI_GENERATED"]
            }
        }))
    }

    async fn invoke_chat(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("claude-sonnet-4-20250514");

        let model = match model_str {
            "claude-opus-4-5-20251101" => Model::ClaudeOpus4_5,
            "claude-sonnet-4-20250514" => Model::ClaudeSonnet4,
            "claude-3-5-haiku-20241022" => Model::Claude3_5Haiku,
            "claude-3-5-sonnet-20241022" => Model::Claude3_5Sonnet,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown model: {model_str}"),
                });
            }
        };

        let message =
            input
                .get("message")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing message".into(),
                })?;

        let system = input.get("system").and_then(|v| v.as_str());
        let max_tokens = match input.get("max_tokens").and_then(|v| v.as_u64()) {
            Some(v) if v > u64::from(u32::MAX) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("max_tokens value {} exceeds maximum {}", v, u32::MAX),
                });
            }
            Some(v) => v as u32,
            None => 4096,
        };

        // Build messages
        let messages = vec![Message {
            role: Role::User,
            content: message.into(),
        }];

        let response = client
            .message(model, messages, max_tokens, system, None, None, None)
            .await
            .map_err(|e: AnthropicError| e.to_fcp_error())?;

        let cost = response.usage.calculate_cost(model);
        self.track_cost(&response.usage, model);

        // Extract text content
        let text_content: String = response
            .content
            .iter()
            .filter_map(|b| b.as_text())
            .collect::<Vec<_>>()
            .join("");

        Ok(json!({
            "response": text_content,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            },
            "cost_usd": cost,
            "provenance": {
                "source": "anthropic",
                "model": model_str,
                "integrity": "untrusted",
                "has_tool_calls": false,
                "chunk_count": 1,
                "taint": ["AI_GENERATED"]
            }
        }))
    }

    async fn invoke_get_usage(&self) -> FcpResult<serde_json::Value> {
        let (input_tokens, output_tokens) = if let Some(client) = &self.client {
            (client.total_input_tokens(), client.total_output_tokens())
        } else {
            (0, 0)
        };
        let requests_total = self.total_requests().saturating_add(1);

        Ok(json!({
            "total_input_tokens": input_tokens,
            "total_output_tokens": output_tokens,
            "total_cost_usd": self.total_cost(),
            "requests_total": requests_total,
            "requests_error": self.total_errors()
        }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown serialization fails (should not happen).
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Anthropic connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for AnthropicConnector {
    fn default() -> Self {
        Self::new()
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
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
        let cap = match op {
            "anthropic.message" => "anthropic.message",
            "anthropic.chat" => "anthropic.chat",
            "anthropic.message.stream" => "anthropic.message.stream",
            "anthropic.get_usage" => "anthropic.get_usage",
            _ => "anthropic.message",
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
        CapabilityToken::from_raw(cose)
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = AnthropicConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.message"]
            }))
            .await
            .unwrap();

        // HandshakeResponse does not include connector_id in V2
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = AnthropicConnector::new();
        let result = connector.handle_health().await.unwrap();

        assert_eq!(result["status"], "not_configured");
        assert_eq!(result["auth"], "unconfigured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_configured() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-test-key"
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert_eq!(result["auth"], "api_key:redacted");
        assert_eq!(result["base_url"], DEFAULT_BASE_URL);
        assert_eq!(result["api_version"], DEFAULT_API_VERSION);
    }

    // --- Configure tests ---

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_api_key() {
        let mut connector = AnthropicConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "sk-test-123" }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(!connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = AnthropicConnector::new();
        let cred_uuid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({ "credential_id": cred_uuid }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_both_api_key_and_credential_id_rejected() {
        let mut connector = AnthropicConnector::new();
        let cred_uuid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "credential_id": cred_uuid
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_no_auth_rejected() {
        let mut connector = AnthropicConnector::new();
        let result = connector.handle_configure(json!({})).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing api_key or credential_id"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_non_anthropic_base_url() {
        let mut connector = AnthropicConnector::new();
        let err = connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "base_url": "https://custom.api.example.com"
            }))
            .await
            .expect_err("non-Anthropic endpoint must be rejected");
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("api.anthropic.com"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_base_url_with_api_path() {
        let mut connector = AnthropicConnector::new();
        let err = connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "base_url": "https://api.anthropic.com/v1"
            }))
            .await
            .expect_err("pathful base_url must be rejected");
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("without path, query, or fragment"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_api_version() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "api_version": " 2024-10-22 "
            }))
            .await
            .unwrap();

        assert_eq!(
            connector.config.as_ref().unwrap().api_version.as_deref(),
            Some("2024-10-22")
        );
        assert_eq!(
            connector.client.as_ref().unwrap().api_version(),
            "2024-10-22"
        );
    }

    // --- Doctor tests ---

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = AnthropicConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        assert_eq!(doctor.status, DoctorStatus::Unhealthy);
        assert!(!doctor.checks[0].passed); // configuration check fails
        assert!(doctor.checks[0].critical);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_api_key() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({ "api_key": "sk-test" }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        assert_eq!(doctor.status, DoctorStatus::Healthy);
        for check in &doctor.checks {
            if check.critical {
                assert!(check.passed, "Critical check '{}' should pass", check.name);
            }
        }
        // Verify credential_injection check passes (not secretless)
        let cred_check = doctor
            .checks
            .iter()
            .find(|c| c.name == "credential_injection")
            .unwrap();
        assert!(cred_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = AnthropicConnector::new();
        let cred_uuid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cred_uuid }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        // Degraded because credential_injection check fails (non-critical)
        assert_eq!(doctor.status, DoctorStatus::Degraded);
        let cred_check = doctor
            .checks
            .iter()
            .find(|c| c.name == "credential_injection")
            .unwrap();
        assert!(!cred_check.passed);
        assert!(!cred_check.critical);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_network_constraints_bad_host() {
        let mut connector = AnthropicConnector::new();
        connector.config = Some(AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: "https://evil.example.com".into(),
            api_version: None,
        });
        connector.client = Some(
            AnthropicClient::new_with_auth(AnthropicAuth::ApiKey("sk-test".into()))
                .expect("client")
                .with_base_url("https://evil.example.com"),
        );
        connector.base.set_configured(true);

        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        assert_eq!(doctor.status, DoctorStatus::Unhealthy);
        let net_check = doctor
            .checks
            .iter()
            .find(|c| c.name == "network_constraints")
            .unwrap();
        assert!(!net_check.passed);
        assert!(net_check.critical);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_network_constraints_rejects_pathful_base_url() {
        let mut connector = AnthropicConnector::new();
        connector.config = Some(AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: "https://api.anthropic.com/v1".into(),
            api_version: None,
        });
        connector.client = Some(
            AnthropicClient::new_with_auth(AnthropicAuth::ApiKey("sk-test".into()))
                .expect("client")
                .with_base_url("https://api.anthropic.com/v1"),
        );
        connector.base.set_configured(true);

        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        assert_eq!(doctor.status, DoctorStatus::Unhealthy);
        let net_check = doctor
            .checks
            .iter()
            .find(|c| c.name == "network_constraints")
            .unwrap();
        assert!(!net_check.passed);
        assert!(
            net_check
                .message
                .as_deref()
                .is_some_and(|message| message.contains("without path, query, or fragment"))
        );
    }

    // --- Self-check tests ---

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = AnthropicConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_mode() {
        let mut connector = AnthropicConnector::new();
        let cred_uuid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cred_uuid }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_api_key_valid() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "sk-valid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_health",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "h"}],
                "model": "claude-3-5-haiku-20241022",
                "stop_reason": "max_tokens",
                "usage": { "input_tokens": 1, "output_tokens": 1 }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-valid",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        assert_eq!(report.status, fcp_core::SelfCheckStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_api_key_invalid() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": {
                    "type": "authentication_error",
                    "message": "Invalid API key"
                }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-bad",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        // InvalidApiKey is not retryable, so should be Failed
        assert_eq!(report.status, fcp_core::SelfCheckStatus::Failed);
        assert_eq!(report.reason_code.as_deref(), Some("self_check_failed"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "error": {
                    "type": "rate_limit_error",
                    "message": "Rate limit exceeded"
                }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();

        // Need to set retry to 0 to avoid actual retries in test
        if let Some(client) = &mut connector.client {
            // Recreate with no retries
            let new_client = AnthropicClient::new("sk-test")
                .unwrap()
                .with_base_url(mock_server.uri())
                .with_retry_config(1, 1, 1);
            *client = new_client;
        }

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        // Rate limited is retryable -> Degraded
        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("self_check_retryable"));
    }

    // --- Existing invoke tests ---

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = AnthropicConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        // Handshake first to setup verifier
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.chat"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "anthropic.chat");

        let result = connector
            .handle_invoke(json!({
                "operation": "anthropic.chat",
                "input": {
                    "message": "Hello"
                },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_message() {
        let mut connector = AnthropicConnector::new();
        // Configure with fake key
        connector.client = Some(
            AnthropicClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.config = Some(AnthropicConfig {
            auth: AnthropicAuth::ApiKey("fake_key".into()),
            base_url: "http://localhost:9999".into(),
            api_version: None,
        });

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "anthropic.message");

        let result = connector
            .handle_invoke(json!({
                "operation": "anthropic.message",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("messages"));
            }
            _ => panic!("Expected InvalidRequest for missing messages, got: {err:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_usage() {
        let mut connector = AnthropicConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.get_usage"]
            }))
            .await
            .unwrap();

        // Must grant the specific operation ID
        let token = generate_valid_token(&signing_key, "anthropic.get_usage");

        let result = connector
            .handle_invoke(json!({
                "operation": "anthropic.get_usage",
                "input": {},
                "capability_token": token
            }))
            .await
            .unwrap();

        assert_eq!(result["total_input_tokens"], 0);
        assert_eq!(result["total_output_tokens"], 0);
        assert_eq!(result["requests_total"], 1);
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

    // --- DoctorStatus serde lowercase ---

    #[test]
    fn doctor_status_serializes_lowercase() {
        let healthy = serde_json::to_string(&DoctorStatus::Healthy).unwrap();
        assert_eq!(healthy, "\"healthy\"");
        let degraded = serde_json::to_string(&DoctorStatus::Degraded).unwrap();
        assert_eq!(degraded, "\"degraded\"");
        let unhealthy = serde_json::to_string(&DoctorStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "\"unhealthy\"");
    }

    #[test]
    fn doctor_status_deserializes_lowercase() {
        let h: DoctorStatus = serde_json::from_str("\"healthy\"").unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_str("\"degraded\"").unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_str("\"unhealthy\"").unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_eq() {
        let a = DoctorStatus::Healthy;
        let b = a;
        let _ = a; // still usable after copy
        assert_eq!(a, b);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
    }

    // --- DoctorCheck skip_serializing_if message None ---

    #[test]
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn doctor_check_includes_message_when_some() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: false,
            message: Some("detail here".into()),
            critical: true,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("detail here"));
    }

    // --- DoctorResult roundtrip ---

    #[test]
    fn doctor_result_roundtrip() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "alpha".into(),
                passed: true,
                message: Some("ok".into()),
                critical: true,
            },
            DoctorCheck {
                name: "beta".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: DoctorResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.status, DoctorStatus::Degraded);
        assert_eq!(deserialized.checks.len(), 2);
        assert_eq!(deserialized.checks[0].name, "alpha");
        assert!(deserialized.checks[0].passed);
        assert!(!deserialized.checks[1].passed);
    }

    // --- DoctorResult debug and clone ---

    #[test]
    fn doctor_result_debug() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "check_a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("DoctorResult"));
        assert!(dbg.contains("Healthy"));
        assert!(dbg.contains("check_a"));
    }

    #[test]
    fn doctor_result_clone() {
        let original = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c1".into(),
            passed: false,
            message: Some("msg".into()),
            critical: true,
        }]);
        let cloned = original.clone();
        assert_eq!(original.status, DoctorStatus::Unhealthy);
        assert_eq!(cloned.checks.len(), 1);
        assert_eq!(cloned.checks[0].name, "c1");
        assert_eq!(cloned.checks[0].message.as_deref(), Some("msg"));
    }

    // --- AnthropicConnector default impl ---

    #[test]
    fn connector_default_impl() {
        let c = AnthropicConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert_eq!(c.total_cost(), 0.0);
        assert_eq!(c.total_requests(), 0);
        assert_eq!(c.total_errors(), 0);
    }

    // --- AnthropicConfig edge cases ---

    #[test]
    fn config_rejects_empty_trimmed_api_key() {
        let params = json!({ "api_key": "   " });
        let result = AnthropicConfig::from_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let params = json!({ "credential_id": 42 });
        let result = AnthropicConfig::from_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("string"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let params = json!({ "credential_id": "not-a-valid-uuid" });
        let result = AnthropicConfig::from_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("valid UUID"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_default_base_url_when_not_specified() {
        let params = json!({ "api_key": "sk-test" });
        let config = AnthropicConfig::from_params(&params).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert!(config.api_version.is_none());
    }

    #[test]
    fn config_rejects_non_string_api_version() {
        let params = json!({ "api_key": "sk-test", "api_version": 20241022 });
        let result = AnthropicConfig::from_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("api_version must be a string"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    // --- DoctorResult all healthy ---

    #[test]
    fn doctor_result_all_healthy() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    // --- DoctorCheck clone and debug ---

    #[test]
    fn doctor_check_clone_and_debug() {
        let original = DoctorCheck {
            name: "check_clone".into(),
            passed: true,
            message: Some("cloned".into()),
            critical: false,
        };
        let cloned = original.clone();
        assert_eq!(original.name, "check_clone");
        assert_eq!(cloned.name, "check_clone");
        assert!(cloned.passed);
        assert_eq!(cloned.message.as_deref(), Some("cloned"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    // --- track_cost accumulates correctly ---

    #[test]
    fn track_cost_accumulates() {
        let connector = AnthropicConnector::new();
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        // ClaudeSonnet4 input: 1M * $3/M = $3.00
        connector.track_cost(&usage, Model::ClaudeSonnet4);
        let cost1 = connector.total_cost();
        assert!((cost1 - 3.0).abs() < 0.01);

        // Track again, should accumulate
        connector.track_cost(&usage, Model::ClaudeSonnet4);
        let cost2 = connector.total_cost();
        assert!((cost2 - 6.0).abs() < 0.01);
    }
}
