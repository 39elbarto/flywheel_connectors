//! FCP OpenAI Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, OpenAIAuth, OpenAIClient},
    error::OpenAIError,
    types::{Message, Model, Tool, ToolChoice, Usage},
};

#[derive(Debug, Clone)]
struct OpenAIConfig {
    auth: OpenAIAuth,
    base_url: String,
    organization: Option<String>,
    default_model: Model,
    deployment_profile: Option<DeploymentProfile>,
}

#[derive(Debug, Clone)]
struct DeploymentProfile {
    name: Option<String>,
    base_url: Option<String>,
    organization: Option<String>,
    default_model: Option<Model>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentProfileObject {
    name: Option<String>,
    base_url: Option<String>,
    organization: Option<String>,
    default_model: Option<Model>,
}

impl From<DeploymentProfileObject> for DeploymentProfile {
    fn from(obj: DeploymentProfileObject) -> Self {
        Self {
            name: obj.name,
            base_url: obj.base_url,
            organization: obj.organization,
            default_model: obj.default_model,
        }
    }
}

impl OpenAIConfig {
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
            (Some(key), None) => OpenAIAuth::ApiKey(key),
            (None, Some(cred_id)) => OpenAIAuth::CredentialId(cred_id),
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

        let deployment_profile = parse_deployment_profile(params.get("deployment_profile"))?;

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| deployment_profile.as_ref().and_then(|p| p.base_url.clone()))
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

        let base_url = normalize_base_url(&base_url)?;

        let organization = params
            .get("organization")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                deployment_profile
                    .as_ref()
                    .and_then(|p| p.organization.clone())
            });

        let default_model = if let Some(model_value) = params.get("default_model") {
            serde_json::from_value(model_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid default_model: {e}"),
            })?
        } else if let Some(profile_model) =
            deployment_profile.as_ref().and_then(|p| p.default_model)
        {
            profile_model
        } else {
            Model::default()
        };

        Ok(Self {
            auth,
            base_url,
            organization,
            default_model,
            deployment_profile,
        })
    }

    fn deployment_profile_name(&self) -> Option<&str> {
        self.deployment_profile
            .as_ref()
            .and_then(|profile| profile.name.as_deref())
    }
}

fn parse_deployment_profile(
    value: Option<&serde_json::Value>,
) -> FcpResult<Option<DeploymentProfile>> {
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        serde_json::Value::String(name) => Ok(Some(DeploymentProfile {
            name: Some(name.clone()),
            base_url: None,
            organization: None,
            default_model: None,
        })),
        serde_json::Value::Object(_) => {
            let profile: DeploymentProfileObject =
                serde_json::from_value(value.clone()).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid deployment_profile: {e}"),
                })?;
            Ok(Some(profile.into()))
        }
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "deployment_profile must be a string or object".into(),
        }),
    }
}

fn normalize_base_url(base_url: &str) -> FcpResult<String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url cannot be empty".into(),
        });
    }

    let parsed = url::Url::parse(trimmed).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {e}"),
    })?;

    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must be http or https".into(),
        });
    }

    if parsed.host_str().is_none() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must include a host".into(),
        });
    }

    Ok(trimmed.trim_end_matches('/').to_string())
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

/// FCP OpenAI Connector.
pub struct OpenAIConnector {
    base: Arc<BaseConnector>,
    config: Option<OpenAIConfig>,
    client: Option<OpenAIClient>,
    total_cost: AtomicU64, // Store as fixed-point (cost * 1_000_000_000)
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl OpenAIConnector {
    /// Create a new OpenAI connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("openai"))),
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
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = OpenAIConfig::from_params(&params)?;
        let mut client =
            OpenAIClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        client = client.with_base_url(&config.base_url);
        if let Some(org) = &config.organization {
            client = client.with_organization(org);
        }

        let auth_label = config.auth.redacted_label();
        let deployment_profile = config.deployment_profile_name().map(str::to_string);

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        info!(
            auth = %auth_label,
            deployment_profile = ?deployment_profile,
            "OpenAI connector configured"
        );

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
            manifest_hash: "sha256:openai-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
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
        let configured = self.config.is_some();
        let auth = self
            .config
            .as_ref()
            .map(|c| c.auth.redacted_label())
            .unwrap_or_else(|| "unconfigured".to_string());
        let base_url = self
            .config
            .as_ref()
            .map(|c| c.base_url.clone())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let deployment_profile = self
            .config
            .as_ref()
            .and_then(|c| c.deployment_profile_name())
            .map(str::to_string);
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "auth": auth,
            "base_url": base_url,
            "deployment_profile": deployment_profile,
            "metrics": {
                "requests_total": self.total_requests(),
                "requests_error": self.total_errors(),
                "total_cost_usd": self.total_cost()
            }
        }))
    }

    /// Handle doctor checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
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

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

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

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth: {}", config.auth.redacted_label())),
            critical: true,
        });

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
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

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
                OperationInfo {
                    id: OperationId::from_static("openai.chat"),
                    summary: "Send a chat completion request".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
                                "default": "gpt-4o"
                            },
                            "messages": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "role": { "type": "string", "enum": ["system", "user", "assistant", "tool"] },
                                        "content": { "type": "string" }
                                    },
                                    "required": ["role", "content"]
                                }
                            },
                            "max_tokens": { "type": "integer", "default": 4096 },
                            "temperature": { "type": "number", "minimum": 0, "maximum": 2 }
                        },
                        "required": ["messages"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "content": { "type": "string" },
                            "model": { "type": "string" },
                            "finish_reason": { "type": "string" },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "prompt_tokens": { "type": "integer" },
                                    "completion_tokens": { "type": "integer" },
                                    "total_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.chat"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a chat completion request to OpenAI models.".into(),
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
                    id: OperationId::from_static("openai.simple_chat"),
                    summary: "Simple chat with GPT (single message)".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
                                "default": "gpt-4o"
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
                                    "prompt_tokens": { "type": "integer" },
                                    "completion_tokens": { "type": "integer" },
                                    "total_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.chat"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Simple single-turn chat with GPT models.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"message": "What is 2+2?"}"#.into()],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.get_usage"),
                    summary: "Get current usage and cost statistics".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {}
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "total_prompt_tokens": { "type": "integer" },
                            "total_completion_tokens": { "type": "integer" },
                            "total_cost_usd": { "type": "number" },
                            "requests_total": { "type": "integer" },
                            "requests_error": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.chat"),
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
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        let mut resource_uris = Vec::new();
        if operation == "openai.chat" || operation == "openai.simple_chat" {
            let default_model = self
                .config
                .as_ref()
                .map(|c| c.default_model.as_str())
                .unwrap_or(Model::default().as_str());
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(default_model);
            resource_uris.push(format!("openai:model:{model}"));
        }

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "openai.chat" => self.invoke_chat(input).await,
            "openai.simple_chat" => self.invoke_simple_chat(input).await,
            "openai.get_usage" => self.invoke_get_usage().await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_chat(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let default_model = self
            .config
            .as_ref()
            .map(|c| c.default_model)
            .unwrap_or_default();
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(default_model.as_str());

        let model = match model_str {
            "gpt-4o" => Model::Gpt4o,
            "gpt-4o-mini" => Model::Gpt4oMini,
            "gpt-4-turbo" => Model::Gpt4Turbo,
            "gpt-4" => Model::Gpt4,
            "gpt-3.5-turbo" => Model::Gpt35Turbo,
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

        let max_tokens = input.get("max_tokens").and_then(|v| v.as_u64()).map(|v| {
            if v > u64::from(u32::MAX) {
                u32::MAX
            } else {
                v as u32
            }
        });
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
            .chat_completion(model, messages, max_tokens, temperature, tools, tool_choice)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let usage = response.usage.unwrap_or_default();
        let cost = usage.calculate_cost(model);
        self.track_cost(&usage, model);

        // Extract content from first choice
        let content = response
            .choices
            .first()
            .and_then(|c| c.message.content.as_ref())
            .cloned()
            .unwrap_or_default();

        let finish_reason = response
            .choices
            .first()
            .and_then(|c| c.finish_reason)
            .map(|r| format!("{r:?}").to_lowercase());

        Ok(json!({
            "id": response.id,
            "content": content,
            "model": response.model,
            "finish_reason": finish_reason,
            "usage": {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens
            },
            "cost_usd": cost
        }))
    }

    async fn invoke_simple_chat(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let default_model = self
            .config
            .as_ref()
            .map(|c| c.default_model)
            .unwrap_or_default();
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(default_model.as_str());

        let model = match model_str {
            "gpt-4o" => Model::Gpt4o,
            "gpt-4o-mini" => Model::Gpt4oMini,
            "gpt-4-turbo" => Model::Gpt4Turbo,
            "gpt-4" => Model::Gpt4,
            "gpt-3.5-turbo" => Model::Gpt35Turbo,
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
        let max_tokens = input.get("max_tokens").and_then(|v| v.as_u64()).map(|v| {
            if v > u64::from(u32::MAX) {
                u32::MAX
            } else {
                v as u32
            }
        });

        // Build messages
        let mut messages = Vec::new();
        if let Some(sys) = system {
            messages.push(Message::system(sys));
        }
        messages.push(Message::user(message));

        let response = client
            .chat_completion(model, messages, max_tokens, None, None, None)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let usage = response.usage.unwrap_or_default();
        let cost = usage.calculate_cost(model);
        self.track_cost(&usage, model);

        // Extract content from first choice
        let text = response
            .choices
            .first()
            .and_then(|c| c.message.content.as_ref())
            .cloned()
            .unwrap_or_default();

        Ok(json!({
            "response": text,
            "usage": {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens
            },
            "cost_usd": cost
        }))
    }

    async fn invoke_get_usage(&self) -> FcpResult<serde_json::Value> {
        let (prompt_tokens, completion_tokens) = if let Some(client) = &self.client {
            (
                client.total_prompt_tokens(),
                client.total_completion_tokens(),
            )
        } else {
            (0, 0)
        };

        Ok(json!({
            "total_prompt_tokens": prompt_tokens,
            "total_completion_tokens": completion_tokens,
            "total_cost_usd": self.total_cost(),
            "requests_total": self.total_requests(),
            "requests_error": self.total_errors()
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("OpenAI connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for OpenAIConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, SecondsFormat, Utc};
    use fcp_core::CredentialId;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_testkit::LogCapture;
    use std::time::Instant;
    use uuid::Uuid;

    struct TestLog {
        test_name: &'static str,
        module: &'static str,
        correlation_id: String,
        start: Instant,
        assertions_passed: u32,
        assertions_failed: u32,
        capture: LogCapture,
    }

    impl TestLog {
        fn new(test_name: &'static str) -> Self {
            Self {
                test_name,
                module: "fcp-openai-connector",
                correlation_id: Uuid::new_v4().to_string(),
                start: Instant::now(),
                assertions_passed: 0,
                assertions_failed: 0,
                capture: LogCapture::new(),
            }
        }

        fn check(&mut self, condition: bool, message: &str) -> Result<(), String> {
            if !condition {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(message.to_string());
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn check_eq<T: std::fmt::Debug + PartialEq>(
            &mut self,
            left: T,
            right: T,
            context: &str,
        ) -> Result<(), String> {
            if left != right {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(format!("{context}: left={left:?} right={right:?}"));
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn emit(&mut self, phase: &str, result: &str, context: serde_json::Value) {
            let duration_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let entry = serde_json::json!({
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "log_version": "v1",
                "level": "info",
                "test_name": self.test_name,
                "module": self.module,
                "phase": phase,
                "correlation_id": self.correlation_id,
                "result": result,
                "duration_ms": duration_ms,
                "assertions": {
                    "passed": self.assertions_passed,
                    "failed": self.assertions_failed
                },
                "context": context
            });

            let serialized = serde_json::to_string(&entry).unwrap_or_else(|err| {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                format!("{{\"error\":\"log_serialization_failed\",\"detail\":\"{err}\"}}")
            });
            println!("{serialized}");
            let _ = self.capture.push_value(&entry);
            if !std::thread::panicking() {
                self.capture.assert_valid();
            }
        }
    }

    impl Drop for TestLog {
        fn drop(&mut self) {
            let result = if std::thread::panicking() {
                if self.assertions_failed == 0 {
                    self.assertions_failed = 1;
                }
                "fail"
            } else {
                "pass"
            };
            self.emit(
                "verify",
                result,
                serde_json::json!({ "connector_id": "openai" }),
            );
        }
    }

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

    #[tokio::test]
    async fn test_handshake() {
        let mut connector = OpenAIConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["openai.chat"]
            }))
            .await
            .unwrap();

        assert!(result.get("session_id").is_some());
        assert_eq!(result["status"], "accepted");
    }

    #[tokio::test]
    async fn test_configure_requires_auth() {
        let mut connector = OpenAIConnector::new();
        let result = connector.handle_configure(json!({})).await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[tokio::test]
    async fn test_configure_rejects_both_auth() {
        let mut connector = OpenAIConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "test-key",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[tokio::test]
    async fn test_configure_with_credential_id_profile() {
        let mut connector = OpenAIConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "deployment_profile": {
                    "name": "staging",
                    "base_url": "https://api.openai.com",
                    "default_model": "gpt-4o-mini"
                },
                "organization": "org-test"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");

        let config = connector.config.as_ref().expect("config should be set");
        assert!(matches!(config.auth, OpenAIAuth::CredentialId(_)));
        assert_eq!(config.base_url, "https://api.openai.com");
        assert_eq!(config.deployment_profile_name(), Some("staging"));
        assert_eq!(config.default_model, Model::Gpt4oMini);
        assert_eq!(
            config.organization.as_deref(),
            Some("org-test"),
            "organization should be stored"
        );

        let parsed = CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap();
        if let OpenAIAuth::CredentialId(cred) = &config.auth {
            assert_eq!(cred, &parsed);
        }
    }

    #[tokio::test]
    async fn test_health_not_configured() {
        let connector = OpenAIConnector::new();
        let result = connector.handle_health().await.unwrap();

        assert_eq!(result["status"], "not_configured");
    }

    #[tokio::test]
    async fn test_doctor_not_configured() -> Result<(), String> {
        let mut log = TestLog::new("openai_doctor_not_configured");
        let connector = OpenAIConnector::new();
        let value = connector
            .handle_doctor()
            .await
            .map_err(|err| format!("doctor failed: {err}"))?;
        let result: DoctorResult =
            serde_json::from_value(value).map_err(|err| format!("doctor parse failed: {err}"))?;

        log.check_eq(result.status, DoctorStatus::Unhealthy, "status")?;
        let config_check = result
            .checks
            .iter()
            .find(|check| check.name == "configuration")
            .ok_or("missing configuration check")?;
        log.check(!config_check.passed, "configuration should be unhealthy")?;
        Ok(())
    }

    #[tokio::test]
    async fn test_doctor_configured_api_key() -> Result<(), String> {
        let mut log = TestLog::new("openai_doctor_configured_api_key");
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({ "api_key": "test-key" }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let value = connector
            .handle_doctor()
            .await
            .map_err(|err| format!("doctor failed: {err}"))?;
        let result: DoctorResult =
            serde_json::from_value(value).map_err(|err| format!("doctor parse failed: {err}"))?;

        log.check_eq(result.status, DoctorStatus::Healthy, "status")?;
        Ok(())
    }

    #[tokio::test]
    async fn test_doctor_configured_credential_id() -> Result<(), String> {
        let mut log = TestLog::new("openai_doctor_configured_credential_id");
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let value = connector
            .handle_doctor()
            .await
            .map_err(|err| format!("doctor failed: {err}"))?;
        let result: DoctorResult =
            serde_json::from_value(value).map_err(|err| format!("doctor parse failed: {err}"))?;

        log.check_eq(result.status, DoctorStatus::Degraded, "status")?;
        let injection_check = result
            .checks
            .iter()
            .find(|check| check.name == "credential_injection")
            .ok_or("missing credential_injection check")?;
        log.check(
            !injection_check.passed,
            "credential_injection should be marked not passed",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_invoke_without_config() {
        let mut connector = OpenAIConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["openai.simple_chat"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "openai.simple_chat");

        let result = connector
            .handle_invoke(json!({
                "operation": "openai.simple_chat",
                "input": {
                    "message": "Hello"
                },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[tokio::test]
    async fn test_invoke_missing_message() {
        let mut connector = OpenAIConnector::new();
        // Configure with fake key
        connector.client = Some(
            OpenAIClient::new("fake_key")
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
                "capabilities_requested": ["openai.chat"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "openai.chat");

        let result = connector
            .handle_invoke(json!({
                "operation": "openai.chat",
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
            _ => assert!(
                false,
                "Expected InvalidRequest for missing messages, got: {err:?}"
            ),
        }
    }

    #[tokio::test]
    async fn test_get_usage() {
        let mut connector = OpenAIConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["openai.chat"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "openai.get_usage");

        let result = connector
            .handle_invoke(json!({
                "operation": "openai.get_usage",
                "input": {},
                "capability_token": token
            }))
            .await
            .unwrap();

        assert_eq!(result["total_prompt_tokens"], 0);
        assert_eq!(result["total_completion_tokens"], 0);
        assert_eq!(result["requests_total"], 1);
    }
}
