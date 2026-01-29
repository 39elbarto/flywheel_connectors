//! FCP OpenAI Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::OpenAIClient,
    error::OpenAIError,
    types::{Message, Model, Tool, ToolChoice, Usage},
};

/// FCP OpenAI Connector.
pub struct OpenAIConnector {
    base: Arc<BaseConnector>,
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
        let api_key =
            params
                .get("api_key")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());
        let organization = params.get("organization").and_then(|v| v.as_str());

        let mut client = OpenAIClient::new(api_key).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        if let Some(org) = organization {
            client = client.with_organization(org);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("OpenAI connector configured");

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
        let configured = self.client.is_some();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": self.total_requests(),
                "requests_error": self.total_errors(),
                "total_cost_usd": self.total_cost()
            }
        }))
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
        self.base.record_request(true); // Optimistically count total

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
        let op_id = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;

        let mut resource_uris = Vec::new();
        if operation == "openai.chat" || operation == "openai.simple_chat" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("gpt-4o");
            resource_uris.push(format!("openai:model:{model}"));
        }

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &op_id, &resource_uris)?;
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
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("gpt-4o");

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
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("gpt-4o");

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
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

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
    async fn test_health_not_configured() {
        let connector = OpenAIConnector::new();
        let result = connector.handle_health().await.unwrap();

        assert_eq!(result["status"], "not_configured");
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
