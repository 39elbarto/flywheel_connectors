//! FCP Google AI Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::GoogleAiClient;
use crate::error::GoogleAiError;

/// FCP Google AI Connector.
pub struct GoogleAiConnector {
    base: Arc<BaseConnector>,
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
            client: None,
            verifier: None,
            session_id: None,
        }
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

        let mut client = GoogleAiClient::new(api_key).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Google AI connector configured");

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
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
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
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "google-ai.generate_content" => self.invoke_generate_content(input).await,
            "google-ai.generate_content_stream" => self.invoke_generate_content_stream(input).await,
            "google-ai.embed_content" => self.invoke_embed_content(input).await,
            "google-ai.batch_embed_contents" => self.invoke_batch_embed_contents(input).await,
            "google-ai.count_tokens" => self.invoke_count_tokens(input).await,
            "google-ai.list_models" => self.invoke_list_models(input).await,
            "google-ai.get_model" => self.invoke_get_model(input).await,
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
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
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
        let mut all_candidates = Vec::new();
        let mut final_usage = None;
        for chunk in chunks {
            all_candidates.extend(chunk.candidates);
            if chunk.usage_metadata.is_some() {
                final_usage = chunk.usage_metadata;
            }
        }

        Ok(json!({
            "candidates": all_candidates,
            "usage_metadata": final_usage,
        }))
    }

    async fn invoke_embed_content(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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

    async fn invoke_count_tokens(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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

    async fn invoke_list_models(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let resp = client
            .list_models(page_size, page_token)
            .await
            .map_err(|e: GoogleAiError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_model(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
    pub async fn handle_shutdown(&self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
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
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
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
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

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
    }

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

        let token = generate_valid_token(&signing_key, "google-ai.generate_content");
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

        let token = generate_valid_token(&signing_key, "google-ai.get_usage");
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
        connector.client = Some(
            GoogleAiClient::new("test-key")
                .unwrap()
                .with_base_url("http://localhost:9999/v1beta"),
        );

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

        let token = generate_valid_token(&signing_key, "google-ai.get_model");
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
        assert!(op_ids.contains(&"google-ai.embed_content"));
        assert!(op_ids.contains(&"google-ai.batch_embed_contents"));
        assert!(op_ids.contains(&"google-ai.count_tokens"));
        assert!(op_ids.contains(&"google-ai.list_models"));
        assert!(op_ids.contains(&"google-ai.get_model"));
        assert!(op_ids.contains(&"google-ai.get_usage"));
        assert_eq!(ops.len(), 8);
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
        let computed = manifest.compute_interface_hash().expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2.compute_interface_hash().expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
