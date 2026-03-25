//! Perplexity Search connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::PerplexityClient;
use crate::types::{ChatCompletionRequest, ChatMessage, PerplexityAuth};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SEARCH: &str = "perplexity-search.query";

const CAP_SEARCH: &str = "perplexity-search.query";

// ── Config ──

#[derive(Clone, Deserialize)]
pub struct PerplexityConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(flatten)]
    pub auth: PerplexityAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Default model to use when the caller does not specify one.
    #[serde(default = "default_model")]
    pub default_model: String,
}

fn default_base_url() -> String {
    "https://api.perplexity.ai".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

fn default_model() -> String {
    "sonar".into()
}

impl std::fmt::Debug for PerplexityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerplexityConfig")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("default_model", &self.default_model)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish_non_exhaustive()
    }
}

impl PerplexityConfig {
    fn validate(&self) -> Result<(), String> {
        let base_url = self.base_url.trim();
        if base_url.is_empty() {
            return Err("base_url cannot be empty".into());
        }
        let parsed = reqwest::Url::parse(base_url)
            .map_err(|e| format!("base_url must be a valid absolute URL: {e}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("base_url must use http or https".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than zero".into());
        }
        if self.default_model.trim().is_empty() {
            return Err("default_model must not be empty".into());
        }
        Ok(())
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let config: Self = serde_json::from_value(value).map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Invalid configuration: {e}"),
        })?;
        config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message,
            })?;
        Ok(config)
    }
}

// ── Doctor ──

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

// ── Connector ──

#[derive(Debug)]
pub struct PerplexitySearchConnector {
    base: BaseConnector,
    config: Option<PerplexityConfig>,
    client: Option<PerplexityClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl PerplexitySearchConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.perplexity-search")),
            config: None,
            client: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut digest = Sha256::new();
        digest.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(digest.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: self
                .config
                .as_ref()
                .map(|_| "Configuration loaded".into())
                .or_else(|| Some("Not configured".into())),
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: self
                .client
                .as_ref()
                .map(|_| "Client initialized".into())
                .or_else(|| Some("Client not initialized".into())),
            critical: true,
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: config.base_url.starts_with("https://"),
                message: Some(format!("API URL: {}", config.base_url)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth".into(),
                passed: !config.auth.is_secretless(),
                message: Some(if config.auth.is_secretless() {
                    "API key not configured (credential injection required)".into()
                } else {
                    "API key configured".into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "model".into(),
                passed: true,
                message: Some(format!("Default model: {}", config.default_model)),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }

    fn capability_for_operation(operation: &str) -> Option<CapabilityId> {
        match operation {
            OP_SEARCH => Some(CapabilityId::from_static(CAP_SEARCH)),
            _ => None,
        }
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing string field: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        let Some(verifier) = &self.verifier else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        };
        let Some(capability) = Self::capability_for_operation(operation) else {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        };
        verifier.verify(&req.capability_token, &capability, &req.operation, &[])?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Perplexity client".into(),
        })?;
        let config = self.config.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing config".into(),
        })?;

        let output = match operation {
            OP_SEARCH => {
                let query = Self::require_str(&req.input, "query")?;
                let model = req
                    .input
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&config.default_model);

                // Build system prompt if provided
                let system_prompt = req.input.get("system_prompt").and_then(|v| v.as_str());

                let mut messages = Vec::new();
                if let Some(sys) = system_prompt {
                    messages.push(ChatMessage {
                        role: "system".into(),
                        content: sys.to_string(),
                    });
                }
                messages.push(ChatMessage {
                    role: "user".into(),
                    content: query.to_string(),
                });

                #[allow(clippy::cast_possible_truncation)]
                let max_tokens = req
                    .input
                    .get("max_tokens")
                    .and_then(serde_json::Value::as_u64)
                    .map(|v| v.min(u64::from(u32::MAX)) as u32);

                let temperature = req
                    .input
                    .get("temperature")
                    .and_then(serde_json::Value::as_f64);

                let top_p = req.input.get("top_p").and_then(serde_json::Value::as_f64);

                #[allow(clippy::cast_possible_truncation)]
                let top_k = req
                    .input
                    .get("top_k")
                    .and_then(serde_json::Value::as_u64)
                    .map(|v| v.min(u64::from(u32::MAX)) as u32);

                let search_domain_filter = req
                    .input
                    .get("search_domain_filter")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    });

                let return_images = req
                    .input
                    .get("return_images")
                    .and_then(serde_json::Value::as_bool);

                let return_related_questions = req
                    .input
                    .get("return_related_questions")
                    .and_then(serde_json::Value::as_bool);

                let search_recency_filter = req
                    .input
                    .get("search_recency_filter")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let presence_penalty = req
                    .input
                    .get("presence_penalty")
                    .and_then(serde_json::Value::as_f64);

                let frequency_penalty = req
                    .input
                    .get("frequency_penalty")
                    .and_then(serde_json::Value::as_f64);

                let chat_req = ChatCompletionRequest {
                    model: model.to_string(),
                    messages,
                    max_tokens,
                    temperature,
                    top_p,
                    search_domain_filter,
                    return_images,
                    return_related_questions,
                    search_recency_filter,
                    top_k,
                    stream: Some(false),
                    presence_penalty,
                    frequency_penalty,
                };

                let resp = client
                    .chat_completions(&chat_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                // Build a user-friendly output
                let answer = resp
                    .choices
                    .first()
                    .map_or("", |c| c.message.content.as_str());

                json!({
                    "answer": answer,
                    "model": resp.model,
                    "citations": resp.citations.unwrap_or_default(),
                    "usage": resp.usage,
                    "id": resp.id,
                    "finish_reason": resp.choices.first().and_then(|c| c.finish_reason.as_deref()),
                })
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

impl Default for PerplexitySearchConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ──

fn schema(required: &[&str]) -> serde_json::Value {
    if required.is_empty() {
        json!({ "type": "object" })
    } else {
        json!({ "type": "object", "required": required })
    }
}

fn operations_info() -> Vec<OperationInfo> {
    vec![OperationInfo {
        id: OperationId::from_static(OP_SEARCH),
        summary: "Execute a grounded Perplexity web research query".into(),
        description: Some(
            "Sends a query to the Perplexity chat completions API (sonar model family) \
             and returns the answer with web citations."
                .into(),
        ),
        input_schema: json!({
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": { "type": "string", "description": "The research question to answer" },
                "model": { "type": "string", "description": "Model to use (default: sonar)" },
                "system_prompt": { "type": "string", "description": "Optional system prompt to guide the search" },
                "max_tokens": { "type": "integer", "description": "Maximum tokens in the response" },
                "temperature": { "type": "number", "description": "Sampling temperature (0.0-2.0)" },
                "top_p": { "type": "number", "description": "Nucleus sampling threshold" },
                "top_k": { "type": "integer", "description": "Top-k sampling parameter" },
                "search_domain_filter": { "type": "array", "items": { "type": "string" }, "description": "Restrict search to these domains" },
                "return_images": { "type": "boolean", "description": "Include image results" },
                "return_related_questions": { "type": "boolean", "description": "Include related questions" },
                "search_recency_filter": { "type": "string", "enum": ["month", "week", "day", "hour"], "description": "Filter results by recency" }
            }
        }),
        output_schema: schema(&["answer"]),
        capability: CapabilityId::from_static(CAP_SEARCH),
        risk_level: RiskLevel::Medium,
        safety_tier: SafetyTier::Safe,
        idempotency: IdempotencyClass::None,
        ai_hints: AgentHint {
            when_to_use: "Use this operation to search the web for current, grounded information with citations. Ideal for fact-checking, research queries, and getting up-to-date answers.".into(),
            common_mistakes: vec![
                "Sending very long queries that exceed model context limits".into(),
                "Expecting structured data output (responses are natural language)".into(),
            ],
            examples: vec![],
            related: Vec::new(),
        },
        rate_limit: None,
        requires_approval: None,
    }]
}

// ── FcpConnector trait impl ──

#[async_trait]
impl FcpConnector for PerplexitySearchConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let perplexity = PerplexityConfig::from_value(config)?;
        let client = PerplexityClient::new(
            perplexity.auth.clone(),
            perplexity.retry.clone(),
            Duration::from_millis(perplexity.request_timeout_ms),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?
        .with_base_url(&perplexity.base_url);

        self.client = Some(client);
        self.config = Some(perplexity);
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

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
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
        let mut snapshot = if self.config.is_some() && self.client.is_some() {
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
                "API key not configured; credential injection is required for health checks",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(e) if e.is_retryable() => Ok(SelfCheckReport::degraded(
                "self_check_retryable",
                e.to_string(),
            )),
            Err(e) => Ok(SelfCheckReport::failed("self_check_failed", e.to_string())),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
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

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_core::{CapabilityToken, ConnectorId, RequestId, SelfCheckStatus, ZoneId};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    fn valid_config() -> serde_json::Value {
        json!({
            "api_key": "pplx-test-key"
        })
    }

    fn signing_key_and_pub() -> (Ed25519SigningKey, [u8; 32]) {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_SEARCH)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn generate_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(CAP_SEARCH)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[OP_SEARCH])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .sign(signing_key)
            .expect("capability token signing should succeed");
        CapabilityToken { raw }
    }

    fn invoke_req(input: serde_json::Value, token: CapabilityToken) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("pp-test-1"),
            connector_id: ConnectorId::from_static("fcp.perplexity-search"),
            operation: OperationId::from_static(OP_SEARCH),
            zone_id: ZoneId::work(),
            input,
            capability_token: token,
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
    fn new_connector_starts_unconfigured() {
        assert!(PerplexitySearchConnector::new().config.is_none());
    }

    #[test]
    fn manifest_hash_is_stable() {
        assert_eq!(
            PerplexitySearchConnector::manifest_hash(),
            PerplexitySearchConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_accepts_api_key() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            assert!(connector.client.is_some());
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_empty_base_url() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            let err = connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "base_url": ""
                }))
                .await
                .unwrap_err();
            match err {
                FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1001),
                other => panic!("expected InvalidRequest, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_zero_timeout() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            let err = connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "request_timeout_ms": 0
                }))
                .await
                .unwrap_err();
            match err {
                FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1001),
                other => panic!("expected InvalidRequest, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn configure_uses_defaults() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let config = connector.config.as_ref().unwrap();
            assert_eq!(config.base_url, "https://api.perplexity.ai");
            assert_eq!(config.default_model, "sonar");
            assert_eq!(config.request_timeout_ms, 30_000);
        })
        .unwrap();
    }

    #[test]
    fn configure_custom_model() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "default_model": "sonar-pro"
                }))
                .await
                .unwrap();
            assert_eq!(
                connector.config.as_ref().unwrap().default_model,
                "sonar-pro"
            );
        })
        .unwrap();
    }

    #[test]
    fn health_degraded_before_configure() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = PerplexitySearchConnector::new();
            let health = connector.health().await;
            assert!(!health.is_ready());
        })
        .unwrap();
    }

    #[test]
    fn health_ready_after_configure() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let health = connector.health().await;
            assert!(health.is_ready());
        })
        .unwrap();
    }

    #[test]
    fn self_check_degraded_before_configure() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = PerplexitySearchConnector::new();
            let report = connector.self_check().await.unwrap();
            assert_eq!(report.status, SelfCheckStatus::Degraded);
        })
        .unwrap();
    }

    #[test]
    fn self_check_degraded_for_secretless() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(json!({ "api_key": "" })).await.unwrap();
            let report = connector.self_check().await.unwrap();
            assert_eq!(report.status, SelfCheckStatus::Degraded);
        })
        .unwrap();
    }

    #[test]
    fn doctor_passes_after_configure() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let result = connector.doctor();
            assert!(result.passed);
        })
        .unwrap();
    }

    #[test]
    fn doctor_fails_before_configure() {
        let connector = PerplexitySearchConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
    }

    #[test]
    fn introspect_lists_search_operation() {
        let connector = PerplexitySearchConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 1);
        assert_eq!(intro.operations[0].id.as_str(), OP_SEARCH);
        assert_eq!(intro.operations[0].risk_level, RiskLevel::Medium);
        assert_eq!(intro.operations[0].safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn shutdown_clears_state() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            connector
                .shutdown(ShutdownRequest {
                    r#type: "shutdown".into(),
                    deadline_ms: 5_000,
                    drain: false,
                    reason: None,
                })
                .await
                .unwrap();
            assert!(connector.config.is_none());
            assert!(connector.client.is_none());
        })
        .unwrap();
    }

    #[test]
    fn invoke_rejects_unknown_operation() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let token = generate_token(&sk);
            let req = InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("pp-unknown-op"),
                connector_id: ConnectorId::from_static("fcp.perplexity-search"),
                operation: OperationId::from_static("perplexity-search.nonexistent"),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: token,
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: vec![],
            };
            let err = connector.invoke(req).await.unwrap_err();
            match err {
                FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1004),
                other => panic!("expected InvalidRequest, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn invoke_rejects_missing_query() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let token = generate_token(&sk);
            let req = invoke_req(json!({}), token);
            let err = connector.invoke(req).await.unwrap_err();
            match err {
                FcpError::InvalidRequest { code, message } => {
                    assert_eq!(code, 1005);
                    assert!(message.contains("query"));
                }
                other => panic!("expected InvalidRequest, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_with_mock_server() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer pplx-test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-test-123",
                "model": "sonar",
                "object": "chat.completion",
                "created": 1_700_000_000u64,
                "choices": [{
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "Rust is a systems programming language focused on safety and performance."
                    },
                    "delta": null
                }],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 15,
                    "total_tokens": 27
                },
                "citations": [
                    "https://www.rust-lang.org/",
                    "https://doc.rust-lang.org/book/"
                ]
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let token = generate_token(&sk);
        let req = invoke_req(
            json!({
                "query": "What is Rust?",
                "temperature": 0.5
            }),
            token,
        );

        let resp = connector.invoke(req).await.unwrap();
        let output = resp.result.expect("result should be present");
        assert_eq!(
            output["answer"],
            "Rust is a systems programming language focused on safety and performance."
        );
        assert_eq!(output["model"], "sonar");
        assert_eq!(output["citations"].as_array().unwrap().len(), 2);
        assert_eq!(output["usage"]["total_tokens"], 27);
        assert_eq!(output["finish_reason"], "stop");
        assert_eq!(output["id"], "chatcmpl-test-123");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_handles_401() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": {
                    "message": "Invalid API Key",
                    "type": "authentication_error"
                }
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-bad-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let token = generate_token(&sk);
        let req = invoke_req(json!({ "query": "test" }), token);

        let err = connector.invoke(req).await.unwrap_err();
        match err {
            FcpError::Unauthorized { .. } => {} // expected
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_handles_429() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "error": {
                    "message": "Rate limit exceeded",
                    "type": "rate_limit_error"
                }
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri(),
                "retry": { "max_retries": 0 }
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let token = generate_token(&sk);
        let req = invoke_req(json!({ "query": "test" }), token);

        let err = connector.invoke(req).await.unwrap_err();
        match err {
            FcpError::RateLimited { .. } => {} // expected
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_with_system_prompt() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-sys-prompt",
                "model": "sonar",
                "object": "chat.completion",
                "created": 1_700_000_000u64,
                "choices": [{
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "Guided answer with system context."
                    },
                    "delta": null
                }],
                "citations": []
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let token = generate_token(&sk);
        let req = invoke_req(
            json!({
                "query": "What is Rust?",
                "system_prompt": "You are a concise technical writer."
            }),
            token,
        );

        let resp = connector.invoke(req).await.unwrap();
        let output = resp.result.expect("result should be present");
        assert_eq!(output["answer"], "Guided answer with system context.");
    }

    #[test]
    fn config_debug_redacts_api_key() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let debug = format!("{:?}", connector.config.as_ref().unwrap());
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("pplx-test-key"));
        })
        .unwrap();
    }

    #[test]
    fn subscribe_returns_not_supported() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = PerplexitySearchConnector::new();
            let err = connector
                .subscribe(SubscribeRequest {
                    r#type: "subscribe".into(),
                    id: RequestId::new("sub-test"),
                    topics: vec![],
                    since: None,
                    max_events_per_sec: None,
                    batch_ms: None,
                    window_size: None,
                    capability_token: None,
                })
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::StreamingNotSupported));
        })
        .unwrap();
    }
}
