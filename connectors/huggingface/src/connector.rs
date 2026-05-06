//! Hugging Face connector implementation.

use std::sync::Arc;
use std::time::Duration;

use fcp_prelude::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde_json::{Value, json};
use tracing::info;

use crate::client::HuggingfaceClient;
use crate::types::{
    ModelListRequest, SummarizationParameters, SummarizationRequest, TextGenerationParameters,
    TextGenerationRequest,
};

const CONNECTOR_ID: &str = "fcp.huggingface";
const CONNECTOR_VERSION: &str = "0.2.0";

const OP_TEXT_GENERATION: &str = "huggingface.inference.text_generation";
const OP_SUMMARIZATION: &str = "huggingface.inference.summarization";
const OP_MODEL_LIST: &str = "huggingface.models.list";
const OP_MODEL_INFO: &str = "huggingface.models.info";

const DEFAULT_TEXT_GEN_MODEL: &str = "gpt2";
const DEFAULT_SUMMARIZATION_MODEL: &str = "facebook/bart-large-cnn";
const MAX_MODEL_LIST_LIMIT: u32 = 100;

pub struct HuggingfaceConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
    client: Option<HuggingfaceClient>,
    runtime: Option<ConnectorRuntime>,
    config: Option<HuggingfaceConfig>,
}

#[derive(Clone, serde::Deserialize)]
pub struct HuggingfaceConfig {
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub credential_id: Option<String>,
    #[serde(default = "default_inference_url")]
    pub inference_url: String,
    #[serde(default = "default_hub_url")]
    pub hub_url: String,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl std::fmt::Debug for HuggingfaceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HuggingfaceConfig")
            .field(
                "api_token",
                &if self.api_token.is_empty() {
                    "<empty>"
                } else {
                    "[REDACTED]"
                },
            )
            .field(
                "credential_id",
                &self
                    .credential_id
                    .as_ref()
                    .map_or("<empty>", |_| "[REDACTED]"),
            )
            .field("inference_url", &self.inference_url)
            .field("hub_url", &self.hub_url)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl HuggingfaceConfig {
    fn validate(&self) -> FcpResult<()> {
        let has_direct_auth = !self.api_token.trim().is_empty();
        let credential_id = self
            .credential_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        if has_direct_auth && credential_id.is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide api_token or credential_id, not both".into(),
            });
        }

        if let Some(raw) = credential_id {
            CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "credential_id must be a valid UUID".into(),
            })?;
        }

        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }

        Ok(())
    }

    fn has_direct_token(&self) -> bool {
        !self.api_token.trim().is_empty()
    }

    fn has_credential_id(&self) -> bool {
        self.credential_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    }
}

fn default_inference_url() -> String {
    "https://api-inference.huggingface.co".into()
}
fn default_hub_url() -> String {
    "https://huggingface.co/api".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

/// Safe conversion from u64 JSON number to u32, returning None on overflow.
fn safe_u32(v: u64) -> Option<u32> {
    u32::try_from(v).ok()
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl HuggingfaceConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            configured: false,
            handshaken: false,
            client: None,
            runtime: None,
            config: None,
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config: HuggingfaceConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;
        config.validate()?;

        let timeout = Duration::from_millis(config.request_timeout_ms);
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(timeout),
        ));

        let client = HuggingfaceClient::new(
            Some(&config.inference_url),
            Some(&config.hub_url),
            &config.api_token,
            config.retry.clone(),
            timeout,
        )
        .map_err(|e| e.to_fcp_error())?;

        self.client = Some(client);
        self.config = Some(config);
        self.configured = true;
        self.base.set_configured(true);

        info!(
            event = "huggingface.configure",
            connector_id = CONNECTOR_ID,
            "Configured Hugging Face connector"
        );

        Ok(json!({"connector_id": CONNECTOR_ID, "configured": true}))
    }

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if !self.configured {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["huggingface.inference", "huggingface.models"],
            "surface_status": "incubating",
            "surface_status_rationale": "Runtime path is incomplete or lacks production evidence"
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let has_direct_auth = self
            .config
            .as_ref()
            .is_some_and(HuggingfaceConfig::has_direct_token);
        let has_credential_id = self
            .config
            .as_ref()
            .is_some_and(HuggingfaceConfig::has_credential_id);
        let status = if self.configured && has_direct_auth {
            "ready"
        } else if self.configured {
            "degraded"
        } else {
            "unconfigured"
        };
        Ok(json!({
            "status": status,
            "configured": self.configured,
            "handshaken": self.handshaken,
            "auth_mode": if has_direct_auth {
                "api_token"
            } else if has_credential_id {
                "credential_id"
            } else {
                "anonymous"
            },
            "live_requests_supported": self.configured,
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let mut checks = vec![
            json!({ "name": "configuration", "passed": self.configured, "critical": true }),
            json!({ "name": "handshake", "passed": self.handshaken, "critical": false }),
            json!({ "name": "client_initialized", "passed": self.client.is_some(), "critical": true }),
            json!({ "name": "runtime_initialized", "passed": self.runtime.is_some(), "critical": true }),
        ];
        if let Some(config) = &self.config {
            checks.push(json!({
                "name": "auth_source",
                "passed": config.has_direct_token() || config.has_credential_id(),
                "critical": false,
                "message": if config.has_direct_token() {
                    "API token configured"
                } else if config.has_credential_id() {
                    "credential_id configured; host or egress proxy injection required for live requests"
                } else {
                    "No auth configured; public models may work but gated models will fail"
                }
            }));
        }
        if let Some(client) = &self.client {
            checks.push(json!({
                "name": "auth_token",
                "passed": !client.is_secretless(),
                "critical": false,
                "message": if client.is_secretless() {
                    "No API token configured; requests to gated models will fail"
                } else {
                    "API token configured"
                }
            }));
        }
        let all_critical_pass = checks.iter().all(|c| {
            !c["critical"].as_bool().unwrap_or(false) || c["passed"].as_bool().unwrap_or(false)
        });
        let status = if all_critical_pass && self.configured {
            "healthy"
        } else if self.configured {
            "degraded"
        } else {
            "unhealthy"
        };
        Ok(json!({
            "status": status,
            "checks": checks
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        if !self.configured {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "Connector not configured"
            }));
        }
        if !self.handshaken {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_handshaken",
                "message": "Connector configured but handshake not completed"
            }));
        }

        if self
            .config
            .as_ref()
            .is_some_and(HuggingfaceConfig::has_credential_id)
        {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "credential_injection_required",
                "message": "Configured with credential_id; host or egress proxy injection required for live checks"
            }));
        }

        // Live self-check: try whoami to validate the token
        if let (Some(client), Some(runtime)) = (&self.client, &self.runtime) {
            match client.whoami(runtime).await {
                Ok(user_info) => {
                    return Ok(json!({
                        "status": "ready",
                        "reason_code": "ok",
                        "message": "Token validated",
                        "user": user_info.get("name").cloned().unwrap_or(Value::Null)
                    }));
                }
                Err(e) => {
                    return Ok(json!({
                        "status": "degraded",
                        "reason_code": "token_validation_failed",
                        "message": format!("Token check failed: {e}")
                    }));
                }
            }
        }

        Ok(json!({
            "status": "degraded",
            "reason_code": "missing_client",
            "message": "Client or runtime not initialized"
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": [
                {
                    "id": OP_TEXT_GENERATION,
                    "summary": "Run text generation inference via Hugging Face Inference API",
                    "capability": "huggingface.inference",
                    "risk_level": "medium",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "implemented": true
                },
                {
                    "id": OP_SUMMARIZATION,
                    "summary": "Run text summarization via Hugging Face Inference API",
                    "capability": "huggingface.inference",
                    "risk_level": "medium",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "implemented": true
                },
                {
                    "id": OP_MODEL_LIST,
                    "summary": "List Hugging Face Hub models with bounded catalog filters",
                    "capability": "huggingface.models",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "implemented": true
                },
                {
                    "id": OP_MODEL_INFO,
                    "summary": "Get model metadata from Hugging Face Hub",
                    "capability": "huggingface.models",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "implemented": true
                }
            ],
            "surface_status": "incubating",
            "surface_status_rationale": "Runtime path is incomplete or lacks production evidence",
            "events": [],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "runtime not initialized".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "client not initialized".into(),
        })?;

        let output = match operation {
            OP_TEXT_GENERATION => self.invoke_text_generation(client, runtime, &input).await?,
            OP_SUMMARIZATION => self.invoke_summarization(client, runtime, &input).await?,
            OP_MODEL_LIST => self.invoke_model_list(client, runtime, &input).await?,
            OP_MODEL_INFO => self.invoke_model_info(client, runtime, &input).await?,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(json!({
            "operation": operation,
            "output": output
        }))
    }

    async fn invoke_text_generation(
        &self,
        client: &HuggingfaceClient,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> FcpResult<Value> {
        let model_id = input
            .get("model_id")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_TEXT_GEN_MODEL);
        let prompt = input
            .get("prompt")
            .or_else(|| input.get("inputs"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "Missing 'prompt' field".into(),
            })?;

        let mut gen_params = TextGenerationParameters::default();
        if let Some(v) = input.get("max_new_tokens").and_then(Value::as_u64) {
            gen_params.max_new_tokens = safe_u32(v);
        }
        if let Some(v) = input.get("temperature").and_then(Value::as_f64) {
            gen_params.temperature = Some(v);
        }
        if let Some(v) = input.get("top_p").and_then(Value::as_f64) {
            gen_params.top_p = Some(v);
        }
        if let Some(v) = input.get("top_k").and_then(Value::as_u64) {
            gen_params.top_k = safe_u32(v);
        }
        if let Some(v) = input.get("repetition_penalty").and_then(Value::as_f64) {
            gen_params.repetition_penalty = Some(v);
        }
        if let Some(v) = input.get("do_sample").and_then(Value::as_bool) {
            gen_params.do_sample = Some(v);
        }
        if let Some(v) = input.get("return_full_text").and_then(Value::as_bool) {
            gen_params.return_full_text = Some(v);
        }

        let has_params = gen_params.max_new_tokens.is_some()
            || gen_params.temperature.is_some()
            || gen_params.top_p.is_some()
            || gen_params.top_k.is_some()
            || gen_params.repetition_penalty.is_some()
            || gen_params.do_sample.is_some()
            || gen_params.return_full_text.is_some();

        let request = TextGenerationRequest {
            inputs: prompt.to_string(),
            parameters: if has_params { Some(gen_params) } else { None },
        };

        let results = client
            .text_generation(runtime, model_id, &request)
            .await
            .map_err(|e| e.to_fcp_error())?;

        serde_json::to_value(&results).map_err(|e| FcpError::Internal {
            message: e.to_string(),
        })
    }

    async fn invoke_summarization(
        &self,
        client: &HuggingfaceClient,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> FcpResult<Value> {
        let model_id = input
            .get("model_id")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_SUMMARIZATION_MODEL);
        let text = input
            .get("text")
            .or_else(|| input.get("inputs"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "Missing 'text' field".into(),
            })?;

        let mut sum_params = SummarizationParameters::default();
        if let Some(v) = input.get("max_length").and_then(Value::as_u64) {
            sum_params.max_length = safe_u32(v);
        }
        if let Some(v) = input.get("min_length").and_then(Value::as_u64) {
            sum_params.min_length = safe_u32(v);
        }

        let has_params = sum_params.max_length.is_some() || sum_params.min_length.is_some();

        let request = SummarizationRequest {
            inputs: text.to_string(),
            parameters: if has_params { Some(sum_params) } else { None },
        };

        let results = client
            .summarization(runtime, model_id, &request)
            .await
            .map_err(|e| e.to_fcp_error())?;

        serde_json::to_value(&results).map_err(|e| FcpError::Internal {
            message: e.to_string(),
        })
    }

    async fn invoke_model_info(
        &self,
        client: &HuggingfaceClient,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> FcpResult<Value> {
        let model_id = input
            .get("model_id")
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "Missing 'model_id' field".into(),
            })?;

        let model_info = client
            .model_info(runtime, model_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        serde_json::to_value(&model_info).map_err(|e| FcpError::Internal {
            message: e.to_string(),
        })
    }

    async fn invoke_model_list(
        &self,
        client: &HuggingfaceClient,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> FcpResult<Value> {
        let limit = match input.get("limit").and_then(Value::as_u64) {
            Some(0) => {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "limit must be greater than zero".into(),
                });
            }
            Some(value) => {
                let parsed = safe_u32(value).ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: "limit exceeds u32 range".into(),
                })?;
                if parsed > MAX_MODEL_LIST_LIMIT {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("limit must be <= {MAX_MODEL_LIST_LIMIT}"),
                    });
                }
                Some(parsed)
            }
            None => Some(25),
        };

        let request = ModelListRequest {
            search: input
                .get("search")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            pipeline_tag: input
                .get("pipeline_tag")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            limit,
        };

        let models = client
            .list_models(runtime, &request)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "models": models,
            "catalog": "hub",
            "limit": request.limit
        }))
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let known = matches!(
            operation,
            OP_TEXT_GENERATION | OP_SUMMARIZATION | OP_MODEL_LIST | OP_MODEL_INFO
        );

        Ok(json!({
            "allowed": known && self.configured,
            "simulate_capability": if known { "supported" } else { "unknown_operation" },
            "reason": if !known {
                "Unknown operation."
            } else if !self.configured {
                "Connector not configured."
            } else {
                "Operation is available for invocation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = false;
        self.handshaken = false;
        self.client = None;
        self.runtime = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for HuggingfaceConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn configure_and_handshake() {
        let mut connector = HuggingfaceConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_token": "hf_test_token",
                "inference_url": "http://localhost:9999",
                "hub_url": "http://localhost:9998"
            }))
            .await
            .expect("configure should succeed");
        assert_eq!(result["configured"], true);
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());

        let hs = connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");
        assert_eq!(hs["surface_status"], "incubating");
        assert_eq!(hs["connector_version"], CONNECTOR_VERSION);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_defaults() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure with defaults should succeed");
        assert!(connector.configured);
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_api_token_and_credential_id_together() {
        let mut connector = HuggingfaceConnector::new();
        let err = connector
            .handle_configure(json!({
                "api_token": "hf_test",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .expect_err("mixed auth sources should fail");
        assert!(err.to_string().contains("api_token or credential_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_credential_id() {
        let mut connector = HuggingfaceConnector::new();
        let err = connector
            .handle_configure(json!({"credential_id": "not-a-uuid"}))
            .await
            .expect_err("invalid credential id should fail");
        assert!(err.to_string().contains("valid UUID"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_base_url_query() {
        let mut connector = HuggingfaceConnector::new();
        let err = connector
            .handle_configure(json!({
                "api_token": "hf_test",
                "inference_url": "https://api-inference.huggingface.co?x=bad"
            }))
            .await
            .expect_err("base URL queries should fail");
        assert!(err.to_string().contains("query or fragment"));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_requires_configure() {
        let mut connector = HuggingfaceConnector::new();
        let err = connector
            .handle_handshake(json!({}))
            .await
            .expect_err("handshake before configure should fail");
        assert!(matches!(err, FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn health_reflects_configuration_state() {
        let mut connector = HuggingfaceConnector::new();
        let h = connector.handle_health().await.unwrap();
        assert_eq!(h["status"], "unconfigured");
        assert_eq!(h["live_requests_supported"], false);

        connector
            .handle_configure(json!({"api_token": "hf_test"}))
            .await
            .unwrap();
        let h = connector.handle_health().await.unwrap();
        assert_eq!(h["status"], "ready");
        assert_eq!(h["live_requests_supported"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn health_degraded_without_token() {
        let mut connector = HuggingfaceConnector::new();
        connector.handle_configure(json!({})).await.unwrap();
        let h = connector.handle_health().await.unwrap();
        assert_eq!(h["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn health_reports_credential_id_mode() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        let h = connector.handle_health().await.unwrap();
        assert_eq!(h["status"], "degraded");
        assert_eq!(h["auth_mode"], "credential_id");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_checks() {
        let mut connector = HuggingfaceConnector::new();
        let d = connector.handle_doctor().await.unwrap();
        assert_eq!(d["status"], "unhealthy");

        connector
            .handle_configure(json!({"api_token": "hf_test"}))
            .await
            .unwrap();
        let d = connector.handle_doctor().await.unwrap();
        assert_eq!(d["status"], "healthy");
        let checks = d["checks"].as_array().unwrap();
        assert!(checks.len() >= 4);
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_lists_operations() {
        let connector = HuggingfaceConnector::new();
        let intro = connector.handle_introspect().await.unwrap();
        assert_eq!(intro["surface_status"], "incubating");
        let ops = intro["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 4);
        assert!(ops.iter().all(|o| o["implemented"] == true));
        assert!(ops.iter().any(|o| o["id"] == OP_MODEL_LIST));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_ready_state() {
        let connector = HuggingfaceConnector::new();
        let err = connector
            .handle_invoke(json!({
                "operation_id": OP_MODEL_INFO,
                "input": {"model_id": "gpt2"}
            }))
            .await
            .expect_err("invoke before configure should fail");
        assert!(
            err.to_string().contains("not configured")
                || err.to_string().contains("Not configured")
                || matches!(err, FcpError::NotConfigured)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_rejects_unknown_operation() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({"api_token": "hf_test"}))
            .await
            .unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let err = connector
            .handle_invoke(json!({"operation_id": "huggingface.nonexistent"}))
            .await
            .expect_err("unknown operation should fail");
        assert!(err.to_string().contains("Unknown operation"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_text_generation_requires_prompt() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({
                "api_token": "hf_test",
                "inference_url": "http://localhost:1"
            }))
            .await
            .unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let err = connector
            .handle_invoke(json!({
                "operation_id": OP_TEXT_GENERATION,
                "input": {"model_id": "gpt2"}
            }))
            .await
            .expect_err("missing prompt should fail");
        assert!(err.to_string().contains("prompt"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_summarization_requires_text() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({
                "api_token": "hf_test",
                "inference_url": "http://localhost:1"
            }))
            .await
            .unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let err = connector
            .handle_invoke(json!({
                "operation_id": OP_SUMMARIZATION,
                "input": {"model_id": "facebook/bart-large-cnn"}
            }))
            .await
            .expect_err("missing text should fail");
        assert!(err.to_string().contains("text"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_model_info_requires_model_id() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({
                "api_token": "hf_test",
                "hub_url": "http://localhost:1"
            }))
            .await
            .unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let err = connector
            .handle_invoke(json!({
                "operation_id": OP_MODEL_INFO,
                "input": {}
            }))
            .await
            .expect_err("missing model_id should fail");
        assert!(err.to_string().contains("model_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_model_list_rejects_unbounded_limit() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({
                "api_token": "hf_test",
                "hub_url": "http://localhost:1"
            }))
            .await
            .unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let err = connector
            .handle_invoke(json!({
                "operation_id": OP_MODEL_LIST,
                "input": {"limit": 10_000}
            }))
            .await
            .expect_err("oversized limit should fail before outbound HTTP");
        assert!(err.to_string().contains("limit must be"));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operations() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({"api_token": "hf_test"}))
            .await
            .unwrap();

        let sim = connector
            .handle_simulate(json!({"operation_id": OP_TEXT_GENERATION}))
            .await
            .unwrap();
        assert_eq!(sim["allowed"], true);
        assert_eq!(sim["simulate_capability"], "supported");

        let sim = connector
            .handle_simulate(json!({"operation_id": OP_SUMMARIZATION}))
            .await
            .unwrap();
        assert_eq!(sim["allowed"], true);

        let sim = connector
            .handle_simulate(json!({"operation_id": OP_MODEL_INFO}))
            .await
            .unwrap();
        assert_eq!(sim["allowed"], true);

        let sim = connector
            .handle_simulate(json!({"operation_id": OP_MODEL_LIST}))
            .await
            .unwrap();
        assert_eq!(sim["allowed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation() {
        let connector = HuggingfaceConnector::new();
        let sim = connector
            .handle_simulate(json!({"operation_id": "huggingface.unknown"}))
            .await
            .unwrap();
        assert_eq!(sim["allowed"], false);
        assert_eq!(sim["simulate_capability"], "unknown_operation");
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({"api_token": "hf_test"}))
            .await
            .unwrap();
        connector.handle_handshake(json!({})).await.unwrap();
        assert!(connector.configured);
        assert!(connector.handshaken);
        assert!(connector.client.is_some());

        connector.handle_shutdown(json!({})).await.unwrap();
        assert!(!connector.configured);
        assert!(!connector.handshaken);
        assert!(connector.client.is_none());
        assert!(connector.runtime.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = HuggingfaceConnector::new();
        let sc = connector.handle_self_check().await.unwrap();
        assert_eq!(sc["status"], "degraded");
        assert_eq!(sc["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_not_handshaken() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({"api_token": "hf_test"}))
            .await
            .unwrap();
        let sc = connector.handle_self_check().await.unwrap();
        assert_eq!(sc["status"], "degraded");
        assert_eq!(sc["reason_code"], "not_handshaken");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_credential_id_requires_injection() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        connector.handle_handshake(json!({})).await.unwrap();
        let sc = connector.handle_self_check().await.unwrap();
        assert_eq!(sc["status"], "degraded");
        assert_eq!(sc["reason_code"], "credential_injection_required");
    }
}
