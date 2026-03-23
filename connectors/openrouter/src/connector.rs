use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.openrouter";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api/v1";

#[derive(Clone, Debug)]
enum Auth {
    ApiKey(String),
    CredentialId(String),
}

impl Auth {
    fn redacted_label(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::CredentialId(_) => "credential_id",
        }
    }

    fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match self {
            Self::ApiKey(key) => request.header("Authorization", format!("Bearer {key}")),
            Self::CredentialId(credential_id) => {
                request.header("X-FCP-Credential-Id", credential_id)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct OpenRouterConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
    app_name: Option<String>,
    app_url: Option<String>,
}

impl OpenRouterConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let auth = match (api_key, credential_id) {
            (Some(key), None) => Auth::ApiKey(key),
            (None, Some(credential_id)) => Auth::CredentialId(credential_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id".into(),
                });
            }
        };

        let base_url = normalize_base_url(
            params.get("base_url").and_then(Value::as_str),
            DEFAULT_BASE_URL,
            &["openrouter.ai"],
        )?;

        Ok(Self {
            auth,
            base_url,
            request_timeout_ms: params
                .get("request_timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(60_000),
            app_name: params
                .get("app_name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            app_url: params
                .get("app_url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        })
    }
}

#[derive(Clone, Debug)]
struct OpenRouterClient {
    http: Client,
    auth: Auth,
    base_url: String,
    app_name: Option<String>,
    app_url: Option<String>,
}

impl OpenRouterClient {
    fn new(config: &OpenRouterConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build OpenRouter HTTP client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
            app_name: config.app_name.clone(),
            app_url: config.app_url.clone(),
        })
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let request = self.auth.apply(self.http.request(method, url));
        let request = if let Some(app_name) = &self.app_name {
            request.header("X-Title", app_name)
        } else {
            request
        };
        if let Some(app_url) = &self.app_url {
            request.header("HTTP-Referer", app_url)
        } else {
            request
        }
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path), "openrouter").await
    }

    async fn post_json(&self, path: &str, body: Value) -> FcpResult<Value> {
        send_json(self.request(Method::POST, path).json(&body), "openrouter").await
    }
}

pub struct OpenRouterConnector {
    base: Arc<BaseConnector>,
    config: Option<OpenRouterConfig>,
    client: Option<Arc<OpenRouterClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl OpenRouterConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = OpenRouterConfig::from_params(&params)?;
        let client = OpenRouterClient::new(&config)?;
        self.client = Some(Arc::new(client));
        self.config = Some(config.clone());
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": config.auth.redacted_label(),
            "base_url": config.base_url,
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        self.session_id = params
            .get("session_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        self.base.set_handshaken(true);

        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["openrouter.chat", "openrouter.models"],
            "streaming_supported": false,
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": health_status(self.config.is_some(), self.session_id.is_some()),
            "configured": self.config.is_some(),
            "handshaken": self.session_id.is_some(),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.config.is_some() && self.client.is_some() { "healthy" } else { "unhealthy" },
            "checks": [
                {
                    "name": "configuration",
                    "passed": self.config.is_some(),
                    "critical": true,
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with api_key or credential_id.") }
                },
                {
                    "name": "client_initialized",
                    "passed": self.client.is_some(),
                    "critical": true,
                    "message": if self.client.is_some() { Value::Null } else { json!("HTTP client not initialized.") }
                },
                {
                    "name": "handshake",
                    "passed": self.session_id.is_some(),
                    "critical": false,
                    "message": if self.session_id.is_some() { Value::Null } else { json!("Handshake has not completed yet.") }
                },
                {
                    "name": "surface_boundary",
                    "passed": true,
                    "critical": false,
                    "message": "This first slice exposes non-streaming chat completions and model discovery only."
                }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let Some(client) = &self.client else {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "OpenRouter is not configured."
            }));
        };

        match client.get_json("/models").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "base_url": client.base_url,
                "surface_boundary": "models.list + non-streaming chat.completions",
            })),
            Err(error) => Ok(json!({
                "status": "failed",
                "reason_code": "upstream_probe_failed",
                "message": error.to_string(),
            })),
        }
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": operations_info(),
            "events": [],
            "resource_types": [],
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "OpenRouter client not initialized".into(),
        })?;

        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let result = match operation {
            "openrouter.chat.completions" => self.invoke_chat(client, &input).await,
            "openrouter.models.list" => client.get_json("/models").await,
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        };

        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        Ok(json!({
            "allowed": matches!(operation, "openrouter.chat.completions" | "openrouter.models.list"),
            "reason": if matches!(operation, "openrouter.chat.completions" | "openrouter.models.list") {
                "Supported operation."
            } else {
                "Unknown operation."
            },
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    async fn invoke_chat(&self, client: &OpenRouterClient, input: &Value) -> FcpResult<Value> {
        if input.get("stream").and_then(Value::as_bool).unwrap_or(false) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "stream=true is not exposed by the first OpenRouter connector slice".into(),
            });
        }

        let messages = input
            .get("messages")
            .and_then(Value::as_array)
            .filter(|messages| !messages.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "messages must be a non-empty array".into(),
            })?;

        let mut body = json!({
            "model": input.get("model").and_then(Value::as_str).unwrap_or("openai/gpt-4.1-mini"),
            "messages": messages,
        });

        copy_if_present(&mut body, input, "max_tokens");
        copy_if_present(&mut body, input, "temperature");
        copy_if_present(&mut body, input, "top_p");
        copy_if_present(&mut body, input, "response_format");
        copy_if_present(&mut body, input, "tools");
        copy_if_present(&mut body, input, "tool_choice");

        let response = client.post_json("/chat/completions", body).await?;
        Ok(json!({
            "id": response.get("id").cloned().unwrap_or(Value::Null),
            "model": response.get("model").cloned().unwrap_or(Value::Null),
            "content": response
                .pointer("/choices/0/message/content")
                .cloned()
                .unwrap_or(Value::Null),
            "finish_reason": response
                .pointer("/choices/0/finish_reason")
                .cloned()
                .unwrap_or(Value::Null),
            "usage": response.get("usage").cloned().unwrap_or(Value::Null),
            "raw": response,
        }))
    }
}

impl Default for OpenRouterConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operations_info() -> Vec<Value> {
    vec![
        json!({
            "id": "openrouter.chat.completions",
            "summary": "Create a non-streaming OpenRouter chat completion",
            "description": "Uses OpenRouter's OpenAI-compatible POST /chat/completions surface. This first slice deliberately omits streaming event delivery.",
            "capability": "openrouter.chat",
            "risk_level": "medium",
            "safety_tier": "safe",
            "idempotency": "none",
            "input_schema": {
                "type": "object",
                "required": ["messages"],
                "properties": {
                    "model": {"type": "string", "default": "openai/gpt-4.1-mini"},
                    "messages": {"type": "array", "minItems": 1},
                    "max_tokens": {"type": "integer"},
                    "temperature": {"type": "number"},
                    "top_p": {"type": "number"},
                    "response_format": {"type": "object"},
                    "tools": {"type": "array"},
                    "tool_choice": {}
                }
            },
            "output_schema": {"type": "object"},
            "ai_hints": {
                "when_to_use": "Use when you need one routed model request through OpenRouter without building provider-specific clients.",
                "common_mistakes": [
                    "This first slice is non-streaming.",
                    "Pass provider-qualified model IDs such as openai/gpt-4.1-mini."
                ],
                "examples": [
                    "{\"model\":\"openai/gpt-4.1-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"Summarize FCP in 3 bullets.\"}]}"
                ],
                "related": ["openrouter.models.list"]
            }
        }),
        json!({
            "id": "openrouter.models.list",
            "summary": "List OpenRouter models",
            "description": "Reads the current OpenRouter model catalog.",
            "capability": "openrouter.models",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {"type": "object", "properties": {}},
            "output_schema": {"type": "object"},
            "ai_hints": {
                "when_to_use": "Use to discover valid provider-qualified model IDs.",
                "common_mistakes": ["Do not assume a first-party provider model ID works unchanged without the OpenRouter prefix."],
                "examples": ["{}"],
                "related": ["openrouter.chat.completions"]
            }
        }),
    ]
}

fn health_status(configured: bool, handshaken: bool) -> &'static str {
    if configured && handshaken {
        "healthy"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}

fn copy_if_present(target: &mut Value, source: &Value, field: &str) {
    if let Some(value) = source.get(field) {
        target[field] = value.clone();
    }
}

fn normalize_base_url(
    override_value: Option<&str>,
    default_value: &str,
    allowed_suffixes: &[&str],
) -> FcpResult<String> {
    let candidate = override_value.unwrap_or(default_value).trim().trim_end_matches('/');
    let parsed = Url::parse(candidate).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;

    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let is_localhost = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme =
        parsed.scheme() == "https" || (parsed.scheme() == "http" && is_localhost);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https (or http only for localhost tests)".into(),
        });
    }

    if !is_localhost
        && !allowed_suffixes
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {host} is not allowed"),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

async fn send_json(request: RequestBuilder, service: &'static str) -> FcpResult<Value> {
    let response = request.send().await.map_err(|error| map_reqwest_error(service, error))?;
    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable response body>".into());
        return Err(FcpError::External {
            service: service.into(),
            message: format!("HTTP {status}: {body}"),
            status_code: Some(status.as_u16()),
            retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
            retry_after: None,
        });
    }
    response.json::<Value>().await.map_err(|error| FcpError::External {
        service: service.into(),
        message: format!("Failed to decode JSON response: {error}"),
        status_code: Some(status.as_u16()),
        retryable: false,
        retry_after: None,
    })
}

fn map_reqwest_error(service: &'static str, error: reqwest::Error) -> FcpError {
    if error.is_timeout() {
        FcpError::UpstreamTimeout {
            service: service.into(),
        }
    } else {
        FcpError::External {
            service: service.into(),
            message: error.to_string(),
            status_code: None,
            retryable: error.is_connect() || error.is_timeout(),
            retry_after: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_requires_exactly_one_auth_source() {
        let error = OpenRouterConfig::from_params(&json!({
            "api_key": "a",
            "credential_id": "b"
        }))
        .expect_err("expected invalid config");
        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn base_url_rejects_unapproved_hosts() {
        let error = normalize_base_url(Some("https://evil.example.com"), DEFAULT_BASE_URL, &["openrouter.ai"])
            .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }
}
