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
    CredentialId { _id: String },
}

impl Auth {
    const fn redacted_label(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match self {
            Self::ApiKey(key) => request.header("Authorization", format!("Bearer {key}")),
            Self::CredentialId { .. } => request,
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
            (None, Some(credential_id)) => Auth::CredentialId { _id: credential_id },
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
            request_timeout_ms: match params.get("request_timeout_ms").and_then(Value::as_u64) {
                Some(0) => {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "request_timeout_ms must be greater than 0".into(),
                    });
                }
                Some(timeout_ms) => timeout_ms,
                None => 60_000,
            },
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

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
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
            .map(ToOwned::to_owned)
            .or_else(|| Some("openrouter-local-session".into()));
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
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": health_status(self.config.is_some(), self.session_id.is_some(), live_requests_supported),
            "configured": self.config.is_some(),
            "handshaken": self.session_id.is_some(),
            "live_requests_supported": live_requests_supported,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": if self.config.is_some()
                && self.client.is_some()
                && self.session_id.is_some()
                && live_requests_supported
            {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
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
                    "name": "credential_injection",
                    "passed": self.config.as_ref().is_some_and(|config| !config.auth.is_secretless()),
                    "critical": false,
                    "message": if self.config.as_ref().is_some_and(|config| config.auth.is_secretless()) {
                        json!("credential_id mode requires host-side credential injection, which this connector slice does not implement.")
                    } else { Value::Null }
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
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "credential_injection_required",
                "message": "Configured with credential_id; this connector slice cannot perform live checks without host-side credential injection."
            }));
        }

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
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "credential_id mode requires host-side credential injection, which this connector slice does not implement".into(),
            });
        }

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
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let supported = matches!(
            operation,
            "openrouter.chat.completions" | "openrouter.models.list"
        );
        let blocked_by_secretless_auth = supported
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.is_secretless());
        let blocked_by_streaming_boundary = operation == "openrouter.chat.completions"
            && input
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        Ok(json!({
            "allowed": supported && !blocked_by_secretless_auth && !blocked_by_streaming_boundary,
            "reason": if blocked_by_secretless_auth {
                "credential_id mode requires host-side credential injection, which this connector slice does not implement."
            } else if blocked_by_streaming_boundary {
                "stream=true is not exposed by the first OpenRouter connector slice."
            } else if supported {
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
        if input
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "stream=true is not exposed by the first OpenRouter connector slice"
                    .into(),
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

const fn health_status(
    configured: bool,
    handshaken: bool,
    live_requests_supported: bool,
) -> &'static str {
    if configured && handshaken && live_requests_supported {
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
    let candidate = override_value
        .unwrap_or(default_value)
        .trim()
        .trim_end_matches('/');
    let parsed = Url::parse(candidate).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;

    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include query or fragment components".into(),
        });
    }
    let is_localhost = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = parsed.scheme() == "https" || (parsed.scheme() == "http" && is_localhost);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https (or http only for localhost tests)".into(),
        });
    }

    if !is_localhost
        && !allowed_suffixes
            .iter()
            .any(|allowed_host| host == *allowed_host)
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {host} is not allowed"),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

async fn send_json(request: RequestBuilder, service: &'static str) -> FcpResult<Value> {
    let response = request
        .send()
        .await
        .map_err(|error| map_reqwest_error(service, &error))?;
    let status = response.status();
    if !status.is_success() {
        let retry_after = parse_retry_after(response.headers());
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable response body>".into());
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_ms =
                retry_after.map_or(30_000, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            return Err(FcpError::RateLimited {
                retry_after_ms,
                violation: None,
            });
        }
        return Err(FcpError::External {
            service: service.into(),
            message: format!("HTTP {status}: {body}"),
            status_code: Some(status.as_u16()),
            retryable: status.is_server_error(),
            retry_after,
        });
    }
    response
        .json::<Value>()
        .await
        .map_err(|error| FcpError::External {
            service: service.into(),
            message: format!("Failed to decode JSON response: {error}"),
            status_code: None,
            retryable: false,
            retry_after: None,
        })
}

fn map_reqwest_error(service: &'static str, error: &reqwest::Error) -> FcpError {
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
        let error = normalize_base_url(
            Some("https://evil.example.com"),
            DEFAULT_BASE_URL,
            &["openrouter.ai"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn base_url_rejects_ambiguous_authority_components() {
        for base_url in [
            "https://user:secret@openrouter.ai/api/v1",
            "https://openrouter.ai/api/v1?proxy=evil",
            "https://openrouter.ai/api/v1#fragment",
            "https://api.openrouter.ai/api/v1",
        ] {
            let error = normalize_base_url(Some(base_url), DEFAULT_BASE_URL, &["openrouter.ai"])
                .expect_err("ambiguous or non-manifest host must be rejected");
            assert!(error.to_string().contains("base_url"));
        }
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = OpenRouterConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_without_session_id_reports_handshaken_state() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        connector
            .handle_handshake(json!({}))
            .await
            .expect("expected handshake to succeed");

        let health = connector.handle_health().await.expect("expected health");
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["handshaken"], true);

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["checks"][2]["passed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_requires_handshake_before_reporting_healthy() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["status"], "degraded");
        assert_eq!(doctor["checks"][3]["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_reports_degraded_readiness() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        connector
            .handle_handshake(json!({}))
            .await
            .expect("expected handshake to succeed");

        let health = connector.handle_health().await.expect("expected health");
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["live_requests_supported"], false);

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["status"], "degraded");
        assert_eq!(doctor["checks"][2]["passed"], false);

        let self_check = connector
            .handle_self_check()
            .await
            .expect("expected self-check");
        assert_eq!(self_check["reason_code"], "credential_injection_required");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "openrouter.models.list"}))
            .await
            .expect("expected simulate");
        assert_eq!(simulate["allowed"], false);
        assert!(
            simulate["reason"]
                .as_str()
                .expect("reason should be a string")
                .contains("credential_id mode")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_blocks_streaming_chat_requests() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({
                "operation_id": "openrouter.chat.completions",
                "input": {
                    "stream": true,
                    "messages": [{"role": "user", "content": "hi"}]
                }
            }))
            .await
            .expect("expected simulate");
        assert_eq!(simulate["allowed"], false);
        assert!(
            simulate["reason"]
                .as_str()
                .expect("reason should be a string")
                .contains("stream=true")
        );
    }
}
