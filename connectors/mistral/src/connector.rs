use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use reqwest::multipart::{Form, Part};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.mistral";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://api.mistral.ai/v1";
const BOUNDARY: &str = "This first slice is request-response only and covers chat completions, embeddings, file-based transcriptions, and model discovery.";

#[derive(Clone)]
enum Auth {
    ApiKey(String),
    CredentialId { _id: String },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"[REDACTED]").finish(),
            Self::CredentialId { _id: id } => {
                f.debug_struct("CredentialId").field("_id", id).finish()
            }
        }
    }
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

#[derive(Clone)]
struct MistralConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for MistralConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MistralConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl MistralConfig {
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

        Ok(Self {
            auth,
            base_url: normalize_base_url(
                params.get("base_url").and_then(Value::as_str),
                DEFAULT_BASE_URL,
                &["mistral.ai"],
            )?,
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
        })
    }
}

#[derive(Clone)]
struct MistralClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for MistralClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MistralClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl MistralClient {
    fn new(config: &MistralConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build Mistral HTTP client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
        })
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.auth.apply(
            self.http
                .request(method, format!("{}{}", self.base_url, path)),
        )
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path), "mistral").await
    }

    async fn post_json(&self, path: &str, body: Value) -> FcpResult<Value> {
        send_json(self.request(Method::POST, path).json(&body), "mistral").await
    }

    async fn post_multipart(&self, path: &str, body: Form) -> FcpResult<Value> {
        send_json(self.request(Method::POST, path).multipart(body), "mistral").await
    }
}

pub struct MistralConnector {
    base: Arc<BaseConnector>,
    config: Option<MistralConfig>,
    client: Option<Arc<MistralClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl MistralConnector {
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
        let config = MistralConfig::from_params(&params)?;
        let client = MistralClient::new(&config)?;
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
            .or_else(|| Some("mistral-local-session".into()));
        self.base.set_handshaken(true);

        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["mistral.chat", "mistral.embeddings", "mistral.audio", "mistral.models"],
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
                    } else {
                        Value::Null
                    }
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
                    "message": BOUNDARY
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
                "message": "Mistral is not configured."
            }));
        };

        match client.get_json("/models").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "surface_boundary": "chat.completions + embeddings.create + audio.transcriptions + models.list",
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
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Mistral client not initialized".into(),
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
            "mistral.chat.completions" => self.invoke_chat(client, &input).await,
            "mistral.embeddings.create" => self.invoke_embeddings(client, &input).await,
            "mistral.audio.transcriptions" => self.invoke_transcription(client, &input).await,
            "mistral.models.list" => client.get_json("/models").await,
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
            "mistral.chat.completions"
                | "mistral.embeddings.create"
                | "mistral.audio.transcriptions"
                | "mistral.models.list"
        );
        let blocked_by_secretless_auth = supported
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.is_secretless());
        let blocked_by_streaming_boundary = operation == "mistral.chat.completions"
            && input
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        Ok(json!({
            "allowed": supported && !blocked_by_secretless_auth && !blocked_by_streaming_boundary,
            "reason": if blocked_by_secretless_auth {
                "credential_id mode requires host-side credential injection, which this connector slice does not implement."
            } else if blocked_by_streaming_boundary {
                "stream=true is not exposed by the first Mistral connector slice."
            } else if supported {
                "Supported operation."
            } else {
                "Unknown operation."
            }
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

    async fn invoke_chat(&self, client: &MistralClient, input: &Value) -> FcpResult<Value> {
        if input
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "stream=true is not exposed by the first Mistral connector slice".into(),
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
            "model": input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("mistral-small-latest"),
            "messages": messages,
        });
        copy_if_present(&mut body, input, "temperature");
        copy_if_present(&mut body, input, "top_p");
        copy_if_present(&mut body, input, "max_tokens");
        copy_if_present(&mut body, input, "response_format");
        copy_if_present(&mut body, input, "tools");
        copy_if_present(&mut body, input, "tool_choice");
        copy_if_present(&mut body, input, "random_seed");
        copy_if_present(&mut body, input, "presence_penalty");
        copy_if_present(&mut body, input, "frequency_penalty");

        client.post_json("/chat/completions", body).await
    }

    async fn invoke_embeddings(&self, client: &MistralClient, input: &Value) -> FcpResult<Value> {
        let embeddings_input = input.get("input").cloned().unwrap_or_else(|| input.clone());

        let body = json!({
            "model": input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("mistral-embed"),
            "input": embeddings_input,
        });

        client.post_json("/embeddings", body).await
    }

    async fn invoke_transcription(
        &self,
        client: &MistralClient,
        input: &Value,
    ) -> FcpResult<Value> {
        let audio_base64 = input
            .get("audio_base64")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "audio_base64 is required".into(),
            })?;
        let audio_bytes =
            BASE64_STANDARD
                .decode(audio_base64)
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("audio_base64 is not valid base64: {error}"),
                })?;
        let filename = input
            .get("filename")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("audio.wav");
        let model = input
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("voxtral-mini-transcribe");

        let mut form = Form::new()
            .part(
                "file",
                Part::bytes(audio_bytes)
                    .file_name(filename.to_string())
                    .mime_str(
                        input
                            .get("content_type")
                            .and_then(Value::as_str)
                            .unwrap_or("audio/wav"),
                    )
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid content_type for audio upload: {error}"),
                    })?,
            )
            .text("model", model.to_string());

        for field in ["language", "prompt", "response_format", "temperature"] {
            if let Some(value) = input.get(field) {
                let as_text = value
                    .as_str()
                    .map_or_else(|| value.to_string(), ToOwned::to_owned);
                form = form.text(field.to_string(), as_text);
            }
        }

        client.post_multipart("/audio/transcriptions", form).await
    }
}

impl Default for MistralConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operations_info() -> Vec<Value> {
    vec![
        json!({
            "id": "mistral.chat.completions",
            "summary": "Create a Mistral chat completion",
            "capability": "mistral.chat",
            "risk_level": "medium",
            "safety_tier": "safe",
            "idempotency": "none",
            "input_schema": {
                "type": "object",
                "required": ["messages"],
                "properties": {
                    "model": {"type": "string", "default": "mistral-small-latest"},
                    "messages": {"type": "array", "minItems": 1},
                    "temperature": {"type": "number"},
                    "top_p": {"type": "number"},
                    "max_tokens": {"type": "integer"},
                    "response_format": {"type": "object"},
                    "tools": {"type": "array"},
                    "tool_choice": {}
                }
            },
            "output_schema": {"type": "object"},
        }),
        json!({
            "id": "mistral.embeddings.create",
            "summary": "Create Mistral embeddings",
            "capability": "mistral.embeddings",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "required": ["input"],
                "properties": {
                    "model": {"type": "string", "default": "mistral-embed"},
                    "input": {}
                }
            },
            "output_schema": {"type": "object"},
        }),
        json!({
            "id": "mistral.audio.transcriptions",
            "summary": "Transcribe an uploaded audio file with Mistral",
            "capability": "mistral.audio",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "none",
            "input_schema": {
                "type": "object",
                "required": ["audio_base64"],
                "properties": {
                    "audio_base64": {"type": "string"},
                    "filename": {"type": "string", "default": "audio.wav"},
                    "content_type": {"type": "string", "default": "audio/wav"},
                    "model": {"type": "string", "default": "voxtral-mini-transcribe"},
                    "language": {"type": "string"},
                    "prompt": {"type": "string"},
                    "response_format": {"type": "string"},
                    "temperature": {}
                }
            },
            "output_schema": {"type": "object"},
        }),
        json!({
            "id": "mistral.models.list",
            "summary": "List Mistral models",
            "capability": "mistral.models",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {"type": "object", "properties": {}},
            "output_schema": {"type": "object"},
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
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
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
        return Err(FcpError::External {
            service: service.into(),
            message: format!("HTTP {status}: {body}"),
            status_code: Some(status.as_u16()),
            retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
            retry_after,
        });
    }

    response
        .json::<Value>()
        .await
        .map_err(|error| FcpError::External {
            service: service.into(),
            message: format!("Failed to decode JSON response: {error}"),
            status_code: Some(status.as_u16()),
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
        let error = MistralConfig::from_params(&json!({
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
            &["mistral.ai"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = MistralConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = MistralConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "mistral.models.list"}))
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
        let mut connector = MistralConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({
                "operation_id": "mistral.chat.completions",
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
