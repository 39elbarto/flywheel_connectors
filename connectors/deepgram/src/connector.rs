use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.deepgram";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str = "This first slice focuses on prerecorded transcription through the Listen API.";
const DEFAULT_BASE_URL: &str = "https://api.deepgram.com";

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
            Self::ApiKey(key) => request.header("Authorization", format!("Token {key}")),
            Self::CredentialId(credential_id) => {
                request.header("X-FCP-Credential-Id", credential_id)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct DeepgramConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl DeepgramConfig {
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

        Ok(Self {
            auth,
            base_url: normalize_base_url(
                params.get("base_url").and_then(Value::as_str),
                DEFAULT_BASE_URL,
                &["api.deepgram.com", "developers.deepgram.com"],
            )?,
            request_timeout_ms: params
                .get("request_timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(60_000),
        })
    }
}

#[derive(Clone, Debug)]
struct DeepgramClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl DeepgramClient {
    fn new(config: &DeepgramConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build Deepgram client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
        })
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.auth
            .apply(self.http.request(method, format!("{}{}", self.base_url, path)))
            .header("Accept", "application/json")
    }

    async fn transcribe(&self, input: &Value) -> FcpResult<Value> {
        let audio_url = input
            .get("audio_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "audio_url must be a non-empty string".into(),
            })?;

        let mut params: Vec<(&str, String)> = Vec::new();
        for key in [
            "model",
            "language",
            "detect_language",
            "smart_format",
            "punctuate",
            "diarize",
            "summarize",
            "topics",
            "intents",
        ] {
            if let Some(value) = input.get(key) {
                let rendered = if let Some(text) = value.as_str() {
                    text.to_string()
                } else if let Some(boolean) = value.as_bool() {
                    boolean.to_string()
                } else if let Some(number) = value.as_u64() {
                    number.to_string()
                } else {
                    continue;
                };
                params.push((key, rendered));
            }
        }

        send_json(
            self.request(Method::POST, "/v1/listen")
                .query(&params)
                .json(&json!({ "url": audio_url })),
            "deepgram",
        )
        .await
    }
}

pub struct DeepgramConnector {
    base: Arc<BaseConnector>,
    config: Option<DeepgramConfig>,
    client: Option<Arc<DeepgramClient>>,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl DeepgramConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            handshaken: false,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = DeepgramConfig::from_params(&params)?;
        let client = DeepgramClient::new(&config)?;
        self.config = Some(config.clone());
        self.client = Some(Arc::new(client));
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": config.auth.redacted_label(),
            "base_url": config.base_url,
        }))
    }

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["deepgram.listen"]
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.config.is_some() && self.handshaken { "healthy" } else if self.config.is_some() { "degraded" } else { "unconfigured" },
            "configured": self.config.is_some(),
            "handshaken": self.handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.config.is_some() && self.client.is_some() { "healthy" } else { "unhealthy" },
            "checks": [
                { "name": "configuration", "passed": self.config.is_some(), "critical": true },
                { "name": "client_initialized", "passed": self.client.is_some(), "critical": true },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.config.is_some() { "ok" } else { "degraded" },
            "reason_code": if self.config.is_some() { Value::Null } else { json!("not_configured") },
            "message": BOUNDARY
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": [
                { "id": "deepgram.listen.transcribe", "summary": "Create a Deepgram prerecorded transcription", "capability": "deepgram.listen", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" }
            ],
            "events": [],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Deepgram client not initialized".into(),
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
            "deepgram.listen.transcribe" => client.transcribe(&input).await,
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
            "allowed": operation == "deepgram.listen.transcribe",
            "reason": BOUNDARY
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.config = None;
        self.client = None;
        self.handshaken = false;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for DeepgramConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_base_url(
    override_value: Option<&str>,
    default_value: &str,
    allowed_hosts: &[&str],
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
    if !is_localhost && !allowed_hosts.iter().any(|allowed| host == *allowed) {
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
