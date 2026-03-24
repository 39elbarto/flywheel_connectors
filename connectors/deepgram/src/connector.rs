use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.deepgram";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str =
    "This first slice focuses on prerecorded transcription through the Listen API.";
const DEFAULT_BASE_URL: &str = "https://api.deepgram.com";

#[derive(Clone)]
enum Auth {
    ApiKey(String),
    CredentialId { _id: String },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"[REDACTED]").finish(),
            Self::CredentialId { _id } => f
                .debug_struct("CredentialId")
                .field("_id", _id)
                .finish(),
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
            Self::ApiKey(key) => request.header("Authorization", format!("Token {key}")),
            Self::CredentialId { .. } => request,
        }
    }
}

#[derive(Clone)]
struct DeepgramConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for DeepgramConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepgramConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
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
                &["api.deepgram.com", "developers.deepgram.com"],
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
struct DeepgramClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for DeepgramClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepgramClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
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
            .apply(
                self.http
                    .request(method, format!("{}{}", self.base_url, path)),
            )
            .header("Accept", "application/json")
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path), "deepgram").await
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

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
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
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": if self.config.is_some() && self.handshaken && live_requests_supported {
                "healthy"
            } else if self.config.is_some() {
                "degraded"
            } else {
                "unconfigured"
            },
            "configured": self.config.is_some(),
            "handshaken": self.handshaken,
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
                && self.handshaken
                && live_requests_supported
            {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                { "name": "configuration", "passed": self.config.is_some(), "critical": true },
                { "name": "client_initialized", "passed": self.client.is_some(), "critical": true },
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
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
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
                "message": "Deepgram is not configured."
            }));
        };

        match client.get_json("/v1/projects").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "surface_boundary": BOUNDARY,
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
        let supported = operation == "deepgram.listen.transcribe";
        let blocked_by_secretless_auth = supported
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.is_secretless());

        Ok(json!({
            "allowed": supported && !blocked_by_secretless_auth,
            "reason": if blocked_by_secretless_auth {
                "credential_id mode requires host-side credential injection, which this connector slice does not implement."
            } else if supported {
                "Supported operation."
            } else {
                "Unknown operation."
            }
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
    if !is_localhost && !allowed_hosts.contains(&host) {
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn config_requires_exactly_one_auth_source() {
        let error = DeepgramConfig::from_params(&json!({
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
            &["api.deepgram.com", "developers.deepgram.com"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = DeepgramConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_performs_authenticated_project_probe() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/projects"))
            .and(header("authorization", "Token test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "projects": [] })))
            .expect(1)
            .mount(&server)
            .await;

        let mut connector = DeepgramConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key",
                "base_url": server.uri()
            }))
            .await
            .expect("expected configure to succeed");

        let self_check = connector
            .handle_self_check()
            .await
            .expect("expected self-check result");
        assert_eq!(self_check["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_requires_handshake_before_reporting_healthy() {
        let mut connector = DeepgramConnector::new();
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
    async fn upstream_retry_after_hint_is_preserved() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/projects"))
            .and(header("authorization", "Token test-key"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "7")
                    .set_body_string("{\"error\":\"slow down\"}"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let config = DeepgramConfig::from_params(&json!({
            "api_key": "test-key",
            "base_url": server.uri()
        }))
        .expect("expected valid config");
        let client = DeepgramClient::new(&config).expect("expected client");
        let error = client
            .get_json("/v1/projects")
            .await
            .expect_err("expected rate-limited error");

        match error {
            FcpError::External {
                status_code,
                retry_after,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert_eq!(retry_after, Some(Duration::from_secs(7)));
                assert!(retryable);
            }
            other => panic!("expected external error, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = DeepgramConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "deepgram.listen.transcribe"}))
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
}
