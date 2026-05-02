use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_prelude::{BaseConnector, ConnectorId, FcpError, FcpResult};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.elevenlabs";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://api.elevenlabs.io/v1";
const BOUNDARY: &str = "This first slice exposes voice discovery plus request-response text-to-speech. Streaming synthesis and voice cloning stay out of scope.";

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
            Self::ApiKey(key) => request.header("xi-api-key", key),
            // Credential IDs are host-side references, not upstream auth material.
            Self::CredentialId { .. } => request,
        }
    }
}

#[derive(Clone)]
struct ElevenLabsConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for ElevenLabsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElevenLabsConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl ElevenLabsConfig {
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
                &["elevenlabs.io"],
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
struct ElevenLabsClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for ElevenLabsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElevenLabsClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl ElevenLabsClient {
    fn new(config: &ElevenLabsConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build ElevenLabs HTTP client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
        })
    }

    fn request(&self, method: Method, path: &str) -> FcpResult<RequestBuilder> {
        let url = self.url_for_path(path)?;
        Ok(self
            .auth
            .apply(self.http.request(method, url))
            .header("Accept", "application/json"))
    }

    fn url_for_path(&self, path: &str) -> FcpResult<Url> {
        let mut url = parse_base_url(&self.base_url)?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| FcpError::InvalidRequest {
                    code: 1003,
                    message: "base_url cannot be used as a hierarchical URL".into(),
                })?;
            for segment in path.split('/').filter(|segment| !segment.is_empty()) {
                segments.push(segment);
            }
        }
        Ok(url)
    }

    fn url_for_segments<'a, I>(&self, segments: I) -> FcpResult<Url>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut url = parse_base_url(&self.base_url)?;
        {
            let mut path_segments =
                url.path_segments_mut()
                    .map_err(|()| FcpError::InvalidRequest {
                        code: 1003,
                        message: "base_url cannot be used as a hierarchical URL".into(),
                    })?;
            for segment in segments {
                path_segments.push(segment);
            }
        }
        Ok(url)
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path)?, "elevenlabs").await
    }

    async fn synthesize(
        &self,
        voice_id: &str,
        body: Value,
        output_format: Option<&str>,
        optimize_streaming_latency: Option<u64>,
    ) -> FcpResult<Value> {
        let mut url = self.url_for_segments(["text-to-speech", voice_id])?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(output_format) = output_format {
                query.append_pair("output_format", output_format);
            }
            if let Some(latency) = optimize_streaming_latency {
                query.append_pair("optimize_streaming_latency", &latency.to_string());
            }
        }
        let response = self
            .auth
            .apply(
                self.http
                    .request(Method::POST, url)
                    .header("Content-Type", "application/json"),
            )
            .json(&body)
            .send()
            .await
            .map_err(|error| map_reqwest_error("elevenlabs", &error))?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = parse_retry_after(response.headers());
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable response body>".into());
            return Err(FcpError::External {
                service: "elevenlabs".into(),
                message: format!("HTTP {status}: {body}"),
                status_code: Some(status.as_u16()),
                retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
                retry_after,
            });
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map_or_else(|| "application/octet-stream".into(), ToOwned::to_owned);
        let audio = response.bytes().await.map_err(|error| FcpError::External {
            service: "elevenlabs".into(),
            message: format!("Failed to read TTS response body: {error}"),
            status_code: Some(status.as_u16()),
            retryable: false,
            retry_after: None,
        })?;

        Ok(json!({
            "voice_id": voice_id,
            "content_type": content_type,
            "audio_base64": BASE64_STANDARD.encode(audio.as_ref()),
            "audio_size_bytes": audio.len(),
        }))
    }
}

pub struct ElevenlabsConnector {
    base: Arc<BaseConnector>,
    config: Option<ElevenLabsConfig>,
    client: Option<Arc<ElevenLabsClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl ElevenlabsConnector {
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
        let config = ElevenLabsConfig::from_params(&params)?;
        let client = ElevenLabsClient::new(&config)?;
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

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        self.session_id = params
            .get("session_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| Some("elevenlabs-local-session".into()));
        self.base.set_handshaken(true);

        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["elevenlabs.tts", "elevenlabs.voices"],
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
                "message": "ElevenLabs is not configured."
            }));
        };

        match client.get_json("/voices").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "surface_boundary": "voices.list + text-to-speech",
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
            message: "ElevenLabs client not initialized".into(),
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
            "elevenlabs.voices.list" => client.get_json("/voices").await,
            "elevenlabs.tts.generate" => self.invoke_tts(client, &input).await,
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
        let supported = matches!(
            operation,
            "elevenlabs.tts.generate" | "elevenlabs.voices.list"
        );
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
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    async fn invoke_tts(&self, client: &ElevenLabsClient, input: &Value) -> FcpResult<Value> {
        let voice_id = input
            .get("voice_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "voice_id is required".into(),
            })?;
        let text = input
            .get("text")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "text is required".into(),
            })?;

        let mut body = json!({ "text": text });
        copy_if_present(&mut body, input, "model_id");
        copy_if_present(&mut body, input, "language_code");
        copy_if_present(&mut body, input, "voice_settings");
        copy_if_present(&mut body, input, "pronunciation_dictionary_locators");

        let output_format = input
            .get("output_format")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let optimize_streaming_latency = input
            .get("optimize_streaming_latency")
            .and_then(Value::as_u64);

        client
            .synthesize(voice_id, body, output_format, optimize_streaming_latency)
            .await
    }
}

impl Default for ElevenlabsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operations_info() -> Vec<Value> {
    vec![
        json!({
            "id": "elevenlabs.voices.list",
            "summary": "List ElevenLabs voices",
            "description": "Reads the current voice catalog from GET /voices.",
            "capability": "elevenlabs.voices",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {"type": "object", "properties": {}},
            "output_schema": {"type": "object"},
        }),
        json!({
            "id": "elevenlabs.tts.generate",
            "summary": "Generate speech audio with ElevenLabs",
            "description": "Runs request-response synthesis against POST /text-to-speech/{voice_id} and returns the encoded audio bytes.",
            "capability": "elevenlabs.tts",
            "risk_level": "medium",
            "safety_tier": "safe",
            "idempotency": "none",
            "input_schema": {
                "type": "object",
                "required": ["voice_id", "text"],
                "properties": {
                    "voice_id": {"type": "string"},
                    "text": {"type": "string"},
                    "model_id": {"type": "string"},
                    "language_code": {"type": "string"},
                    "voice_settings": {"type": "object"},
                    "pronunciation_dictionary_locators": {"type": "array"},
                    "output_format": {"type": "string"},
                    "optimize_streaming_latency": {"type": "integer"}
                }
            },
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

fn parse_base_url(base_url: &str) -> FcpResult<Url> {
    Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })
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
        let error = ElevenLabsConfig::from_params(&json!({
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
            &["elevenlabs.io"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = ElevenLabsConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[test]
    fn request_path_preserves_base_prefix() {
        let config = ElevenLabsConfig::from_params(&json!({
            "api_key": "test-key"
        }))
        .expect("expected valid config");
        let client = ElevenLabsClient::new(&config).expect("expected client");
        let url = client.url_for_path("/voices").expect("expected url");
        assert_eq!(url.path(), "/v1/voices");
    }

    #[test]
    fn synthesize_url_encodes_voice_id_as_single_segment() {
        let config = ElevenLabsConfig::from_params(&json!({
            "api_key": "test-key"
        }))
        .expect("expected valid config");
        let client = ElevenLabsClient::new(&config).expect("expected client");
        let url = client
            .url_for_segments(["text-to-speech", "voice/../../evil?x=1#frag"])
            .expect("expected url");

        assert_eq!(
            url.path(),
            "/v1/text-to-speech/voice%2F..%2F..%2Fevil%3Fx=1%23frag"
        );
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    #[test]
    fn synthesize_url_places_audio_options_in_query() {
        let config = ElevenLabsConfig::from_params(&json!({
            "api_key": "test-key"
        }))
        .expect("expected valid config");
        let client = ElevenLabsClient::new(&config).expect("expected client");
        let mut url = client
            .url_for_segments(["text-to-speech", "voice-id"])
            .expect("expected url");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("output_format", "mp3_44100_128");
            query.append_pair("optimize_streaming_latency", "1");
        }

        assert_eq!(
            url.as_str(),
            "https://api.elevenlabs.io/v1/text-to-speech/voice-id?output_format=mp3_44100_128&optimize_streaming_latency=1"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = ElevenlabsConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "elevenlabs.voices.list"}))
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
