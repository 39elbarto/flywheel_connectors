use std::{
    net::{IpAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use crate::error::ZaloError;
use fcp_prelude::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde::Deserialize;
use serde_json::{Value, json};
use url::{Host, Url};

const CONNECTOR_ID: &str = "fcp.zalo";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str = "This first slice covers bot identity, message send, photo send, long-poll updates, webhook setup, and webhook token verification.";
const NOT_HANDSHAKEN_REASON_CODE: &str = "not_handshaken";
const NOT_HANDSHAKEN_MESSAGE: &str = "Connector configured, but handshake has not completed yet.";
const MISSING_TOKEN_REASON_CODE: &str = "missing_access_token";
const WEBHOOK_VERIFY_OPERATION_ID: &str = "zalo.webhook.verify";
const GET_ME_OPERATION_ID: &str = "zalo.self.get_me";
const SEND_MESSAGE_OPERATION_ID: &str = "zalo.messages.send";
const SEND_PHOTO_OPERATION_ID: &str = "zalo.messages.send_photo";
const POLL_UPDATES_OPERATION_ID: &str = "zalo.updates.poll";
const SET_WEBHOOK_OPERATION_ID: &str = "zalo.webhook.set";
const DELETE_WEBHOOK_OPERATION_ID: &str = "zalo.webhook.delete";
const WEBHOOK_INFO_OPERATION_ID: &str = "zalo.webhook.info";
const DEFAULT_BASE_URL: &str = "https://bot-api.zaloplatforms.com";
const ZALO_API_HOST: &str = "bot-api.zaloplatforms.com";
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const MAX_REQUEST_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 30;
const MAX_POLL_TIMEOUT_SECONDS: u64 = 55;
const MAX_MESSAGE_CHARS: usize = 2_000;
const LIVE_CAPABILITIES: [&str; 3] = ["zalo.messages", "zalo.updates", "zalo.webhook"];

pub struct ZaloConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
    webhook_verify_challenge: Option<String>,
    config: Option<ZaloConfig>,
    client: reqwest::Client,
}

#[derive(Clone, Debug)]
struct ZaloConfig {
    base_url: String,
    credential: Option<String>,
    request_timeout_ms: u64,
}

#[derive(Deserialize)]
struct ZaloApiEnvelope {
    ok: bool,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error_code: Option<u16>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Clone, Copy)]
enum PublicUrlKind {
    Photo,
    Webhook,
}

// Zalo's planned FCP handlers share async signatures before live invoke support lands.
#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl ZaloConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            configured: false,
            handshaken: false,
            webhook_verify_challenge: None,
            config: None,
            client: reqwest::Client::new(),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let base_url = optional_trimmed_string(&params, "base_url")?
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let normalized_base_url = normalize_base_url(&base_url)?;
        let request_timeout_ms =
            optional_u64(&params, "request_timeout_ms")?.unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
        if request_timeout_ms == 0 || request_timeout_ms > MAX_REQUEST_TIMEOUT_MS {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "request_timeout_ms must be between 1 and {MAX_REQUEST_TIMEOUT_MS}"
                ),
            });
        }

        let credential =
            first_optional_trimmed_string(&params, &["access_token", "bot_token", "token"])?;
        if let Some(value) = credential.as_deref() {
            validate_access_token(value)?;
        }

        self.webhook_verify_challenge =
            if let Some(token) = optional_trimmed_string(&params, "webhook_verify_challenge")? {
                Some(token)
            } else {
                optional_trimmed_string(&params, "webhook_token")?
            };
        self.config = Some(ZaloConfig {
            base_url: normalized_base_url,
            credential,
            request_timeout_ms,
        });
        self.configured = true;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "bot_api_configured": self
                .config
                .as_ref()
                .and_then(|config| config.credential.as_ref())
                .is_some(),
            "base_url": self.config.as_ref().map(|config| config.base_url.as_str()),
            "request_timeout_ms": request_timeout_ms,
            "webhook_verify_configured": self.webhook_verify_challenge.is_some()
        }))
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
            "capabilities": LIVE_CAPABILITIES,
            "surface_status": "experimental",
            "surface_status_rationale": "Live request-response Zalo Bot API operations are implemented with bounded HTTP, URL policy, and loopback proof."
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let bot_api_configured = self.has_access_token();
        Ok(json!({
            "status": if !self.configured {
                "unconfigured"
            } else if bot_api_configured {
                "ready"
            } else {
                "degraded"
            },
            "configured": self.configured,
            "handshaken": self.handshaken,
            "bot_api_configured": bot_api_configured,
            "live_requests_supported": bot_api_configured,
            "base_url": self.config.as_ref().map(|config| config.base_url.as_str()),
            "surface_status": "experimental",
            "implemented_operations": implemented_operations(),
            "capabilities": LIVE_CAPABILITIES,
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let bot_api_configured = self.has_access_token();
        Ok(json!({
            "status": if !self.configured {
                "unhealthy"
            } else if bot_api_configured {
                "ready"
            } else {
                "degraded"
            },
            "checks": [
                { "name": "configuration", "passed": self.configured, "critical": true },
                { "name": "access_token", "passed": bot_api_configured, "critical": true, "message": if bot_api_configured { "Zalo Bot API token configured." } else { "Configure access_token or bot_token before invoking upstream Bot API operations." } },
                { "name": "base_url", "passed": self.config.as_ref().is_some_and(|config| validate_base_url(&config.base_url).is_ok()), "critical": true, "message": self.config.as_ref().map_or("not configured", |config| config.base_url.as_str()) },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "webhook_verify", "passed": self.webhook_verify_challenge.is_some(), "critical": false, "message": "Local webhook token verification is implemented when webhook_verify_challenge is configured." },
                { "name": "invoke_surface", "passed": true, "critical": false, "message": "Zalo Bot API getMe, sendMessage, sendPhoto, getUpdates, setWebhook, deleteWebhook, and getWebhookInfo are wired through bounded POST requests." },
                { "name": "url_policy", "passed": true, "critical": true, "message": "Photo and webhook URLs must be public HTTPS targets; localhost/private/link-local/multicast/unspecified targets are rejected before API calls." },
                { "name": "surface_status", "passed": true, "critical": false, "message": "Connector is experimental while live Bot API behavior is validated through loopback proof and operator opt-in." },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let (status, reason_code, message) = if !self.configured {
            ("degraded", json!("not_configured"), json!(BOUNDARY))
        } else if !self.handshaken {
            (
                "degraded",
                json!(NOT_HANDSHAKEN_REASON_CODE),
                json!(NOT_HANDSHAKEN_MESSAGE),
            )
        } else if !self.has_access_token() {
            (
                "degraded",
                json!(MISSING_TOKEN_REASON_CODE),
                json!(
                    "Configure access_token or bot_token before invoking Zalo Bot API operations."
                ),
            )
        } else {
            (
                "ok",
                json!("ready"),
                json!("Zalo Bot API request-response operations are configured."),
            )
        };
        Ok(json!({
            "status": status,
            "reason_code": reason_code,
            "message": message,
            "surface_status": "experimental",
            "implemented_operations": implemented_operations(),
            "capabilities": LIVE_CAPABILITIES
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": [
                { "id": GET_ME_OPERATION_ID, "summary": "Get Zalo bot identity", "capability": "zalo.messages", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict", "implemented": true },
                { "id": SEND_MESSAGE_OPERATION_ID, "summary": "Send a Zalo text message", "capability": "zalo.messages", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": true },
                { "id": SEND_PHOTO_OPERATION_ID, "summary": "Send a Zalo photo message", "capability": "zalo.messages", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": true },
                { "id": POLL_UPDATES_OPERATION_ID, "summary": "Long-poll one Zalo update", "capability": "zalo.updates", "risk_level": "low", "safety_tier": "safe", "idempotency": "none", "implemented": true },
                { "id": SET_WEBHOOK_OPERATION_ID, "summary": "Set the Zalo webhook URL", "capability": "zalo.webhook", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": true },
                { "id": DELETE_WEBHOOK_OPERATION_ID, "summary": "Delete the Zalo webhook", "capability": "zalo.webhook", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": true },
                { "id": WEBHOOK_INFO_OPERATION_ID, "summary": "Get Zalo webhook info", "capability": "zalo.webhook", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict", "implemented": true },
                { "id": WEBHOOK_VERIFY_OPERATION_ID, "summary": "Verify a webhook secret token against local config", "capability": "zalo.webhook", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict", "implemented": true }
            ],
            "surface_status": "experimental",
            "surface_status_rationale": "Runtime path performs live Bot API-shaped requests with bounded HTTP and public-URL policy.",
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

        if operation == WEBHOOK_VERIFY_OPERATION_ID {
            return self.invoke_webhook_verify(params.get("input").unwrap_or(&params));
        }

        let input = params.get("input").unwrap_or(&params);
        match operation {
            GET_ME_OPERATION_ID => self.invoke_get_me().await,
            SEND_MESSAGE_OPERATION_ID => self.invoke_send_message(input).await,
            SEND_PHOTO_OPERATION_ID => self.invoke_send_photo(input).await,
            POLL_UPDATES_OPERATION_ID => self.invoke_poll_updates(input).await,
            SET_WEBHOOK_OPERATION_ID => self.invoke_set_webhook(input).await,
            DELETE_WEBHOOK_OPERATION_ID => self.invoke_delete_webhook().await,
            WEBHOOK_INFO_OPERATION_ID => self.invoke_webhook_info().await,
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");

        if operation == WEBHOOK_VERIFY_OPERATION_ID {
            let input = params.get("input").unwrap_or(&params);
            let supplied_challenge = input
                .get("token")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|token| !token.is_empty());
            let configured =
                self.configured && self.handshaken && self.webhook_verify_challenge.is_some();
            let token_matches = configured
                && supplied_challenge.is_some_and(|token| {
                    self.webhook_verify_challenge
                        .as_deref()
                        .is_some_and(|expected| {
                            constant_time_eq(expected.as_bytes(), token.as_bytes())
                        })
                });
            return Ok(json!({
                "allowed": token_matches,
                "simulate_capability": "local_validation",
                "reason": if token_matches {
                    "Webhook verification token matches configured challenge."
                } else if !self.configured {
                    "Connector is not configured."
                } else if !self.handshaken {
                    NOT_HANDSHAKEN_MESSAGE
                } else if self.webhook_verify_challenge.is_none() {
                    "webhook_verify_challenge is not configured."
                } else if supplied_challenge.is_none() {
                    "Missing token."
                } else {
                    "Webhook verification token would not match configured challenge."
                }
            }));
        }

        let known_live_operation = matches!(
            operation,
            GET_ME_OPERATION_ID
                | SEND_MESSAGE_OPERATION_ID
                | SEND_PHOTO_OPERATION_ID
                | POLL_UPDATES_OPERATION_ID
                | SET_WEBHOOK_OPERATION_ID
                | DELETE_WEBHOOK_OPERATION_ID
                | WEBHOOK_INFO_OPERATION_ID
        );

        Ok(json!({
            "allowed": known_live_operation && self.has_access_token(),
            "simulate_capability": if known_live_operation { "zalo_bot_api" } else { "unsupported" },
            "reason": if !known_live_operation {
                "Unknown operation."
            } else if self.has_access_token() {
                "Operation is implemented and would perform a bounded Zalo Bot API request."
            } else {
                "Configure access_token or bot_token before invoking upstream Zalo Bot API operations."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = false;
        self.handshaken = false;
        self.webhook_verify_challenge = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn has_access_token(&self) -> bool {
        self.config
            .as_ref()
            .and_then(|config| config.credential.as_deref())
            .is_some_and(|value| !value.is_empty())
    }

    async fn invoke_get_me(&self) -> FcpResult<Value> {
        self.call_zalo_api("getMe", None, None).await
    }

    async fn invoke_send_message(&self, input: &Value) -> FcpResult<Value> {
        let chat_id = required_any_string(input, &["recipient_id", "chat_id"], "recipient_id")?;
        let text = required_string(input, "message")?;
        let body = json!({
            "chat_id": chat_id,
            "text": truncate_chars(&text, MAX_MESSAGE_CHARS),
        });
        self.call_zalo_api("sendMessage", Some(body), None).await
    }

    async fn invoke_send_photo(&self, input: &Value) -> FcpResult<Value> {
        let chat_id = required_any_string(input, &["recipient_id", "chat_id"], "recipient_id")?;
        let photo = required_any_string(input, &["photo_url", "photo"], "photo_url")?;
        let photo = validate_public_https_url(&photo, PublicUrlKind::Photo)
            .map_err(|error| error.to_fcp_error())?;
        let mut body = json!({
            "chat_id": chat_id,
            "photo": photo,
        });
        if let Some(caption) = optional_input_string(input, "caption")? {
            body["caption"] = json!(truncate_chars(&caption, MAX_MESSAGE_CHARS));
        }
        self.call_zalo_api("sendPhoto", Some(body), None).await
    }

    async fn invoke_poll_updates(&self, input: &Value) -> FcpResult<Value> {
        let timeout_seconds = optional_u64(input, "timeout_seconds")?
            .or(optional_u64(input, "timeout")?)
            .unwrap_or(DEFAULT_POLL_TIMEOUT_SECONDS);
        if timeout_seconds > MAX_POLL_TIMEOUT_SECONDS {
            return Err(ZaloError::InvalidInput(format!(
                "timeout_seconds must be between 0 and {MAX_POLL_TIMEOUT_SECONDS}"
            ))
            .to_fcp_error());
        }
        let body = json!({ "timeout": timeout_seconds.to_string() });
        let request_timeout_ms = timeout_seconds
            .saturating_add(5)
            .saturating_mul(1_000)
            .max(1);
        self.call_zalo_api("getUpdates", Some(body), Some(request_timeout_ms))
            .await
    }

    async fn invoke_set_webhook(&self, input: &Value) -> FcpResult<Value> {
        let url = required_string(input, "url")?;
        let url = validate_public_https_url(&url, PublicUrlKind::Webhook)
            .map_err(|error| error.to_fcp_error())?;
        let mut body = json!({ "url": url });
        if let Some(secret_token) = optional_input_string(input, "secret_token")?
            .or_else(|| self.webhook_verify_challenge.clone())
        {
            body["secret_token"] = json!(secret_token);
        }
        self.call_zalo_api("setWebhook", Some(body), None).await
    }

    async fn invoke_delete_webhook(&self) -> FcpResult<Value> {
        self.call_zalo_api("deleteWebhook", None, None).await
    }

    async fn invoke_webhook_info(&self) -> FcpResult<Value> {
        self.call_zalo_api("getWebhookInfo", None, None).await
    }

    async fn call_zalo_api(
        &self,
        method: &'static str,
        body: Option<Value>,
        timeout_override_ms: Option<u64>,
    ) -> FcpResult<Value> {
        let config = self.config.as_ref().ok_or_else(|| {
            ZaloError::NotConfigured("configure connector before invoking Zalo Bot API".into())
                .to_fcp_error()
        })?;
        let credential = config.credential.as_deref().ok_or_else(|| {
            ZaloError::NotConfigured("missing access_token or bot_token".into()).to_fcp_error()
        })?;
        let url = build_zalo_api_url(&config.base_url, credential, method)
            .map_err(|error| error.to_fcp_error())?;
        let timeout_ms = timeout_override_ms.unwrap_or(config.request_timeout_ms);
        let mut request = self
            .client
            .post(url)
            .timeout(Duration::from_millis(timeout_ms));
        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request
            .send()
            .await
            .map_err(|error| sanitize_transport_error(method, &error).to_fcp_error())?;
        let status = response.status();
        let retry_after_ms = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after_ms);
        let raw = response
            .text()
            .await
            .map_err(|error| sanitize_transport_error(method, &error).to_fcp_error())?;
        let envelope: ZaloApiEnvelope =
            serde_json::from_str(&raw).map_err(|error| ZaloError::Json(error).to_fcp_error())?;

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || envelope.error_code == Some(429) {
            return Err(ZaloError::RateLimited {
                retry_after_ms: retry_after_ms.unwrap_or(1_000),
            }
            .to_fcp_error());
        }

        if !status.is_success() || !envelope.ok {
            let status_code = envelope.error_code.unwrap_or_else(|| status.as_u16());
            let message = envelope
                .description
                .unwrap_or_else(|| format!("Zalo API returned HTTP {}", status.as_u16()));
            return Err(ZaloError::Api {
                status_code,
                message,
            }
            .to_fcp_error());
        }

        Ok(json!({
            "ok": true,
            "result": envelope.result.unwrap_or_else(|| json!({})),
        }))
    }

    fn invoke_webhook_verify(&self, input: &Value) -> FcpResult<Value> {
        let expected_challenge =
            self.webhook_verify_challenge
                .as_deref()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1004,
                    message: "webhook_verify_challenge is not configured".into(),
                })?;
        let supplied_challenge = input
            .get("token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing token".into(),
            })?;

        Ok(json!({
            "verified": constant_time_eq(expected_challenge.as_bytes(), supplied_challenge.as_bytes())
        }))
    }
}

fn optional_trimmed_string(params: &Value, key: &str) -> FcpResult<Option<String>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must be a string"),
        });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must not be empty"),
        });
    }
    Ok(Some(trimmed.to_string()))
}

fn first_optional_trimmed_string(params: &Value, keys: &[&str]) -> FcpResult<Option<String>> {
    for key in keys {
        if let Some(value) = optional_trimmed_string(params, key)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn optional_u64(params: &Value, key: &str) -> FcpResult<Option<u64>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must be an unsigned integer"),
        })
}

fn normalize_base_url(base_url: &str) -> FcpResult<String> {
    let parsed = validate_base_url(base_url)?;
    let mut normalized = parsed.as_str().trim_end_matches('/').to_string();
    if normalized.is_empty() {
        normalized = DEFAULT_BASE_URL.to_string();
    }
    Ok(normalized)
}

fn validate_base_url(base_url: &str) -> FcpResult<Url> {
    let parsed = Url::parse(base_url.trim()).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid Zalo base_url: {error}"),
    })?;
    let Some(host) = parsed.host_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must include a host".into(),
        });
    };
    let local_host = is_local_base_host(host);

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include embedded credentials".into(),
        });
    }
    if host != ZALO_API_HOST && !local_host {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url host `{host}` is not allowed; use {DEFAULT_BASE_URL} or localhost/127.0.0.1/[::1] for loopback tests"
            ),
        });
    }
    if host == ZALO_API_HOST && parsed.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Production Zalo base_url must use https".into(),
        });
    }
    if local_host && !matches!(parsed.scheme(), "http" | "https") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Loopback Zalo base_url must use http or https".into(),
        });
    }
    if !local_host && parsed.port_or_known_default() != Some(443) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Production Zalo base_url must use port 443".into(),
        });
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a path segment".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include query or fragment components".into(),
        });
    }

    Ok(parsed)
}

fn is_local_base_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn validate_access_token(token: &str) -> FcpResult<()> {
    if token
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '/' | '?' | '#'))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "access_token must not include whitespace or URL path separators".into(),
        });
    }
    Ok(())
}

fn required_string(input: &Value, key: &str) -> FcpResult<String> {
    optional_input_string(input, key)?.ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{key} must not be empty"),
    })
}

fn required_any_string(input: &Value, keys: &[&str], label: &str) -> FcpResult<String> {
    for key in keys {
        if let Some(value) = optional_input_string(input, key)? {
            return Ok(value);
        }
    }
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{label} must not be empty"),
    })
}

fn optional_input_string(input: &Value, key: &str) -> FcpResult<Option<String>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must be a string"),
        });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must not be empty"),
        });
    }
    Ok(Some(trimmed.to_string()))
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn build_zalo_api_url(base_url: &str, token: &str, method: &str) -> Result<Url, ZaloError> {
    let mut url = Url::parse(base_url)
        .map_err(|error| ZaloError::InvalidInput(format!("Invalid base_url: {error}")))?;
    url.set_path(&format!("/bot{token}/{method}"));
    Ok(url)
}

fn sanitize_transport_error(method: &'static str, error: &reqwest::Error) -> ZaloError {
    if error.is_timeout() {
        ZaloError::Async(format!("request deadline exceeded during {method}"))
    } else if error.is_connect() {
        ZaloError::Api {
            status_code: 503,
            message: format!("Zalo API connection failed during {method}"),
        }
    } else {
        ZaloError::Api {
            status_code: error.status().map_or(502, |status| status.as_u16()),
            message: format!("Zalo API transport failed during {method}"),
        }
    }
}

fn parse_retry_after_ms(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1_000))
}

fn validate_public_https_url(value: &str, kind: PublicUrlKind) -> Result<String, ZaloError> {
    let parsed = Url::parse(value).map_err(|error| {
        ZaloError::InvalidInput(format!("{} URL is malformed: {error}", kind.label()))
    })?;
    if parsed.scheme() != "https" {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL must use https",
            kind.label()
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL must not include embedded credentials",
            kind.label()
        )));
    }
    if parsed.fragment().is_some() {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL must not include a fragment",
            kind.label()
        )));
    }
    let ips = resolve_url_ips(&parsed)?;
    if ips.is_empty() {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL host did not resolve to any address",
            kind.label()
        )));
    }
    if let Some(blocked) = ips.into_iter().find(|ip| is_blocked_target_ip(*ip)) {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL resolves to blocked address {blocked}",
            kind.label()
        )));
    }
    Ok(parsed.as_str().to_string())
}

impl PublicUrlKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Photo => "photo",
            Self::Webhook => "webhook",
        }
    }
}

fn resolve_url_ips(url: &Url) -> Result<Vec<IpAddr>, ZaloError> {
    let Some(host) = url.host() else {
        return Err(ZaloError::InvalidInput("URL must include a host".into()));
    };
    match host {
        Host::Ipv4(ip) => Ok(vec![IpAddr::V4(ip)]),
        Host::Ipv6(ip) => Ok(vec![IpAddr::V6(ip)]),
        Host::Domain(domain) => {
            if domain.eq_ignore_ascii_case("localhost")
                || domain
                    .rsplit_once('.')
                    .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("local"))
            {
                return Err(ZaloError::InvalidInput(
                    "URL host must not be localhost or .local".into(),
                ));
            }
            let port = url.port_or_known_default().unwrap_or(443);
            (domain, port)
                .to_socket_addrs()
                .map(|addresses| addresses.map(|address| address.ip()).collect())
                .map_err(|error| {
                    ZaloError::InvalidInput(format!("URL host `{domain}` did not resolve: {error}"))
                })
        }
    }
}

const fn is_blocked_target_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
        }
    }
}

const fn implemented_operations() -> [&'static str; 8] {
    [
        GET_ME_OPERATION_ID,
        SEND_MESSAGE_OPERATION_ID,
        SEND_PHOTO_OPERATION_ID,
        POLL_UPDATES_OPERATION_ID,
        SET_WEBHOOK_OPERATION_ID,
        DELETE_WEBHOOK_OPERATION_ID,
        WEBHOOK_INFO_OPERATION_ID,
        WEBHOOK_VERIFY_OPERATION_ID,
    ]
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

impl Default for ZaloConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs::OpenOptions,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::{Path, PathBuf},
        sync::mpsc::{self, Receiver},
        thread,
        time::Duration,
    };

    use super::*;
    use fcp_manifest::{ConnectorManifest, ConnectorStatus};
    use fcp_sdk::migration::ConnectorErrorMapping;

    const MANIFEST_TOML: &str = include_str!("../manifest.toml");

    #[fcp_async_core::runtime::test]
    async fn live_connector_reports_ready_surface_when_token_configured() {
        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({
                "access_token": "test-token",
                "webhook_verify_challenge": "challenge"
            }))
            .await
            .expect("configure should succeed");

        let pre_handshake = connector
            .handle_self_check()
            .await
            .expect("self_check before handshake should succeed");
        assert_eq!(pre_handshake["status"], "degraded");
        assert_eq!(pre_handshake["reason_code"], NOT_HANDSHAKEN_REASON_CODE);

        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let health = connector
            .handle_health()
            .await
            .expect("health should succeed");
        assert_eq!(health["status"], "ready");
        assert_eq!(health["live_requests_supported"], true);
        assert_eq!(health["surface_status"], "experimental");
        assert_eq!(
            health["implemented_operations"],
            json!(implemented_operations())
        );

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "experimental");
        assert!(
            introspect["operations"]
                .as_array()
                .expect("operations should be an array")
                .iter()
                .all(
                    |operation| operation.get("implemented").and_then(Value::as_bool) == Some(true)
                )
        );

        let self_check = connector
            .handle_self_check()
            .await
            .expect("self_check should succeed");
        assert_eq!(self_check["status"], "ok");
        assert_eq!(self_check["reason_code"], "ready");
        assert_eq!(self_check["surface_status"], "experimental");
    }

    #[fcp_async_core::runtime::test]
    async fn manifest_and_introspection_align_on_experimental_live_surface() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("manifest should validate");
        assert_eq!(manifest.connector.status, ConnectorStatus::Experimental);
        assert!(
            manifest
                .capabilities
                .required
                .iter()
                .all(|capability| { !capability.as_str().starts_with("zalo.") })
        );

        let optional_capabilities = manifest
            .capabilities
            .optional
            .iter()
            .map(fcp_prelude::CapabilityId::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            optional_capabilities,
            BTreeSet::from(["zalo.messages", "zalo.updates", "zalo.webhook"])
        );

        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({
                "access_token": "test-token",
                "webhook_verify_challenge": "challenge"
            }))
            .await
            .expect("configure should succeed");
        let handshake = connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");
        assert_eq!(handshake["capabilities"], json!(LIVE_CAPABILITIES));
        assert_eq!(handshake["surface_status"], "experimental");

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "experimental");

        let manifest_operations = manifest
            .provides
            .operations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let introspected_operations = introspect["operations"]
            .as_array()
            .expect("operations should be an array")
            .iter()
            .map(|operation| operation["id"].as_str().expect("operation id"))
            .collect::<BTreeSet<_>>();
        assert_eq!(manifest_operations, introspected_operations);

        let implemented = introspect["operations"]
            .as_array()
            .expect("operations should be an array")
            .iter()
            .filter(|operation| operation["implemented"].as_bool() == Some(true))
            .map(|operation| operation["id"].as_str().expect("operation id"))
            .collect::<Vec<_>>();
        assert_eq!(implemented, implemented_operations());
    }

    #[fcp_async_core::runtime::test]
    async fn missing_token_invoke_and_simulate_are_stable() {
        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let error = connector
            .handle_invoke(json!({
                "operation_id": SEND_MESSAGE_OPERATION_ID,
                "input": { "recipient_id": "chat-1", "message": "hello" }
            }))
            .await
            .expect_err("invoke should reject missing token");
        assert!(matches!(
            error,
            FcpError::InvalidRequest { code: 1001, ref message }
                if message.contains("missing access_token")
        ));

        let simulate = connector
            .handle_simulate(json!({"operation_id": SEND_MESSAGE_OPERATION_ID}))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], false);
        assert_eq!(simulate["simulate_capability"], "zalo_bot_api");
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_verify_uses_configured_challenge_without_upstream_stub() {
        let mut connector = ZaloConnector::new();
        let configure = connector
            .handle_configure(json!({"webhook_verify_challenge": "expected-challenge"}))
            .await
            .expect("configure should succeed");
        assert_eq!(configure["webhook_verify_configured"], true);
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let good = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_VERIFY_OPERATION_ID,
                "input": { "token": "expected-challenge" }
            }))
            .await
            .expect("matching token should verify");
        assert_eq!(good["verified"], true);

        let bad = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_VERIFY_OPERATION_ID,
                "input": { "token": "wrong-challenge" }
            }))
            .await
            .expect("mismatched token should return a negative verification result");
        assert_eq!(bad["verified"], false);

        let simulate = connector
            .handle_simulate(json!({
                "operation_id": WEBHOOK_VERIFY_OPERATION_ID,
                "input": { "token": "expected-challenge" }
            }))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], true);
        assert_eq!(simulate["simulate_capability"], "local_validation");

        let bad_simulate = connector
            .handle_simulate(json!({
                "operation_id": WEBHOOK_VERIFY_OPERATION_ID,
                "input": { "token": "wrong-challenge" }
            }))
            .await
            .expect("simulate should succeed for mismatched token");
        assert_eq!(bad_simulate["allowed"], false);
        assert!(
            bad_simulate["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("would not match"))
        );
    }

    #[test]
    fn constant_time_eq_matches_equal_byte_strings_only() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"Secret"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(!constant_time_eq(b"secret", b""));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_error_paths_are_ordered_and_specific() {
        let mut connector = ZaloConnector::new();

        let unconfigured = connector
            .handle_invoke(json!({"operation_id": SEND_MESSAGE_OPERATION_ID}))
            .await
            .expect_err("invoke should require configure first");
        assert!(matches!(unconfigured, FcpError::NotConfigured));

        connector
            .handle_configure(json!({"access_token": "test-token"}))
            .await
            .expect("configure should succeed");
        let not_handshaken = connector
            .handle_invoke(json!({"operation_id": SEND_MESSAGE_OPERATION_ID}))
            .await
            .expect_err("invoke should require handshake after configure");
        assert!(matches!(not_handshaken, FcpError::NotHandshaken));

        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");
        let missing_operation = connector
            .handle_invoke(json!({}))
            .await
            .expect_err("invoke should reject missing operation id");
        assert!(matches!(
            missing_operation,
            FcpError::InvalidRequest { code: 1003, ref message }
                if message.contains("Missing operation_id")
        ));

        let unknown_operation = connector
            .handle_invoke(json!({"operation_id": "zalo.unknown"}))
            .await
            .expect_err("invoke should reject unknown operations");
        assert!(matches!(
            unknown_operation,
            FcpError::InvalidRequest { code: 1002, ref message }
                if message.contains("Unknown operation: zalo.unknown")
        ));
    }

    #[test]
    fn base_url_and_access_token_validation_are_strict() {
        assert!(validate_base_url(DEFAULT_BASE_URL).is_ok());
        assert!(validate_base_url("http://127.0.0.1:38080").is_ok());
        assert!(validate_base_url("https://bot-api.zaloplatforms.com/path").is_err());
        assert!(validate_base_url("https://example.com").is_err());
        assert!(validate_access_token("abc/def").is_err());
        assert!(validate_access_token("abc def").is_err());
    }

    #[test]
    fn public_url_policy_rejects_non_https_and_private_targets() {
        assert!(
            validate_public_https_url("http://93.184.216.34/photo.jpg", PublicUrlKind::Photo)
                .is_err()
        );
        assert!(
            validate_public_https_url("https://127.0.0.1/photo.jpg", PublicUrlKind::Photo).is_err()
        );
        assert!(
            validate_public_https_url("https://10.0.0.1/hook", PublicUrlKind::Webhook).is_err()
        );
        assert!(
            validate_public_https_url("https://93.184.216.34/photo.jpg", PublicUrlKind::Photo)
                .is_ok()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn request_bodies_are_zalo_bot_api_shaped() {
        let (base_url, requests, join) = spawn_loopback_server(
            vec![
                LoopbackResponse::json(
                    "send_message",
                    200,
                    r#"{"ok":true,"result":{"message_id":"msg-1"}}"#,
                ),
                LoopbackResponse::json(
                    "send_photo",
                    200,
                    r#"{"ok":true,"result":{"message_id":"photo-1"}}"#,
                ),
                LoopbackResponse::json(
                    "set_webhook",
                    200,
                    r#"{"ok":true,"result":{"url":"https://93.184.216.34/hook"}}"#,
                ),
            ],
            None,
        );
        let connector = configured_loopback_connector(&base_url, 1_000).await;

        let text = connector
            .handle_invoke(json!({
                "operation_id": SEND_MESSAGE_OPERATION_ID,
                "input": { "recipient_id": "chat-1", "message": "hello" }
            }))
            .await
            .expect("sendMessage should succeed");
        assert_eq!(text["result"]["message_id"], "msg-1");

        let photo = connector
            .handle_invoke(json!({
                "operation_id": SEND_PHOTO_OPERATION_ID,
                "input": {
                    "recipient_id": "chat-1",
                    "photo_url": "https://93.184.216.34/photo.jpg",
                    "caption": "caption"
                }
            }))
            .await
            .expect("sendPhoto should succeed");
        assert_eq!(photo["result"]["message_id"], "photo-1");

        let webhook = connector
            .handle_invoke(json!({
                "operation_id": SET_WEBHOOK_OPERATION_ID,
                "input": {
                    "url": "https://93.184.216.34/hook",
                    "secret_token": "secret"
                }
            }))
            .await
            .expect("setWebhook should succeed");
        assert_eq!(webhook["result"]["url"], "https://93.184.216.34/hook");

        let first = requests
            .recv_timeout(Duration::from_secs(1))
            .expect("send_message request should be recorded");
        assert_eq!(first.label, "send_message");
        assert_eq!(
            first.request_line,
            "POST /bottest-token/sendMessage HTTP/1.1"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&first.body).expect("json body"),
            json!({ "chat_id": "chat-1", "text": "hello" })
        );

        let second = requests
            .recv_timeout(Duration::from_secs(1))
            .expect("send_photo request should be recorded");
        assert_eq!(second.label, "send_photo");
        assert_eq!(
            second.request_line,
            "POST /bottest-token/sendPhoto HTTP/1.1"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&second.body).expect("json body"),
            json!({
                "chat_id": "chat-1",
                "photo": "https://93.184.216.34/photo.jpg",
                "caption": "caption"
            })
        );

        let third = requests
            .recv_timeout(Duration::from_secs(1))
            .expect("set_webhook request should be recorded");
        assert_eq!(third.label, "set_webhook");
        assert_eq!(
            third.request_line,
            "POST /bottest-token/setWebhook HTTP/1.1"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&third.body).expect("json body"),
            json!({
                "url": "https://93.184.216.34/hook",
                "secret_token": "secret"
            })
        );

        join.join().expect("loopback server should exit");
    }

    #[fcp_async_core::runtime::test]
    async fn loopback_e2e_logs_success_auth_rate_limit_malformed_timeout_and_cancellation() {
        let log_path = loopback_log_path();
        let (base_url, _requests, join) = spawn_loopback_server(
            vec![
                LoopbackResponse::json(
                    "success",
                    200,
                    r#"{"ok":true,"result":{"id":"bot-1","name":"Test Bot"}}"#,
                ),
                LoopbackResponse::json(
                    "auth_failure",
                    200,
                    r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
                ),
                LoopbackResponse::json(
                    "rate_limit",
                    429,
                    r#"{"ok":false,"error_code":429,"description":"Too many requests"}"#,
                ),
                LoopbackResponse::json("malformed", 200, "not-json"),
                LoopbackResponse::delayed_json(
                    "timeout",
                    200,
                    r#"{"ok":true,"result":{"late":true}}"#,
                    Duration::from_millis(150),
                ),
            ],
            Some(log_path.clone()),
        );
        let connector = configured_loopback_connector(&base_url, 25).await;

        let success = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect("success response should parse");
        assert_eq!(success["result"]["id"], "bot-1");

        let auth_failure = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect_err("auth failure should map to FCP error");
        assert!(matches!(
            auth_failure,
            FcpError::External {
                status_code: Some(401),
                retryable: false,
                ..
            }
        ));

        let rate_limit = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect_err("rate limit should map to FCP rate limit");
        assert!(matches!(rate_limit, FcpError::RateLimited { .. }));

        let malformed = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect_err("malformed response should map to internal parse error");
        assert!(matches!(malformed, FcpError::Internal { .. }));

        let timeout = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect_err("delayed response should timeout");
        assert!(timeout.to_string().contains("deadline exceeded"));

        let cancelled = ZaloError::from_async_error(fcp_async_core::AsyncError::Cancelled);
        append_jsonl(
            &log_path,
            &json!({
                "case": "cancellation",
                "status": "mapped",
                "error": cancelled.to_string()
            }),
        );
        assert!(cancelled.to_string().contains("cancelled"));

        join.join().expect("loopback server should exit");
        let log = std::fs::read_to_string(&log_path).expect("jsonl log should be readable");
        for label in [
            "success",
            "auth_failure",
            "rate_limit",
            "malformed",
            "timeout",
            "cancellation",
        ] {
            assert!(log.contains(label), "missing JSONL evidence for {label}");
        }
    }

    #[derive(Debug)]
    struct RecordedRequest {
        label: String,
        request_line: String,
        body: String,
    }

    struct LoopbackResponse {
        label: &'static str,
        status: u16,
        body: &'static str,
        delay: Duration,
    }

    impl LoopbackResponse {
        const fn json(label: &'static str, status: u16, body: &'static str) -> Self {
            Self {
                label,
                status,
                body,
                delay: Duration::from_millis(0),
            }
        }

        const fn delayed_json(
            label: &'static str,
            status: u16,
            body: &'static str,
            delay: Duration,
        ) -> Self {
            Self {
                label,
                status,
                body,
                delay,
            }
        }
    }

    async fn configured_loopback_connector(base_url: &str, timeout_ms: u64) -> ZaloConnector {
        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({
                "access_token": "test-token",
                "base_url": base_url,
                "request_timeout_ms": timeout_ms,
                "webhook_verify_challenge": "secret"
            }))
            .await
            .expect("loopback configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("loopback handshake should succeed");
        connector
    }

    fn spawn_loopback_server(
        responses: Vec<LoopbackResponse>,
        log_path: Option<PathBuf>,
    ) -> (String, Receiver<RecordedRequest>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        let (tx, rx) = mpsc::channel();
        let join = thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _peer)) = listener.accept() else {
                    continue;
                };
                let (request_line, body) = read_http_request(&mut stream);
                if let Some(path) = log_path.as_deref() {
                    append_jsonl(
                        path,
                        &json!({
                            "case": response.label,
                            "request_line": request_line,
                            "body": body,
                            "status": response.status,
                            "delay_ms": response.delay.as_millis()
                        }),
                    );
                }
                tx.send(RecordedRequest {
                    label: response.label.to_string(),
                    request_line,
                    body,
                })
                .expect("record request");
                if response.delay > Duration::from_millis(0) {
                    thread::sleep(response.delay);
                }
                let header = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    response.body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(response.body.as_bytes());
            }
        });
        (base_url, rx, join)
    }

    fn read_http_request(stream: &mut TcpStream) -> (String, String) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).expect("read request");
            assert!(read > 0, "request stream ended before headers");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position;
            }
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let body_start = header_end + 4;
        while buffer.len() < body_start + content_length {
            let read = stream.read(&mut chunk).expect("read request body");
            assert!(read > 0, "request stream ended before body");
            buffer.extend_from_slice(&chunk[..read]);
        }
        let request_line = headers.lines().next().expect("request line").to_string();
        let body =
            String::from_utf8_lossy(&buffer[body_start..body_start + content_length]).to_string();
        (request_line, body)
    }

    fn loopback_log_path() -> PathBuf {
        std::env::temp_dir().join(format!("fcp-zalo-loopback-{}.jsonl", std::process::id()))
    }

    fn append_jsonl(path: &Path, value: &Value) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open jsonl log");
        writeln!(file, "{value}").expect("write jsonl log");
    }
}
