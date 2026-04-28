//! `DingTalk` HTTP client with token caching and `ConnectorRuntime` integration.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fcp_async_core::sync::Mutex;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Url, header::HeaderMap, multipart};
use serde_json::{Value, json};

use crate::error::{DingTalkError, DingTalkResult};
use crate::types::{
    AccessTokenResponse, ConversationIdentity, DingTalkCallbackEvent, DingTalkConfig,
    NormalizedDingTalkEvent, TOKEN_REFRESH_SAFETY_MARGIN_SECS,
};

#[derive(Clone)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

impl std::fmt::Debug for CachedAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedAccessToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub struct DingTalkClient {
    config: DingTalkConfig,
    client: reqwest::Client,
    token_cache: Arc<Mutex<Option<CachedAccessToken>>>,
    runtime: ConnectorRuntime,
}

impl std::fmt::Debug for DingTalkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DingTalkClient")
            .field("config", &self.config)
            .field("client", &"reqwest::Client")
            .field("token_cache", &"token cache")
            .field("runtime", &"ConnectorRuntime")
            .finish_non_exhaustive()
    }
}

impl DingTalkClient {
    /// Build a configured `DingTalk` HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid or the underlying HTTP client
    /// cannot be initialized.
    pub fn new(config: DingTalkConfig) -> DingTalkResult<Self> {
        let config = config.normalized();
        validate_host(
            &config.base_url,
            &["api.dingtalk.com", "localhost", "127.0.0.1"],
        )?;
        validate_host(
            &config.media_base_url,
            &["oapi.dingtalk.com", "localhost", "127.0.0.1"],
        )?;
        if config.client_id.trim().is_empty() {
            return Err(DingTalkError::Config("client_id must not be empty".into()));
        }
        if config.client_secret.trim().is_empty() {
            return Err(DingTalkError::Config(
                "client_secret must not be empty".into(),
            ));
        }
        if config.request_timeout_ms == 0 {
            return Err(DingTalkError::Config(
                "request_timeout_ms must be greater than zero".into(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(DingTalkError::Http)?;

        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        );

        Ok(Self {
            config,
            client,
            token_cache: Arc::new(Mutex::new(None)),
            runtime,
        })
    }

    #[must_use]
    pub const fn runtime(&self) -> &ConnectorRuntime {
        &self.runtime
    }

    #[must_use]
    pub const fn config(&self) -> &DingTalkConfig {
        &self.config
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn api_url(&self, path: &str) -> DingTalkResult<Url> {
        Url::parse(self.config.base_url.trim())
            .map(|mut url| {
                url.set_path(path);
                url
            })
            .map_err(|e| DingTalkError::Config(format!("invalid base_url: {e}")))
    }

    fn media_url(&self, path: &str) -> DingTalkResult<Url> {
        Url::parse(self.config.media_base_url.trim())
            .map(|mut url| {
                url.set_path(path);
                url
            })
            .map_err(|e| DingTalkError::Config(format!("invalid media_base_url: {e}")))
    }

    /// Fetch or reuse a cached `DingTalk` access token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token endpoint rejects the credentials or the
    /// response payload is malformed.
    pub async fn access_token(&self) -> DingTalkResult<String> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(cached) = cache.as_ref() {
                if Instant::now() < cached.expires_at {
                    return Ok(cached.token.clone());
                }
            }
        }

        let url = self.api_url("/v1.0/oauth2/accessToken")?;
        let response = self
            .client
            .post(url)
            .json(&json!({
                "appKey": self.config.client_id,
                "appSecret": self.config.client_secret
            }))
            .send()
            .await
            .map_err(DingTalkError::Http)?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();
            return Err(http_status_error(status, &headers, body));
        }

        let body: Value = response.json().await.map_err(|e| {
            DingTalkError::Token(format!("failed to decode access token response: {e}"))
        })?;

        let auth_response: AccessTokenResponse =
            serde_json::from_value(body.clone()).map_err(|e| {
                DingTalkError::Token(format!("failed to parse access token payload: {e}"))
            })?;

        if auth_response.access_token.trim().is_empty() {
            return Err(DingTalkError::Token(
                "access token response missing or empty access_token field".into(),
            ));
        }

        let ttl = auth_response
            .expire_in
            .saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS)
            .max(1);
        *self.token_cache.lock().await = Some(CachedAccessToken {
            token: auth_response.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        });

        Ok(auth_response.access_token)
    }

    /// Send a JSON `POST` request against the `DingTalk` API.
    ///
    /// # Errors
    ///
    /// Returns an error if token acquisition fails, the request cannot be sent,
    /// or `DingTalk` returns a non-success response.
    pub async fn post_json(&self, path: &str, body: Value) -> DingTalkResult<Value> {
        let auth_material = self.access_token().await?;
        let url = self.api_url(path)?;
        let response = self
            .client
            .post(url)
            .header("x-acs-dingtalk-access-token", &auth_material)
            .json(&body)
            .send()
            .await
            .map_err(DingTalkError::Http)?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let text = response.text().await.unwrap_or_default();
            return Err(http_status_error(status, &headers, text));
        }

        response.json().await.map_err(DingTalkError::Http)
    }

    /// Upload media bytes to `DingTalk` and return the API response payload.
    ///
    /// # Errors
    ///
    /// Returns an error if token acquisition fails, the base64 input is
    /// invalid, or the upstream API rejects the upload.
    pub async fn upload_media(
        &self,
        media_type: &str,
        file_name: &str,
        mime_type: &str,
        content_base64: &str,
    ) -> DingTalkResult<Value> {
        let auth_material = self.access_token().await?;
        let bytes = BASE64.decode(content_base64.trim()).map_err(|e| {
            DingTalkError::InvalidInput(format!("content_base64 must be valid base64: {e}"))
        })?;

        let mut url = self.media_url("/media/upload")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &auth_material);
            query.append_pair("type", media_type);
        }

        let part = multipart::Part::bytes(bytes)
            .file_name(file_name.to_string())
            .mime_str(mime_type)
            .map_err(|e| DingTalkError::InvalidInput(format!("invalid mime_type: {e}")))?;

        let response = self
            .client
            .post(url)
            .multipart(multipart::Form::new().part("media", part))
            .send()
            .await
            .map_err(DingTalkError::Http)?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();
            return Err(http_status_error(status, &headers, body));
        }

        let body: Value = response.json().await.map_err(DingTalkError::Http)?;
        ensure_media_success(body)
    }
}

fn validate_host(raw: &str, allowed_hosts: &[&str]) -> DingTalkResult<()> {
    let url = Url::parse(raw.trim())
        .map_err(|e| DingTalkError::Config(format!("invalid URL `{raw}`: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| DingTalkError::Config(format!("URL `{raw}` must include a host")))?;
    let is_local = matches!(host, "localhost" | "127.0.0.1");
    if !is_local && url.scheme() != "https" {
        return Err(DingTalkError::Config(format!(
            "URL `{raw}` must use https for non-local hosts"
        )));
    }
    if !allowed_hosts.contains(&host) {
        return Err(DingTalkError::Config(format!(
            "URL host `{host}` is not allowed"
        )));
    }
    Ok(())
}

fn ensure_media_success(body: Value) -> DingTalkResult<Value> {
    let errcode = body.get("errcode").and_then(Value::as_i64).unwrap_or(0);
    if errcode == 0 {
        Ok(body)
    } else {
        let errmsg = body
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("unknown DingTalk media upload error")
            .to_string();
        Err(DingTalkError::Media { errcode, errmsg })
    }
}

fn http_status_error(status: u16, headers: &HeaderMap, body: String) -> DingTalkError {
    let message = if body.trim().is_empty() {
        format!("DingTalk HTTP request failed with status {status}")
    } else if body.len() > 500 {
        format!("{}...[truncated]", &body[..500])
    } else {
        body
    };
    match status {
        401 | 403 => DingTalkError::Unauthorized(message),
        429 => DingTalkError::RateLimited {
            retry_after_ms: retry_after_ms(headers).unwrap_or(1_000),
        },
        _ => DingTalkError::Api {
            code: u32::from(status),
            message,
        },
    }
}

const MAX_RETRY_AFTER_MS: u64 = 60 * 60 * 1000;

fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after_header_value)
}

fn parse_retry_after_header_value(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1_000).min(MAX_RETRY_AFTER_MS))
}

#[must_use]
pub fn default_mime_type(media_type: &str) -> &'static str {
    match media_type {
        "image" => "image/png",
        "voice" => "audio/amr",
        "video" => "video/mp4",
        _ => "application/octet-stream",
    }
}

/// Map `DingTalk` conversation type codes to human-readable labels.
///
/// * `"1"` -> `"private"`
/// * `"2"` -> `"group"`
/// * anything else -> `"unknown"`
#[must_use]
pub fn normalize_conversation_type(raw: Option<&str>) -> String {
    match raw.map(str::trim) {
        Some("1") => "private".into(),
        Some("2") => "group".into(),
        _ => "unknown".into(),
    }
}

/// Normalize a raw `DingTalk` robot callback event into an [`NormalizedDingTalkEvent`].
///
/// This converts the camelCase callback payload into a uniform structure
/// suitable for downstream processing.
///
/// # Errors
///
/// Returns an error if `raw_json` cannot be deserialized as a callback event.
pub fn normalize_callback_event(raw_json: &Value) -> DingTalkResult<NormalizedDingTalkEvent> {
    let event: DingTalkCallbackEvent =
        serde_json::from_value(raw_json.clone()).map_err(|error| {
            DingTalkError::InvalidInput(format!("invalid callback event payload: {error}"))
        })?;

    let conversation_type = normalize_conversation_type(event.conversation_type.as_deref());

    let text = event.text.as_ref().and_then(|t| t.content.clone());

    let at_bot = detect_at_bot(&event);

    Ok(NormalizedDingTalkEvent {
        event_type: "message".into(),
        message_id: event.msg_id.clone(),
        conversation_id: event.conversation_id.clone(),
        conversation_type,
        sender_id: event.sender_id.clone(),
        sender_name: event.sender_nick.clone(),
        text,
        timestamp_ms: event.create_at,
        at_bot,
        raw: raw_json.clone(),
    })
}

/// Detect whether the bot was @-mentioned in a callback event.
///
/// Returns `true` only when an explicit @-mention entry matches the
/// `chatbot_user_id` field. If the callback does not identify the bot, we do
/// not guess from unrelated mentions.
#[must_use]
pub fn detect_at_bot(event: &DingTalkCallbackEvent) -> bool {
    let Some(at_users) = event.at_users.as_ref() else {
        return false;
    };
    if at_users.is_empty() {
        return false;
    }
    let Some(bot_id) = event
        .chatbot_user_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    else {
        return false;
    };
    at_users.iter().any(|u| {
        u.dingtalk_id
            .as_deref()
            .is_some_and(|id| id.trim() == bot_id)
    })
}

/// Extract a [`ConversationIdentity`] from a callback event.
///
/// Returns `None` if the event has no conversation id.
#[must_use]
pub fn extract_conversation_identity(
    event: &DingTalkCallbackEvent,
) -> Option<ConversationIdentity> {
    let id = event.conversation_id.as_ref()?.clone();
    let conversation_type = normalize_conversation_type(event.conversation_type.as_deref());
    Some(ConversationIdentity {
        id,
        conversation_type,
        title: event.conversation_title.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DEFAULT_TIMEOUT_MS;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    fn test_config(base_url: &str) -> DingTalkConfig {
        DingTalkConfig {
            base_url: base_url.to_string(),
            media_base_url: base_url.to_string(),
            client_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    fn localhost_config() -> DingTalkConfig {
        DingTalkConfig {
            base_url: "http://localhost:9999".into(),
            media_base_url: "http://localhost:9999".into(),
            client_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    #[test]
    fn rejects_empty_client_id() {
        let mut config = localhost_config();
        config.client_id = String::new();
        assert!(DingTalkClient::new(config).is_err());
    }

    #[test]
    fn rejects_empty_client_secret() {
        let mut config = localhost_config();
        config.client_secret.clear();
        assert!(DingTalkClient::new(config).is_err());
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut config = localhost_config();
        config.request_timeout_ms = 0;
        assert!(DingTalkClient::new(config).is_err());
    }

    #[test]
    fn trims_config_fields() {
        let config = DingTalkConfig {
            base_url: " http://localhost:9999 ".into(),
            media_base_url: " http://localhost:9999 ".into(),
            client_id: " test-app ".into(),
            client_secret: " test-secret ".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        let client = DingTalkClient::new(config).unwrap();
        assert_eq!(client.config().base_url, "http://localhost:9999");
        assert_eq!(client.config().media_base_url, "http://localhost:9999");
        assert_eq!(client.config().client_id, "test-app");
        assert_eq!(client.config().client_secret, "test-secret");
    }

    #[test]
    fn rejects_disallowed_host() {
        let config = test_config("https://evil.example.com");
        assert!(DingTalkClient::new(config).is_err());
    }

    #[test]
    fn rejects_insecure_public_host() {
        let config = DingTalkConfig {
            base_url: "http://api.dingtalk.com".into(),
            media_base_url: "http://oapi.dingtalk.com".into(),
            client_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        assert!(DingTalkClient::new(config).is_err());
    }

    #[test]
    fn debug_redacts_runtime() {
        let config = localhost_config();
        let client = DingTalkClient::new(config).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("test-secret"));
    }

    #[fcp_async_core::runtime::test]
    async fn post_json_sends_with_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "tok-1",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1.0/robot/oToMessages/batchSend"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "processQueryKey": "msg-1"
            })))
            .mount(&server)
            .await;

        let client = DingTalkClient::new(test_config(&server.uri())).unwrap();
        let result = client
            .post_json(
                "/v1.0/robot/oToMessages/batchSend",
                json!({"robotCode": "test-app", "userIds": ["u1"]}),
            )
            .await
            .unwrap();
        assert_eq!(result["processQueryKey"], "msg-1");
    }

    #[fcp_async_core::runtime::test]
    async fn post_json_returns_api_error_on_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "tok-1",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1.0/robot/oToMessages/batchSend"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&server)
            .await;

        let client = DingTalkClient::new(test_config(&server.uri())).unwrap();
        let err = client
            .post_json(
                "/v1.0/robot/oToMessages/batchSend",
                json!({"robotCode": "test-app"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DingTalkError::Api { code: 400, .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn upload_media_with_valid_base64() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "tok-1",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/media/upload"))
            .and(query_param("access_token", "tok-1"))
            .and(query_param("type", "image"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "media_id": "MEDIA-1"
            })))
            .mount(&server)
            .await;

        let client = DingTalkClient::new(test_config(&server.uri())).unwrap();
        let result = client
            .upload_media("image", "test.png", "image/png", &BASE64.encode(b"png"))
            .await
            .unwrap();
        assert_eq!(result["media_id"], "MEDIA-1");
    }

    #[fcp_async_core::runtime::test]
    async fn upload_media_returns_media_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "tok-1",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/media/upload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 400_001,
                "errmsg": "invalid media"
            })))
            .mount(&server)
            .await;

        let client = DingTalkClient::new(test_config(&server.uri())).unwrap();
        let err = client
            .upload_media("image", "test.png", "image/png", &BASE64.encode(b"png"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            DingTalkError::Media {
                errcode: 400_001,
                ..
            }
        ));
    }

    #[test]
    fn ensure_media_success_passes_on_zero() {
        let body = json!({"errcode": 0, "errmsg": "ok", "media_id": "M1"});
        assert!(ensure_media_success(body).is_ok());
    }

    #[test]
    fn ensure_media_success_fails_on_nonzero() {
        let body = json!({"errcode": 12345, "errmsg": "bad"});
        let err = ensure_media_success(body).unwrap_err();
        assert!(matches!(err, DingTalkError::Media { errcode: 12345, .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn access_token_maps_unauthorized_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad credentials"))
            .mount(&server)
            .await;

        let client = DingTalkClient::new(test_config(&server.uri())).unwrap();
        let err = client.access_token().await.unwrap_err();
        assert!(matches!(
            err,
            DingTalkError::Unauthorized(ref message) if message.contains("bad credentials")
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn post_json_maps_retry_after_header_to_rate_limit() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "tok-1",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1.0/robot/oToMessages/batchSend"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "2")
                    .set_body_string("slow down"),
            )
            .mount(&server)
            .await;

        let client = DingTalkClient::new(test_config(&server.uri())).unwrap();
        let err = client
            .post_json(
                "/v1.0/robot/oToMessages/batchSend",
                json!({"robotCode": "test-app"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            DingTalkError::RateLimited {
                retry_after_ms: 2_000
            }
        ));
    }

    #[test]
    fn retry_after_header_parser_clamps_large_value() {
        assert_eq!(
            parse_retry_after_header_value(&u64::MAX.to_string()),
            Some(MAX_RETRY_AFTER_MS)
        );
    }

    #[test]
    fn retry_after_header_parser_rejects_invalid_values() {
        assert_eq!(parse_retry_after_header_value("-1"), None);
        assert_eq!(parse_retry_after_header_value("1.5"), None);
        assert_eq!(parse_retry_after_header_value("not-a-number"), None);
    }

    #[test]
    fn default_mime_types() {
        assert_eq!(default_mime_type("image"), "image/png");
        assert_eq!(default_mime_type("voice"), "audio/amr");
        assert_eq!(default_mime_type("video"), "video/mp4");
        assert_eq!(default_mime_type("file"), "application/octet-stream");
        assert_eq!(default_mime_type("unknown"), "application/octet-stream");
    }

    // ── Normalization tests ──────────────────────────────────────

    #[test]
    fn normalize_conversation_type_private() {
        assert_eq!(normalize_conversation_type(Some("1")), "private");
    }

    #[test]
    fn normalize_conversation_type_group() {
        assert_eq!(normalize_conversation_type(Some("2")), "group");
    }

    #[test]
    fn normalize_conversation_type_unknown() {
        assert_eq!(normalize_conversation_type(None), "unknown");
        assert_eq!(normalize_conversation_type(Some("99")), "unknown");
        assert_eq!(normalize_conversation_type(Some(" 2 ")), "group");
    }

    #[test]
    fn normalize_callback_full_group_event() {
        let raw = json!({
            "msgType": "text",
            "text": { "content": "hello bot" },
            "senderId": "user-001",
            "senderNick": "Alice",
            "conversationId": "conv-123",
            "conversationType": "2",
            "conversationTitle": "Dev Team",
            "atUsers": [
                { "dingtalkId": "bot-999", "staffId": "staff-bot" }
            ],
            "chatbotUserId": "bot-999",
            "createAt": 1_700_000_000_000_i64,
            "msgId": "msg-abc"
        });
        let normalized = normalize_callback_event(&raw).unwrap();
        assert_eq!(normalized.event_type, "message");
        assert_eq!(normalized.message_id.as_deref(), Some("msg-abc"));
        assert_eq!(normalized.conversation_id.as_deref(), Some("conv-123"));
        assert_eq!(normalized.conversation_type, "group");
        assert_eq!(normalized.sender_id.as_deref(), Some("user-001"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Alice"));
        assert_eq!(normalized.text.as_deref(), Some("hello bot"));
        assert_eq!(normalized.timestamp_ms, Some(1_700_000_000_000));
        assert!(normalized.at_bot);
    }

    #[test]
    fn normalize_callback_private_event() {
        let raw = json!({
            "msgType": "text",
            "text": { "content": "dm from user" },
            "senderId": "user-002",
            "senderNick": "Bob",
            "conversationId": "priv-1",
            "conversationType": "1",
            "chatbotUserId": "bot-999",
            "msgId": "msg-priv-1"
        });
        let normalized = normalize_callback_event(&raw).unwrap();
        assert_eq!(normalized.conversation_type, "private");
        assert!(!normalized.at_bot);
        assert_eq!(normalized.text.as_deref(), Some("dm from user"));
    }

    #[test]
    fn normalize_callback_minimal_event() {
        let raw = json!({});
        let normalized = normalize_callback_event(&raw).unwrap();
        assert_eq!(normalized.event_type, "message");
        assert!(normalized.message_id.is_none());
        assert!(normalized.conversation_id.is_none());
        assert_eq!(normalized.conversation_type, "unknown");
        assert!(normalized.sender_id.is_none());
        assert!(normalized.text.is_none());
        assert!(!normalized.at_bot);
    }

    #[test]
    fn normalize_callback_no_text_content() {
        let raw = json!({
            "msgType": "picture",
            "conversationType": "2",
            "conversationId": "conv-pic"
        });
        let normalized = normalize_callback_event(&raw).unwrap();
        assert!(normalized.text.is_none());
        assert_eq!(normalized.conversation_type, "group");
    }

    #[test]
    fn normalize_callback_text_content_null() {
        let raw = json!({
            "msgType": "text",
            "text": { "content": null },
            "conversationType": "1"
        });
        let normalized = normalize_callback_event(&raw).unwrap();
        assert!(normalized.text.is_none());
    }

    #[test]
    fn normalize_callback_preserves_raw() {
        let raw = json!({
            "msgType": "text",
            "text": { "content": "test" },
            "customField": "extra-data"
        });
        let normalized = normalize_callback_event(&raw).unwrap();
        assert_eq!(normalized.raw["customField"], "extra-data");
    }

    #[test]
    fn normalize_callback_rejects_non_object_payload() {
        let err = normalize_callback_event(&json!("not an event")).unwrap_err();
        assert!(matches!(err, DingTalkError::InvalidInput(_)));
        assert!(err.to_string().contains("invalid callback event payload"));
    }

    #[test]
    fn normalize_callback_rejects_malformed_field_shapes() {
        for raw in [
            json!({ "text": "plain string is not a text object" }),
            json!({ "atUsers": "not an array" }),
            json!({ "createAt": "not an integer timestamp" }),
        ] {
            let err = normalize_callback_event(&raw).unwrap_err();
            assert!(matches!(err, DingTalkError::InvalidInput(_)));
            assert!(err.to_string().contains("invalid callback event payload"));
        }
    }

    // ── detect_at_bot tests ──────────────────────────────────────

    #[test]
    fn detect_at_bot_matches_chatbot_user_id() {
        use crate::types::{AtUser, DingTalkCallbackEvent};
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: None,
            conversation_type: None,
            conversation_title: None,
            at_users: Some(vec![AtUser {
                dingtalk_id: Some("bot-1".into()),
                staff_id: None,
            }]),
            chatbot_user_id: Some("bot-1".into()),
            create_at: None,
            msg_id: None,
        };
        assert!(detect_at_bot(&event));
    }

    #[test]
    fn detect_at_bot_no_match() {
        use crate::types::{AtUser, DingTalkCallbackEvent};
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: None,
            conversation_type: None,
            conversation_title: None,
            at_users: Some(vec![AtUser {
                dingtalk_id: Some("other-user".into()),
                staff_id: None,
            }]),
            chatbot_user_id: Some("bot-1".into()),
            create_at: None,
            msg_id: None,
        };
        assert!(!detect_at_bot(&event));
    }

    #[test]
    fn detect_at_bot_rejects_empty_chatbot_id_match() {
        use crate::types::{AtUser, DingTalkCallbackEvent};
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: None,
            conversation_type: None,
            conversation_title: None,
            at_users: Some(vec![AtUser {
                dingtalk_id: Some(String::new()),
                staff_id: None,
            }]),
            chatbot_user_id: Some("   ".into()),
            create_at: None,
            msg_id: None,
        };
        assert!(!detect_at_bot(&event));
    }

    #[test]
    fn detect_at_bot_empty_at_users() {
        use crate::types::DingTalkCallbackEvent;
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: None,
            conversation_type: None,
            conversation_title: None,
            at_users: Some(vec![]),
            chatbot_user_id: Some("bot-1".into()),
            create_at: None,
            msg_id: None,
        };
        assert!(!detect_at_bot(&event));
    }

    #[test]
    fn detect_at_bot_no_chatbot_id_with_mentions() {
        use crate::types::{AtUser, DingTalkCallbackEvent};
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: None,
            conversation_type: None,
            conversation_title: None,
            at_users: Some(vec![AtUser {
                dingtalk_id: Some("someone".into()),
                staff_id: None,
            }]),
            chatbot_user_id: None,
            create_at: None,
            msg_id: None,
        };
        assert!(!detect_at_bot(&event));
    }

    #[test]
    fn detect_at_bot_no_at_users() {
        use crate::types::DingTalkCallbackEvent;
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: None,
            conversation_type: None,
            conversation_title: None,
            at_users: None,
            chatbot_user_id: Some("bot-1".into()),
            create_at: None,
            msg_id: None,
        };
        assert!(!detect_at_bot(&event));
    }

    // ── extract_conversation_identity tests ──────────────────────

    #[test]
    fn extract_conversation_identity_group() {
        use crate::types::DingTalkCallbackEvent;
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: Some("conv-42".into()),
            conversation_type: Some("2".into()),
            conversation_title: Some("Team Chat".into()),
            at_users: None,
            chatbot_user_id: None,
            create_at: None,
            msg_id: None,
        };
        let ci = extract_conversation_identity(&event).unwrap();
        assert_eq!(ci.id, "conv-42");
        assert_eq!(ci.conversation_type, "group");
        assert_eq!(ci.title.as_deref(), Some("Team Chat"));
    }

    #[test]
    fn extract_conversation_identity_private() {
        use crate::types::DingTalkCallbackEvent;
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: Some("priv-7".into()),
            conversation_type: Some("1".into()),
            conversation_title: None,
            at_users: None,
            chatbot_user_id: None,
            create_at: None,
            msg_id: None,
        };
        let ci = extract_conversation_identity(&event).unwrap();
        assert_eq!(ci.id, "priv-7");
        assert_eq!(ci.conversation_type, "private");
        assert!(ci.title.is_none());
    }

    #[test]
    fn extract_conversation_identity_none_when_no_id() {
        use crate::types::DingTalkCallbackEvent;
        let event = DingTalkCallbackEvent {
            msg_type: None,
            text: None,
            sender_id: None,
            sender_nick: None,
            sender_staff_id: None,
            conversation_id: None,
            conversation_type: Some("2".into()),
            conversation_title: None,
            at_users: None,
            chatbot_user_id: None,
            create_at: None,
            msg_id: None,
        };
        assert!(extract_conversation_identity(&event).is_none());
    }
}
