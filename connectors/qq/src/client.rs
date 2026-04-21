//! `QQ` HTTP client with token caching and `ConnectorRuntime` integration.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fcp_async_core::sync::Mutex;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Url, header::HeaderMap};
use serde_json::{Value, json};

use crate::error::{QqError, QqResult};
use crate::types::{
    AccessTokenResponse, NormalizedQqEvent, QqConfig, QqGatewayEvent, QqMessageEvent, QqRouting,
    TOKEN_REFRESH_SAFETY_MARGIN_SECS,
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

pub struct QqClient {
    config: QqConfig,
    client: reqwest::Client,
    token_cache: Arc<Mutex<Option<CachedAccessToken>>>,
    runtime: ConnectorRuntime,
}

impl std::fmt::Debug for QqClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QqClient")
            .field("config", &self.config)
            .field("client", &"reqwest::Client")
            .field("token_cache", &"token cache")
            .field("runtime", &"ConnectorRuntime")
            .finish_non_exhaustive()
    }
}

impl QqClient {
    /// Build a configured `QQ` HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid or the underlying HTTP client
    /// cannot be initialized.
    pub fn new(config: QqConfig) -> QqResult<Self> {
        let config = config.normalized();
        validate_host(
            &config.base_url,
            &["api.sgroup.qq.com", "localhost", "127.0.0.1"],
        )?;
        validate_host(
            &config.token_base_url,
            &["bots.qq.com", "localhost", "127.0.0.1"],
        )?;
        if config.app_id.trim().is_empty() {
            return Err(QqError::Config("app_id must not be empty".into()));
        }
        if config.client_secret.trim().is_empty() {
            return Err(QqError::Config("client_secret must not be empty".into()));
        }
        if config.request_timeout_ms == 0 {
            return Err(QqError::Config(
                "request_timeout_ms must be greater than zero".into(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(QqError::Http)?;

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
    pub const fn config(&self) -> &QqConfig {
        &self.config
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn api_url(&self, path: &str) -> QqResult<Url> {
        Url::parse(self.config.base_url.trim())
            .map(|mut url| {
                url.set_path(path);
                url
            })
            .map_err(|e| QqError::Config(format!("invalid base_url: {e}")))
    }

    fn token_url(&self, path: &str) -> QqResult<Url> {
        Url::parse(self.config.token_base_url.trim())
            .map(|mut url| {
                url.set_path(path);
                url
            })
            .map_err(|e| QqError::Config(format!("invalid token_base_url: {e}")))
    }

    /// Fetch or reuse a cached `QQ` bot access token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token endpoint rejects the credentials or the
    /// response payload is malformed.
    pub async fn access_token(&self) -> QqResult<String> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(cached) = cache.as_ref() {
                if Instant::now() < cached.expires_at {
                    return Ok(cached.token.clone());
                }
            }
        }

        let url = self.token_url("/app/getAppAccessToken")?;
        let response = self
            .client
            .post(url)
            .json(&json!({
                "appId": self.config.app_id,
                "clientSecret": self.config.client_secret
            }))
            .send()
            .await
            .map_err(QqError::Http)?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();
            return Err(http_status_error(status, &headers, body));
        }

        let body: Value = response
            .json()
            .await
            .map_err(|e| QqError::Token(format!("failed to decode access token response: {e}")))?;

        let token: AccessTokenResponse = serde_json::from_value(body.clone())
            .map_err(|e| QqError::Token(format!("failed to parse access token payload: {e}")))?;

        if token.access_token.trim().is_empty() {
            return Err(QqError::Token(
                "access token response missing or empty access_token field".to_string(),
            ));
        }

        let ttl = token
            .expires_in
            .saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS)
            .max(1);
        *self.token_cache.lock().await = Some(CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        });

        Ok(token.access_token)
    }

    /// Send an authenticated API request to `QQ`.
    ///
    /// # Errors
    ///
    /// Returns an error if token acquisition fails, the HTTP request cannot be
    /// sent, or the API returns a non-success response.
    pub async fn api_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> QqResult<Value> {
        let token = self.access_token().await?;
        let url = self.api_url(path)?;
        let request = self
            .client
            .request(method, url)
            .header("Authorization", format!("QQBot {token}"));
        let request = if let Some(body) = body.as_ref() {
            request.json(body)
        } else {
            request
        };
        let response = request.send().await.map_err(QqError::Http)?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();
            return Err(http_status_error(
                status,
                &headers,
                format!("QQ API request failed [{status}]: {body}"),
            ));
        }

        response.json().await.map_err(QqError::Http)
    }
}

fn validate_host(raw: &str, allowed_hosts: &[&str]) -> QqResult<()> {
    let url =
        Url::parse(raw.trim()).map_err(|e| QqError::Config(format!("invalid URL `{raw}`: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(QqError::Config(format!(
            "URL `{raw}` must not include userinfo"
        )));
    }
    if url.query().is_some() {
        return Err(QqError::Config(format!(
            "URL `{raw}` must not include a query string"
        )));
    }
    if url.fragment().is_some() {
        return Err(QqError::Config(format!(
            "URL `{raw}` must not include a fragment"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| QqError::Config(format!("URL `{raw}` must include a host")))?;
    let is_local = matches!(host, "localhost" | "127.0.0.1");
    if !is_local && url.scheme() != "https" {
        return Err(QqError::Config(format!(
            "URL `{raw}` must use https for non-local hosts"
        )));
    }
    if !allowed_hosts.contains(&host) {
        return Err(QqError::Config(format!("URL host `{host}` is not allowed")));
    }
    Ok(())
}

/// Build a channel message body (content + optional `msg_id`).
#[must_use]
pub fn channel_message_body(content: &str, msg_id: Option<&str>) -> Value {
    let mut body = json!({
        "content": content,
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = json!(msg_id);
    }
    body
}

/// Build a direct/group message body (content + `msg_type` + `msg_seq` +
/// optional `msg_id`).
#[must_use]
pub fn direct_message_body(content: &str, msg_id: Option<&str>) -> Value {
    let mut body = json!({
        "content": content,
        "msg_type": 0,
        "msg_seq": 1,
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = json!(msg_id);
    }
    body
}

/// Validate and sanitize a path segment to prevent URL path injection.
///
/// # Errors
///
/// Returns an error if `value` is empty or contains path traversal characters.
pub fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> QqResult<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(QqError::InvalidInput(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
    {
        return Err(QqError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Normalize a raw gateway event into a structured `NormalizedQqEvent`.
///
/// Detects routing from the event type, extracts quote context from
/// `message_reference`, and detects whether attachments are present.
///
/// # Errors
///
/// Returns an error if the event type is missing or is not a recognized
/// message event, or if the event data cannot be parsed.
pub fn normalize_message_event(event: &QqGatewayEvent) -> QqResult<NormalizedQqEvent> {
    let event_type = event
        .t
        .as_deref()
        .ok_or_else(|| QqError::InvalidInput("gateway event missing event type (t)".into()))?;

    let routing = QqRouting::from_event_type(event_type).ok_or_else(|| {
        QqError::InvalidInput(format!(
            "event type `{event_type}` is not a normalizable message event"
        ))
    })?;

    let raw_data = event.d.clone().unwrap_or_else(|| serde_json::json!({}));

    // Treat null data as empty object for deserialization
    let effective_data = if raw_data.is_null() {
        serde_json::json!({})
    } else {
        raw_data.clone()
    };

    let msg: QqMessageEvent = serde_json::from_value(effective_data)
        .map_err(|e| QqError::InvalidInput(format!("failed to parse message event data: {e}")))?;

    let reply_to = msg
        .message_reference
        .as_ref()
        .and_then(|r| r.message_id.clone());
    let is_reply = reply_to.is_some();

    let has_attachments = msg.attachments.as_ref().is_some_and(|a| !a.is_empty());

    // Sender ID: for group messages use group_member_openid, for channel/c2c use author.id
    let sender_id = match routing {
        QqRouting::Group => msg
            .group_member_openid
            .clone()
            .or_else(|| msg.author.as_ref().and_then(|a| a.id.clone())),
        _ => msg.author.as_ref().and_then(|a| a.id.clone()),
    };

    let sender_name = msg.author.as_ref().and_then(|a| a.username.clone());

    // Group ID: for group messages use group_openid
    let group_id = match routing {
        QqRouting::Group => msg.group_openid.clone(),
        _ => None,
    };

    Ok(NormalizedQqEvent {
        event_type: event_type.to_string(),
        message_id: msg.id,
        channel_id: msg.channel_id,
        guild_id: msg.guild_id,
        group_id,
        sender_id,
        sender_name,
        text: msg.content,
        timestamp: msg.timestamp,
        is_reply,
        reply_to,
        has_attachments,
        routing,
        raw: raw_data,
    })
}

fn http_status_error(status: u16, headers: &HeaderMap, body: String) -> QqError {
    let message = if body.trim().is_empty() {
        format!("QQ HTTP request failed with status {status}")
    } else {
        body
    };
    match status {
        401 | 403 => QqError::Unauthorized(message),
        429 => QqError::RateLimited {
            retry_after_ms: retry_after_ms(headers).unwrap_or(1_000),
        },
        _ => QqError::Api {
            code: u32::from(status),
            message,
        },
    }
}

fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DEFAULT_TIMEOUT_MS;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, header, method, path},
    };

    fn localhost_config() -> QqConfig {
        QqConfig {
            base_url: "http://localhost:9999".into(),
            token_base_url: "http://localhost:9999".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
        }
    }

    fn test_config(api_url: &str, token_url: &str) -> QqConfig {
        QqConfig {
            base_url: api_url.to_string(),
            token_base_url: token_url.to_string(),
            app_id: "app-1".into(),
            client_secret: "secret".into(),
            request_timeout_ms: 30_000,
        }
    }

    #[test]
    fn rejects_empty_app_id() {
        let mut config = localhost_config();
        config.app_id = String::new();
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_empty_client_secret() {
        let mut config = localhost_config();
        config.client_secret = String::new();
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut config = localhost_config();
        config.request_timeout_ms = 0;
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn trims_config_fields() {
        let config = QqConfig {
            base_url: " http://localhost:9999 ".into(),
            token_base_url: " http://localhost:9999 ".into(),
            app_id: " test-app ".into(),
            client_secret: " test-secret ".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        };
        let client = QqClient::new(config).unwrap();
        assert_eq!(client.config().base_url, "http://localhost:9999");
        assert_eq!(client.config().token_base_url, "http://localhost:9999");
        assert_eq!(client.config().app_id, "test-app");
        assert_eq!(client.config().client_secret, "test-secret");
    }

    #[test]
    fn rejects_disallowed_host() {
        let config = QqConfig {
            base_url: "https://evil.example.com".into(),
            token_base_url: "http://localhost:9999".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
        };
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_disallowed_token_host() {
        let config = QqConfig {
            base_url: "http://localhost:9999".into(),
            token_base_url: "https://evil.example.com".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
        };
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_insecure_public_hosts() {
        let config = QqConfig {
            base_url: "http://api.sgroup.qq.com".into(),
            token_base_url: "https://bots.qq.com".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
        };
        assert!(QqClient::new(config).is_err());

        let config = QqConfig {
            base_url: "https://api.sgroup.qq.com".into(),
            token_base_url: "http://bots.qq.com".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
        };
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_base_url_with_query_fragment_or_userinfo() {
        let query = test_config(
            "https://api.sgroup.qq.com/api?trace=1",
            "https://bots.qq.com/app",
        );
        let err = QqClient::new(query).unwrap_err().to_string();
        assert!(err.contains("must not include a query string"));

        let fragment = test_config(
            "https://api.sgroup.qq.com/api#fragment",
            "https://bots.qq.com/app",
        );
        let err = QqClient::new(fragment).unwrap_err().to_string();
        assert!(err.contains("must not include a fragment"));

        let userinfo = test_config(
            "https://bot:secret@api.sgroup.qq.com/api",
            "https://bots.qq.com/app",
        );
        let err = QqClient::new(userinfo).unwrap_err().to_string();
        assert!(err.contains("must not include userinfo"));
    }

    #[test]
    fn rejects_token_base_url_with_query_fragment_or_userinfo() {
        let query = test_config(
            "https://api.sgroup.qq.com/api",
            "https://bots.qq.com/oauth2/token?trace=1",
        );
        let err = QqClient::new(query).unwrap_err().to_string();
        assert!(err.contains("must not include a query string"));

        let fragment = test_config(
            "https://api.sgroup.qq.com/api",
            "https://bots.qq.com/oauth2/token#fragment",
        );
        let err = QqClient::new(fragment).unwrap_err().to_string();
        assert!(err.contains("must not include a fragment"));

        let userinfo = test_config(
            "https://api.sgroup.qq.com/api",
            "https://bot:secret@bots.qq.com/oauth2/token",
        );
        let err = QqClient::new(userinfo).unwrap_err().to_string();
        assert!(err.contains("must not include userinfo"));
    }

    #[test]
    fn debug_redacts_secret() {
        let config = localhost_config();
        let client = QqClient::new(config).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("test-secret"));
    }

    #[test]
    fn channel_message_body_without_msg_id() {
        let body = channel_message_body("hello", None);
        assert_eq!(body["content"], "hello");
        assert!(body.get("msg_id").is_none());
    }

    #[test]
    fn channel_message_body_with_msg_id() {
        let body = channel_message_body("hello", Some("msg-1"));
        assert_eq!(body["content"], "hello");
        assert_eq!(body["msg_id"], "msg-1");
    }

    #[test]
    fn direct_message_body_without_msg_id() {
        let body = direct_message_body("hello", None);
        assert_eq!(body["content"], "hello");
        assert_eq!(body["msg_type"], 0);
        assert_eq!(body["msg_seq"], 1);
        assert!(body.get("msg_id").is_none());
    }

    #[test]
    fn direct_message_body_with_msg_id() {
        let body = direct_message_body("hello", Some("msg-2"));
        assert_eq!(body["msg_id"], "msg-2");
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "id").is_err());
        assert!(sanitize_path_segment("foo/bar", "id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "id").is_err());
        assert!(sanitize_path_segment("%2E%2E", "id").is_err());
        assert!(sanitize_path_segment("", "id").is_err());
        assert!(sanitize_path_segment("  ", "id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(sanitize_path_segment("abc123", "id").unwrap(), "abc123");
        assert_eq!(
            sanitize_path_segment("channel-id-42", "id").unwrap(),
            "channel-id-42"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_channel_posts_expected_payload() {
        let api_server = MockServer::start().await;
        let token_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/app/getAppAccessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&token_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/channels/channel-1/messages"))
            .and(header("authorization", "QQBot token-123"))
            .and(body_partial_json(json!({
                "content": "hello qq"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg-1",
                "timestamp": "123456"
            })))
            .mount(&api_server)
            .await;

        let client = QqClient::new(test_config(&api_server.uri(), &token_server.uri())).unwrap();
        let output = client
            .api_request(
                reqwest::Method::POST,
                "/channels/channel-1/messages",
                Some(channel_message_body("hello qq", None)),
            )
            .await
            .unwrap();

        assert_eq!(output["id"], "msg-1");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_request_uses_bearer_token() {
        let api_server = MockServer::start().await;
        let token_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/app/getAppAccessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&token_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/gateway"))
            .and(header("authorization", "QQBot token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "url": "wss://gateway.qq.example/ws"
            })))
            .mount(&api_server)
            .await;

        let client = QqClient::new(test_config(&api_server.uri(), &token_server.uri())).unwrap();
        let output = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap();

        assert_eq!(output["url"], "wss://gateway.qq.example/ws");
    }

    #[fcp_async_core::runtime::test]
    async fn api_request_returns_error_on_failure() {
        let api_server = MockServer::start().await;
        let token_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/app/getAppAccessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&token_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/gateway"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&api_server)
            .await;

        let client = QqClient::new(test_config(&api_server.uri(), &token_server.uri())).unwrap();
        let err = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap_err();

        assert!(matches!(err, QqError::Api { code: 500, .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn access_token_maps_unauthorized_status() {
        let token_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/getAppAccessToken"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid bot secret"))
            .mount(&token_server)
            .await;

        let client =
            QqClient::new(test_config("http://localhost:9999", &token_server.uri())).unwrap();
        let err = client.access_token().await.unwrap_err();
        match err {
            QqError::Unauthorized(message) => {
                assert!(message.contains("invalid bot secret"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn api_request_maps_retry_after_header_to_rate_limit() {
        let api_server = MockServer::start().await;
        let token_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/app/getAppAccessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&token_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/gateway"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "3")
                    .set_body_string("rate limited"),
            )
            .mount(&api_server)
            .await;

        let client = QqClient::new(test_config(&api_server.uri(), &token_server.uri())).unwrap();
        let err = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            QqError::RateLimited {
                retry_after_ms: 3_000
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn token_caching_reuses_valid_token() {
        let api_server = MockServer::start().await;
        let token_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/app/getAppAccessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "cached-token",
                "expires_in": 7200
            })))
            .expect(1) // should only be called once
            .mount(&token_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/gateway"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "url": "wss://gateway.qq.example/ws"
            })))
            .mount(&api_server)
            .await;

        let client = QqClient::new(test_config(&api_server.uri(), &token_server.uri())).unwrap();

        // First call fetches token
        let _ = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap();

        // Second call should reuse cached token
        let _ = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap();
    }

    // ─── Event normalization tests ──────────────────────────────

    #[test]
    fn normalize_channel_message() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(1),
            t: Some("AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-1",
                "channel_id": "ch-1",
                "guild_id": "guild-1",
                "content": "hello world",
                "timestamp": "2026-03-23T12:00:00Z",
                "author": {"id": "user-1", "username": "Alice", "bot": false}
            })),
            id: Some("evt-1".into()),
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.event_type, "AT_MESSAGE_CREATE");
        assert_eq!(normalized.routing, QqRouting::Channel);
        assert_eq!(normalized.message_id.as_deref(), Some("msg-1"));
        assert_eq!(normalized.channel_id.as_deref(), Some("ch-1"));
        assert_eq!(normalized.guild_id.as_deref(), Some("guild-1"));
        assert!(normalized.group_id.is_none());
        assert_eq!(normalized.sender_id.as_deref(), Some("user-1"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Alice"));
        assert_eq!(normalized.text.as_deref(), Some("hello world"));
        assert!(!normalized.is_reply);
        assert!(normalized.reply_to.is_none());
        assert!(!normalized.has_attachments);
    }

    #[test]
    fn normalize_group_message() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(2),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-2",
                "content": "group hello",
                "group_openid": "group-1",
                "group_member_openid": "member-1",
                "author": {"id": "user-2", "username": "Bob"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::Group);
        assert_eq!(normalized.group_id.as_deref(), Some("group-1"));
        assert_eq!(normalized.sender_id.as_deref(), Some("member-1"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Bob"));
        assert!(normalized.channel_id.is_none());
        assert!(normalized.guild_id.is_none());
    }

    #[test]
    fn normalize_c2c_message() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(3),
            t: Some("C2C_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-3",
                "content": "private hello",
                "author": {"id": "user-3", "username": "Carol"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::C2c);
        assert_eq!(normalized.sender_id.as_deref(), Some("user-3"));
        assert!(normalized.group_id.is_none());
        assert!(normalized.channel_id.is_none());
    }

    #[test]
    fn normalize_message_with_reply() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(4),
            t: Some("MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-4",
                "channel_id": "ch-1",
                "content": "replying",
                "message_reference": {"message_id": "msg-original"},
                "author": {"id": "user-4"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert!(normalized.is_reply);
        assert_eq!(normalized.reply_to.as_deref(), Some("msg-original"));
    }

    #[test]
    fn normalize_message_with_attachments() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(5),
            t: Some("AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-5",
                "channel_id": "ch-1",
                "content": "see attached",
                "attachments": [
                    {"url": "https://example.com/a.png", "filename": "a.png", "content_type": "image/png", "size": 4096},
                    {"url": "https://example.com/b.pdf", "filename": "b.pdf", "content_type": "application/pdf", "size": 8192}
                ],
                "author": {"id": "user-5"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert!(normalized.has_attachments);
        assert!(!normalized.is_reply);
    }

    #[test]
    fn normalize_message_empty_attachments_not_flagged() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(6),
            t: Some("MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-6",
                "channel_id": "ch-1",
                "content": "no attachments",
                "attachments": [],
                "author": {"id": "user-6"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert!(!normalized.has_attachments);
    }

    #[test]
    fn normalize_rejects_missing_event_type() {
        let event = QqGatewayEvent {
            op: 1,
            s: None,
            t: None,
            d: None,
            id: None,
        };
        let err = normalize_message_event(&event).unwrap_err();
        assert!(matches!(err, QqError::InvalidInput(_)));
    }

    #[test]
    fn normalize_rejects_non_message_event_type() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(1),
            t: Some("GUILD_CREATE".into()),
            d: Some(json!({})),
            id: None,
        };
        let err = normalize_message_event(&event).unwrap_err();
        match &err {
            QqError::InvalidInput(msg) => {
                assert!(msg.contains("GUILD_CREATE"));
                assert!(msg.contains("not a normalizable"));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn normalize_handles_null_data() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(1),
            t: Some("AT_MESSAGE_CREATE".into()),
            d: None,
            id: None,
        };
        // null data deserializes to QqMessageEvent with all None fields
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::Channel);
        assert!(normalized.message_id.is_none());
        assert!(normalized.text.is_none());
        assert!(normalized.sender_id.is_none());
    }

    #[test]
    fn normalize_group_message_create_variant() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(10),
            t: Some("GROUP_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-10",
                "content": "group variant",
                "group_openid": "group-2",
                "group_member_openid": "member-2"
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::Group);
        assert_eq!(normalized.group_id.as_deref(), Some("group-2"));
        assert_eq!(normalized.sender_id.as_deref(), Some("member-2"));
    }

    #[test]
    fn normalize_group_falls_back_to_author_id() {
        // When group_member_openid is missing, fall back to author.id
        let event = QqGatewayEvent {
            op: 0,
            s: Some(11),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-11",
                "content": "fallback sender",
                "group_openid": "group-3",
                "author": {"id": "user-fallback", "username": "Fallback"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::Group);
        assert_eq!(normalized.sender_id.as_deref(), Some("user-fallback"));
    }

    #[test]
    fn normalize_raw_preserves_original_data() {
        let data = json!({
            "id": "msg-raw",
            "content": "raw test",
            "extra_field": "preserved"
        });
        let event = QqGatewayEvent {
            op: 0,
            s: Some(12),
            t: Some("MESSAGE_CREATE".into()),
            d: Some(data),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.raw["extra_field"], "preserved");
        assert_eq!(normalized.raw["id"], "msg-raw");
    }
}
