//! `QQ` HTTP client with token caching and `ConnectorRuntime` integration.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fcp_async_core::sync::Mutex;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Url, header::HeaderMap};
use serde_json::{Value, json};

use crate::error::{QqError, QqResult};
use crate::types::{AccessTokenResponse, QqConfig, TOKEN_REFRESH_SAFETY_MARGIN_SECS};

#[derive(Debug, Clone)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
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
            return Err(QqError::Token(format!(
                "access token response missing access_token: {body}"
            )));
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
    let host = url
        .host_str()
        .ok_or_else(|| QqError::Config(format!("URL `{raw}` must include a host")))?;
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
    if value.trim().is_empty() {
        return Err(QqError::InvalidInput(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(QqError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
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
}
