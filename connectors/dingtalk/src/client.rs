//! `DingTalk` HTTP client with token caching and `ConnectorRuntime` integration.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fcp_async_core::sync::Mutex;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Url, header::HeaderMap, multipart};
use serde_json::{Value, json};

use crate::error::{DingTalkError, DingTalkResult};
use crate::types::{AccessTokenResponse, DingTalkConfig, TOKEN_REFRESH_SAFETY_MARGIN_SECS};

#[derive(Debug, Clone)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
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

        let token: AccessTokenResponse = serde_json::from_value(body.clone()).map_err(|e| {
            DingTalkError::Token(format!("failed to parse access token payload: {e}"))
        })?;

        if token.access_token.trim().is_empty() {
            return Err(DingTalkError::Token(format!(
                "access token response missing access_token: {body}"
            )));
        }

        let ttl = token
            .expire_in
            .saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS)
            .max(1);
        *self.token_cache.lock().await = Some(CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        });

        Ok(token.access_token)
    }

    /// Send a JSON `POST` request against the `DingTalk` API.
    ///
    /// # Errors
    ///
    /// Returns an error if token acquisition fails, the request cannot be sent,
    /// or `DingTalk` returns a non-success response.
    pub async fn post_json(&self, path: &str, body: Value) -> DingTalkResult<Value> {
        let token = self.access_token().await?;
        let url = self.api_url(path)?;
        let response = self
            .client
            .post(url)
            .header("x-acs-dingtalk-access-token", &token)
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
        let token = self.access_token().await?;
        let bytes = BASE64.decode(content_base64.trim()).map_err(|e| {
            DingTalkError::InvalidInput(format!("content_base64 must be valid base64: {e}"))
        })?;

        let mut url = self.media_url("/media/upload")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &token);
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

fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000))
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
        config.client_secret = String::new();
        assert!(DingTalkClient::new(config).is_err());
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut config = localhost_config();
        config.request_timeout_ms = 0;
        assert!(DingTalkClient::new(config).is_err());
    }

    #[test]
    fn rejects_disallowed_host() {
        let config = test_config("https://evil.example.com");
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
        match err {
            DingTalkError::Unauthorized(message) => {
                assert!(message.contains("bad credentials"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
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
    fn default_mime_types() {
        assert_eq!(default_mime_type("image"), "image/png");
        assert_eq!(default_mime_type("voice"), "audio/amr");
        assert_eq!(default_mime_type("video"), "video/mp4");
        assert_eq!(default_mime_type("file"), "application/octet-stream");
        assert_eq!(default_mime_type("unknown"), "application/octet-stream");
    }
}
