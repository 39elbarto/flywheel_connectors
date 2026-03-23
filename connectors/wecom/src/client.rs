//! HTTP client and token-cache runtime for the `WeCom` connector.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fcp_async_core::sync::Mutex;
use fcp_core::FcpError;
use reqwest::{Url, multipart};
use serde_json::Value;

use crate::error::{WeComError, WeComResult};
use crate::types::{
    AccessTokenResponse, TOKEN_REFRESH_SAFETY_MARGIN_SECS, WeComConfig, WeComDepartmentListRequest,
    WeComMediaUploadRequest, WeComMessageRequest, WeComStateModel, WeComUserLookupRequest,
};

#[derive(Debug, Clone)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct WeComClient {
    config: WeComConfig,
    client: reqwest::Client,
    token_cache: Arc<Mutex<Option<CachedAccessToken>>>,
}

impl WeComClient {
    pub fn new(config: WeComConfig) -> WeComResult<Self> {
        config.validate().map_err(map_config_error)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms()))
            .build()?;
        Ok(Self {
            config,
            client,
            token_cache: Arc::new(Mutex::new(None)),
        })
    }

    #[must_use]
    pub const fn config(&self) -> &WeComConfig {
        &self.config
    }

    pub async fn state_model(&self) -> WeComStateModel {
        let token_cached = {
            let cache = self.token_cache.lock().await;
            cache
                .as_ref()
                .is_some_and(|cached| Instant::now() < cached.expires_at)
        };
        self.config.state_model(token_cached)
    }

    pub async fn access_token(&self) -> WeComResult<String> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(cached) = cache.as_ref()
                && Instant::now() < cached.expires_at
            {
                return Ok(cached.token.clone());
            }
        }

        let mut url = self.url("/cgi-bin/gettoken")?;
        url.query_pairs_mut()
            .append_pair("corpid", self.config.corp_id())
            .append_pair("corpsecret", self.config.agent_secret());

        let response = self.client.get(url).send().await?;
        let body = ensure_wecom_success(response.json().await?)?;
        let token: AccessTokenResponse = serde_json::from_value(body).map_err(|error| {
            WeComError::Token(format!("failed to parse access token payload: {error}"))
        })?;
        if token.access_token.trim().is_empty() {
            return Err(WeComError::Token(
                "WeCom access token response omitted access_token".into(),
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

    pub async fn send_message(&self, request: &WeComMessageRequest) -> WeComResult<Value> {
        self.post_json(
            "/cgi-bin/message/send",
            request.to_body(self.config.agent_id()),
        )
        .await
    }

    pub async fn upload_media(&self, request: &WeComMediaUploadRequest) -> WeComResult<Value> {
        let token = self.access_token().await?;
        let bytes = request.decode_content().map_err(WeComError::InvalidInput)?;
        let mut url = self.url("/cgi-bin/media/upload")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &token);
            query.append_pair("type", request.media_type());
        }
        let part = multipart::Part::bytes(bytes)
            .file_name(request.file_name().to_string())
            .mime_str(request.mime_type())
            .map_err(|error| WeComError::InvalidInput(format!("invalid mime_type: {error}")))?;
        let response = self
            .client
            .post(url)
            .multipart(multipart::Form::new().part("media", part))
            .send()
            .await?;
        ensure_wecom_success(response.json().await?)
    }

    pub async fn get_user(&self, request: &WeComUserLookupRequest) -> WeComResult<Value> {
        self.get_json(
            "/cgi-bin/user/get",
            &[("userid", request.userid().to_string())],
        )
        .await
    }

    pub async fn list_departments(
        &self,
        request: &WeComDepartmentListRequest,
    ) -> WeComResult<Value> {
        let mut params = Vec::new();
        if let Some(id) = request.id() {
            params.push(("id", id.to_string()));
        }
        self.get_json("/cgi-bin/department/list", &params).await
    }

    async fn get_json(&self, path: &str, params: &[(&str, String)]) -> WeComResult<Value> {
        let token = self.access_token().await?;
        let mut url = self.url(path)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &token);
            for (key, value) in params {
                query.append_pair(key, value);
            }
        }
        let response = self.client.get(url).send().await?;
        ensure_wecom_success(response.json().await?)
    }

    async fn post_json(&self, path: &str, body: Value) -> WeComResult<Value> {
        let token = self.access_token().await?;
        let mut url = self.url(path)?;
        url.query_pairs_mut().append_pair("access_token", &token);
        let response = self.client.post(url).json(&body).send().await?;
        ensure_wecom_success(response.json().await?)
    }

    fn url(&self, path: &str) -> WeComResult<Url> {
        let mut url = Url::parse(self.config.base_url())
            .map_err(|error| WeComError::Config(format!("stored base_url is invalid: {error}")))?;
        url.set_path(path);
        Ok(url)
    }
}

fn ensure_wecom_success(body: Value) -> WeComResult<Value> {
    let errcode = body.get("errcode").and_then(Value::as_i64).unwrap_or(0);
    if errcode == 0 {
        Ok(body)
    } else {
        let errmsg = body
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("unknown WeCom error")
            .to_string();
        Err(WeComError::Api { errcode, errmsg })
    }
}

fn map_config_error(error: FcpError) -> WeComError {
    match error {
        FcpError::InvalidRequest { message, .. } => WeComError::Config(message),
        other => WeComError::Config(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path, query_param},
    };

    use super::*;
    use crate::types::{DEFAULT_TIMEOUT_MS, WeComMessageKind};

    #[fcp_async_core::runtime::test]
    async fn send_text_posts_expected_message_payload() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cgi-bin/gettoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/cgi-bin/message/send"))
            .and(query_param("access_token", "token-123"))
            .and(body_partial_json(json!({
                "touser": "zhangsan",
                "msgtype": "text",
                "agentid": 1_000_002_u64,
                "text": { "content": "hello from test" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "msgid": "mid-1"
            })))
            .mount(&server)
            .await;

        let client = WeComClient::new(
            WeComConfig::from_value(json!({
                "base_url": server.uri(),
                "corp_id": "corp",
                "agent_id": 1_000_002_u64,
                "agent_secret": "secret",
                "request_timeout_ms": DEFAULT_TIMEOUT_MS,
            }))
            .expect("config should parse"),
        )
        .expect("client should build");

        let request = WeComMessageRequest::from_value(
            &json!({
                "touser": "zhangsan",
                "content": "hello from test",
            }),
            WeComMessageKind::Text,
        )
        .expect("message request should parse");

        let output = client
            .send_message(&request)
            .await
            .expect("send text should succeed");

        assert_eq!(output["msgid"], "mid-1");
    }

    #[fcp_async_core::runtime::test]
    async fn upload_media_posts_multipart_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cgi-bin/gettoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/cgi-bin/media/upload"))
            .and(query_param("access_token", "token-123"))
            .and(query_param("type", "image"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "type": "image",
                "media_id": "MEDIA123"
            })))
            .mount(&server)
            .await;

        let client = WeComClient::new(
            WeComConfig::from_value(json!({
                "base_url": server.uri(),
                "corp_id": "corp",
                "agent_id": 1_000_002_u64,
                "agent_secret": "secret",
                "request_timeout_ms": DEFAULT_TIMEOUT_MS,
            }))
            .expect("config should parse"),
        )
        .expect("client should build");

        let request = WeComMediaUploadRequest::from_value(&json!({
            "media_type": "image",
            "file_name": "test.png",
            "mime_type": "image/png",
            "content_base64": BASE64.encode(b"png"),
        }))
        .expect("upload request should parse");

        let output = client
            .upload_media(&request)
            .await
            .expect("upload should succeed");

        assert_eq!(output["media_id"], "MEDIA123");
    }
}
