//! LINE Messaging API client.

use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop, classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::{Client, RequestBuilder};
use serde_json::json;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{LineError, LineResult};
use crate::types::{
    GroupMembersResponse, GroupSummary, Message, RichMenu, RichMenuCreateResponse,
    RichMenuListResponse, SentMessageResponse, UserProfile,
};

/// LINE API client with retry and runtime integration.
pub struct LineClient {
    client: Client,
    base_url: String,
    channel_access_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for LineClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineClient")
            .field("base_url", &self.base_url)
            .field("channel_access_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl LineClient {
    /// Create a new LINE client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        channel_access_token: &str,
        retry_config: HttpRetryConfig,
    ) -> LineResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(LineError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            channel_access_token: channel_access_token.to_string(),
            retry_config,
        })
    }

    fn authenticate(&self, request: RequestBuilder) -> RequestBuilder {
        if self.channel_access_token.is_empty() {
            request
        } else {
            request.bearer_auth(&self.channel_access_token)
        }
    }

    /// Sanitize a path segment to prevent path traversal.
    fn sanitize_path_segment(segment: &str) -> LineResult<&str> {
        if segment.trim().is_empty()
            || segment.contains('/')
            || segment.contains('\\')
            || segment.contains("..")
            || segment.contains('\0')
        {
            return Err(LineError::InvalidInput(
                "Invalid path segment: contains forbidden characters".to_string(),
            ));
        }
        Ok(segment)
    }

    /// Push a message to a user.
    pub async fn push_message(
        &self,
        runtime: &ConnectorRuntime,
        to: &str,
        messages: Vec<Message>,
    ) -> LineResult<SentMessageResponse> {
        let url = format!("{}/v2/bot/message/push", self.base_url);
        let body = json!({ "to": to, "messages": messages });
        self.post_message(runtime, &url, &body).await
    }

    /// Reply to a message using a reply token.
    pub async fn reply_message(
        &self,
        runtime: &ConnectorRuntime,
        reply_token: &str,
        messages: Vec<Message>,
    ) -> LineResult<SentMessageResponse> {
        let url = format!("{}/v2/bot/message/reply", self.base_url);
        let body = json!({ "replyToken": reply_token, "messages": messages });
        self.post_message(runtime, &url, &body).await
    }

    /// Multicast a message to multiple users.
    pub async fn multicast(
        &self,
        runtime: &ConnectorRuntime,
        to: &[String],
        messages: Vec<Message>,
    ) -> LineResult<SentMessageResponse> {
        let url = format!("{}/v2/bot/message/multicast", self.base_url);
        let body = json!({ "to": to, "messages": messages });
        self.post_message(runtime, &url, &body).await
    }

    /// Common POST for messaging endpoints with retry.
    async fn post_message(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> LineResult<SentMessageResponse> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let body_clone = body.clone();
        let client = self.client.clone();
        let token = self.channel_access_token.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "Sending LINE message");
                let request = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                }
                .json(&body);

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: LineError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: LineError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(LineError::Unauthorized(
                        "Invalid channel access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "LINE API request failed");
                    let decision = classify_http_status(status, None);
                    let err = LineError::Api {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                // LINE messaging endpoints return 200 with optional body
                let text = resp.text().await.unwrap_or_default();
                if text.is_empty() {
                    return AttemptOutcome::Success(SentMessageResponse::default());
                }
                match serde_json::from_str::<SentMessageResponse>(&text) {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(LineError::Json(e)),
                }
            }
        })
        .await
    }

    /// Get a user's profile.
    pub async fn get_profile(
        &self,
        runtime: &ConnectorRuntime,
        user_id: &str,
    ) -> LineResult<UserProfile> {
        let user_id = Self::sanitize_path_segment(user_id)?;
        let url = format!("{}/v2/bot/profile/{}", self.base_url, user_id);
        self.get_json(runtime, &url).await
    }

    /// Get a group's summary (profile).
    pub async fn get_group_summary(
        &self,
        runtime: &ConnectorRuntime,
        group_id: &str,
    ) -> LineResult<GroupSummary> {
        let group_id = Self::sanitize_path_segment(group_id)?;
        let url = format!("{}/v2/bot/group/{}/summary", self.base_url, group_id);
        self.get_json(runtime, &url).await
    }

    /// Get group member IDs.
    pub async fn get_group_members(
        &self,
        runtime: &ConnectorRuntime,
        group_id: &str,
        start: Option<&str>,
    ) -> LineResult<GroupMembersResponse> {
        let group_id = Self::sanitize_path_segment(group_id)?;
        let mut url = format!(
            "{}/v2/bot/group/{}/members/ids",
            self.base_url, group_id
        );
        if let Some(token) = start {
            url.push_str(&format!("?start={token}"));
        }
        self.get_json(runtime, &url).await
    }

    /// List rich menus.
    pub async fn list_rich_menus(
        &self,
        runtime: &ConnectorRuntime,
    ) -> LineResult<RichMenuListResponse> {
        let url = format!("{}/v2/bot/richmenu/list", self.base_url);
        self.get_json(runtime, &url).await
    }

    /// Create a rich menu.
    pub async fn create_rich_menu(
        &self,
        runtime: &ConnectorRuntime,
        menu: &RichMenu,
    ) -> LineResult<RichMenuCreateResponse> {
        let url = format!("{}/v2/bot/richmenu", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = serde_json::to_value(menu).map_err(LineError::Json)?;
        let client = self.client.clone();
        let token = self.channel_access_token.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, "Creating LINE rich menu");
                let request = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                }
                .json(&body);

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: LineError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 {
                    return AttemptOutcome::Terminal(LineError::Unauthorized(
                        "Invalid channel access token".into(),
                    ));
                }
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = LineError::Api {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<RichMenuCreateResponse>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(LineError::Http(e)),
                }
            }
        })
        .await
    }

    /// Delete a rich menu.
    pub async fn delete_rich_menu(
        &self,
        runtime: &ConnectorRuntime,
        rich_menu_id: &str,
    ) -> LineResult<()> {
        let rich_menu_id = Self::sanitize_path_segment(rich_menu_id)?;
        let url = format!("{}/v2/bot/richmenu/{}", self.base_url, rich_menu_id);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let client = self.client.clone();
        let token = self.channel_access_token.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, "Deleting LINE rich menu");
                let request = if token.is_empty() {
                    client.delete(&url)
                } else {
                    client.delete(&url).bearer_auth(&token)
                };

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: LineError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 {
                    return AttemptOutcome::Terminal(LineError::Unauthorized(
                        "Invalid channel access token".into(),
                    ));
                }
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = LineError::Api {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                AttemptOutcome::Success(())
            }
        })
        .await
    }

    /// Health check: verify the LINE API is reachable.
    pub async fn health_check(&self) -> LineResult<()> {
        let url = format!("{}/v2/bot/info", self.base_url);
        let resp = self
            .authenticate(self.client.get(&url))
            .send()
            .await
            .map_err(LineError::Http)?;
        let status = resp.status().as_u16();

        if resp.status().is_success() || status == 400 {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60)
                * 1000;
            Err(LineError::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(LineError::Unauthorized(
                "Invalid channel access token".into(),
            ))
        } else {
            Err(LineError::Api {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode.
    pub fn is_secretless(&self) -> bool {
        self.channel_access_token.is_empty()
    }

    /// Generic GET → JSON deserialization with retry.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> LineResult<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let client = self.client.clone();
        let token = self.channel_access_token.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %url, "LINE API GET");
                let request = if token.is_empty() {
                    client.get(&url)
                } else {
                    client.get(&url).bearer_auth(&token)
                };

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: LineError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: LineError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(LineError::Unauthorized(
                        "Invalid channel access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "LINE API request failed");
                    let decision = classify_http_status(status, None);
                    let err = LineError::Api {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<T>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(LineError::Http(e)),
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn client_creation() {
        let client = LineClient::new(
            "https://api.line.me",
            "test_token",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = LineClient::new(
            "https://api.line.me/",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client =
            LineClient::new("https://api.line.me", "", HttpRetryConfig::default()).unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn non_secretless() {
        let client = LineClient::new(
            "https://api.line.me",
            "real_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[test]
    fn debug_redacts_token() {
        let client = LineClient::new(
            "https://api.line.me",
            "super_secret_channel_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_channel_token"),
            "Debug output must not contain the raw token"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn sanitize_path_rejects_traversal() {
        assert!(LineClient::sanitize_path_segment("../etc/passwd").is_err());
        assert!(LineClient::sanitize_path_segment("foo/bar").is_err());
        assert!(LineClient::sanitize_path_segment("").is_err());
        assert!(LineClient::sanitize_path_segment("foo\0bar").is_err());
    }

    #[test]
    fn sanitize_path_accepts_valid() {
        assert!(LineClient::sanitize_path_segment("U1234567890abcdef").is_ok());
        assert!(LineClient::sanitize_path_segment("richmenu-abc123").is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/bot/info"))
            .and(header("authorization", "Bearer test_tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let client =
            LineClient::new(&mock_server.uri(), "test_tok", HttpRetryConfig::default()).unwrap();
        assert!(client.health_check().await.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_401() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/bot/info"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client =
            LineClient::new(&mock_server.uri(), "bad_tok", HttpRetryConfig::default()).unwrap();
        let result = client.health_check().await;
        assert!(matches!(result, Err(LineError::Unauthorized(_))));
    }

    #[fcp_async_core::runtime::test]
    async fn secretless_health_check_omits_auth() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/bot/info"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&mock_server)
            .await;

        let client =
            LineClient::new(&mock_server.uri(), "", HttpRetryConfig::default()).unwrap();
        assert!(client.health_check().await.is_ok());

        let requests = mock_server.received_requests().await.unwrap_or_default();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.get("authorization").is_none());
    }
}
