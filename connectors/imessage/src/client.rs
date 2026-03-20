//! `BlueBubbles` HTTP client.
//!
//! Communicates with the `BlueBubbles` REST API to bridge `iMessage`.
//! All requests require the server password as a query parameter.

use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop, classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{BlueBubblesError, BlueBubblesResult};
use crate::types::{
    Chat, Message, PaginatedResponse, QueryParams, SendMessageRequest, SendMessageResponse,
    ServerInfo,
};

/// `BlueBubbles` API client.
pub struct BlueBubblesClient {
    client: Client,
    server_url: String,
    password: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for BlueBubblesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlueBubblesClient")
            .field("client", &self.client)
            .field("server_url", &self.server_url)
            .field("password", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl BlueBubblesClient {
    /// Create a new `BlueBubbles` client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        server_url: &str,
        password: &str,
        retry_config: HttpRetryConfig,
    ) -> BlueBubblesResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(BlueBubblesError::Http)?;

        Ok(Self {
            client,
            server_url: server_url.trim_end_matches('/').to_string(),
            password: password.to_string(),
            retry_config,
        })
    }

    /// Get the server base URL (for diagnostics).
    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Get server information.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn server_info(&self, runtime: &ConnectorRuntime) -> BlueBubblesResult<ServerInfo> {
        let url = format!("{}/api/v1/server/info", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let password = self.password.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let password = password.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles server info");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &password)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<ServerInfo>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(BlueBubblesError::Http(e)),
                }
            }
        })
        .await
    }

    /// Send a text message to a chat.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn send_message(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
        text: &str,
    ) -> BlueBubblesResult<SendMessageResponse> {
        let url = format!("{}/api/v1/message/text", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let password = self.password.clone();

        let body = SendMessageRequest {
            chat_guid: chat_guid.to_string(),
            message: text.to_string(),
            temp_guid: Some(uuid::Uuid::new_v4().to_string()),
            method: "apple-script".to_string(),
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let password = password.clone();
            let body = body.clone();
            async move {
                debug!(attempt, "Sending iMessage via BlueBubbles");
                let resp = match client
                    .post(&url)
                    .query(&[("password", &password)])
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis()
                                .try_into()
                                .unwrap_or(u64::MAX),
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<SendMessageResponse>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(BlueBubblesError::Http(e)),
                }
            }
        })
        .await
    }

    /// Get a paginated list of chats.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_chats(
        &self,
        runtime: &ConnectorRuntime,
        params: &QueryParams,
    ) -> BlueBubblesResult<PaginatedResponse<Chat>> {
        let url = format!("{}/api/v1/chat", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let password = self.password.clone();
        let params = params.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let password = password.clone();
            let params = params.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles chats");
                let mut query: Vec<(&str, String)> = vec![("password", password)];
                if let Some(offset) = params.offset {
                    query.push(("offset", offset.to_string()));
                }
                if let Some(limit) = params.limit {
                    query.push(("limit", limit.to_string()));
                }
                if let Some(sort) = &params.sort {
                    query.push(("sort", sort.clone()));
                }

                let resp = match client.get(&url).query(&query).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<PaginatedResponse<Chat>>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(BlueBubblesError::Http(e)),
                }
            }
        })
        .await
    }

    /// Get a single chat by GUID.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_chat(
        &self,
        runtime: &ConnectorRuntime,
        guid: &str,
    ) -> BlueBubblesResult<Chat> {
        let url = format!("{}/api/v1/chat/{guid}", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let password = self.password.clone();
        let guid = guid.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let password = password.clone();
            let guid = guid.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles chat");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &password)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::ChatNotFound { guid });
                }

                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Unauthorized {
                        message: "Invalid server password".into(),
                    });
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<Chat>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(BlueBubblesError::Http(e)),
                }
            }
        })
        .await
    }

    /// Get messages for a chat.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_messages(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
        params: &QueryParams,
    ) -> BlueBubblesResult<PaginatedResponse<Message>> {
        let url = format!("{}/api/v1/chat/{chat_guid}/message", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let password = self.password.clone();
        let params = params.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let password = password.clone();
            let params = params.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles messages");
                let mut query: Vec<(&str, String)> = vec![("password", password)];
                if let Some(offset) = params.offset {
                    query.push(("offset", offset.to_string()));
                }
                if let Some(limit) = params.limit {
                    query.push(("limit", limit.to_string()));
                }
                if let Some(after) = params.after {
                    query.push(("after", after.to_string()));
                }
                if let Some(before) = params.before {
                    query.push(("before", before.to_string()));
                }
                if let Some(sort) = &params.sort {
                    query.push(("sort", sort.clone()));
                }

                let resp = match client.get(&url).query(&query).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "BlueBubbles get_messages failed");
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<PaginatedResponse<Message>>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(BlueBubblesError::Http(e)),
                }
            }
        })
        .await
    }

    /// Download an attachment by GUID.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails.
    pub async fn download_attachment(
        &self,
        runtime: &ConnectorRuntime,
        guid: &str,
    ) -> BlueBubblesResult<Vec<u8>> {
        let url = format!("{}/api/v1/attachment/{guid}/download", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let password = self.password.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let password = password.clone();
            async move {
                debug!(attempt, "Downloading BlueBubbles attachment");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &password)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.bytes().await {
                    Ok(bytes) => AttemptOutcome::Success(bytes.to_vec()),
                    Err(e) => AttemptOutcome::Terminal(BlueBubblesError::Http(e)),
                }
            }
        })
        .await
    }

    /// Mark a chat as read.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn mark_read(
        &self,
        runtime: &ConnectorRuntime,
        chat_guid: &str,
    ) -> BlueBubblesResult<()> {
        let url = format!("{}/api/v1/chat/{chat_guid}/read", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let password = self.password.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let password = password.clone();
            async move {
                debug!(attempt, "Marking BlueBubbles chat as read");
                let resp = match client
                    .post(&url)
                    .query(&[("password", &password)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = BlueBubblesError::from_api_response(status, &text);
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

    /// Lightweight health check: verify server is reachable.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is unreachable.
    pub async fn health_check(&self) -> BlueBubblesResult<()> {
        let url = format!("{}/api/v1/server/info", self.server_url);
        let resp = self
            .client
            .get(&url)
            .query(&[("password", &self.password)])
            .send()
            .await
            .map_err(|_| BlueBubblesError::ServerUnreachable)?;

        if resp.status().is_success() {
            Ok(())
        } else if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
            Err(BlueBubblesError::Unauthorized {
                message: "Invalid server password".into(),
            })
        } else {
            Err(BlueBubblesError::ServerUnreachable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = BlueBubblesClient::new(
            "http://localhost:1234",
            "test-password",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn server_url_trimmed() {
        let client = BlueBubblesClient::new(
            "http://localhost:1234/",
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.server_url().ends_with('/'));
    }

    #[fcp_async_core::runtime::test]
    async fn server_info_success() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/server/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "os_version": "14.2",
                    "server_version": "1.9.0",
                    "private_api": true,
                    "proxy_service": "cloudflare"
                })),
            )
            .mount(&mock_server)
            .await;

        let client = BlueBubblesClient::new(
            &mock_server.uri(),
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::migration::ConnectorRuntimeConfig::default());
        let info = client.server_info(&runtime).await.unwrap();
        assert_eq!(info.os_version.as_deref(), Some("14.2"));
        assert!(info.private_api);
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_success() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/message/text"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status": 200,
                    "message": "Message sent!",
                    "data": {
                        "guid": "msg-001",
                        "text": "Hello!",
                        "is_from_me": true,
                        "attachments": []
                    }
                })),
            )
            .mount(&mock_server)
            .await;

        let client = BlueBubblesClient::new(
            &mock_server.uri(),
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::migration::ConnectorRuntimeConfig::default());
        let resp = client
            .send_message(&runtime, "iMessage;-;+15551234567", "Hello!")
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.data.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_unauthorized() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/message/text"))
            .respond_with(wiremock::ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&mock_server)
            .await;

        let client = BlueBubblesClient::new(
            &mock_server.uri(),
            "bad-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::migration::ConnectorRuntimeConfig::default());
        let result = client
            .send_message(&runtime, "iMessage;-;+15551234567", "Hello!")
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BlueBubblesError::Unauthorized { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/server/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "os_version": "14.2",
                    "server_version": "1.9.0",
                    "private_api": false
                })),
            )
            .mount(&mock_server)
            .await;

        let client = BlueBubblesClient::new(
            &mock_server.uri(),
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.health_check().await.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_server_down() {
        let client = BlueBubblesClient::new(
            "http://127.0.0.1:1",
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let result = client.health_check().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BlueBubblesError::ServerUnreachable
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn get_chats_success() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/chat"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "total": 2,
                    "offset": 0,
                    "limit": 25,
                    "data": [
                        {
                            "guid": "iMessage;-;+15551234567",
                            "display_name": "Alice",
                            "participants": [],
                            "is_group": false
                        },
                        {
                            "guid": "iMessage;+;chat123",
                            "display_name": "Family",
                            "participants": [],
                            "is_group": true
                        }
                    ]
                })),
            )
            .mount(&mock_server)
            .await;

        let client = BlueBubblesClient::new(
            &mock_server.uri(),
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::migration::ConnectorRuntimeConfig::default());
        let resp = client
            .get_chats(&runtime, &QueryParams::default())
            .await
            .unwrap();
        assert_eq!(resp.total, Some(2));
        assert_eq!(resp.data.len(), 2);
        assert!(!resp.data[0].is_group);
        assert!(resp.data[1].is_group);
    }

    #[fcp_async_core::runtime::test]
    async fn get_chat_success() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/chat/iMessage;-;+15551234567",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "guid": "iMessage;-;+15551234567",
                    "display_name": "Alice",
                    "participants": [],
                    "is_group": false
                })),
            )
            .mount(&mock_server)
            .await;

        let client = BlueBubblesClient::new(
            &mock_server.uri(),
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::migration::ConnectorRuntimeConfig::default());
        let resp = client
            .get_chat(&runtime, "iMessage;-;+15551234567")
            .await
            .unwrap();
        assert_eq!(resp.guid, "iMessage;-;+15551234567");
        assert_eq!(resp.display_name.as_deref(), Some("Alice"));
    }

    #[fcp_async_core::runtime::test]
    async fn download_attachment_success() {
        let mock_server = wiremock::MockServer::start().await;
        let body = b"bluebubbles-attachment".to_vec();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/attachment/attachment-123/download",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&mock_server)
            .await;

        let client = BlueBubblesClient::new(
            &mock_server.uri(),
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::migration::ConnectorRuntimeConfig::default());
        let resp = client
            .download_attachment(&runtime, "attachment-123")
            .await
            .unwrap();
        assert_eq!(resp, body);
    }

    #[fcp_async_core::runtime::test]
    async fn mark_read_success() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/v1/chat/iMessage;-;+15551234567/read",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status": 200, "message": "Marked as read"})),
            )
            .mount(&mock_server)
            .await;

        let client = BlueBubblesClient::new(
            &mock_server.uri(),
            "test-password",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::migration::ConnectorRuntimeConfig::default());
        let result = client.mark_read(&runtime, "iMessage;-;+15551234567").await;
        assert!(result.is_ok());
    }
}
