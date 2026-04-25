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

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> BlueBubblesResult<&'a str> {
    if value.trim().is_empty() {
        return Err(BlueBubblesError::Validation(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(BlueBubblesError::Validation(format!(
            "{field} contains invalid path characters"
        )));
    }
    Ok(value)
}

use crate::types::{
    BlueBubblesConfig, Chat, Message, PaginatedResponse, QueryParams, SendMessageRequest,
    SendMessageResponse, ServerInfo,
};

fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn duration_to_ms(d: Duration) -> u64 {
    d.as_millis().try_into().unwrap_or(u64::MAX)
}

async fn decode_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, BlueBubblesError> {
    resp.json::<T>().await.map_err(BlueBubblesError::Http)
}

/// `BlueBubbles` API client.
pub struct BlueBubblesClient {
    client: Client,
    server_url: String,
    server_passcode: String,
    retry_config: HttpRetryConfig,
    request_timeout: Duration,
}

impl std::fmt::Debug for BlueBubblesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlueBubblesClient")
            .field("client", &self.client)
            .field("server_url", &self.server_url)
            .field("server_passcode", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .field("request_timeout", &self.request_timeout)
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
        server_passcode: &str,
        retry_config: HttpRetryConfig,
    ) -> BlueBubblesResult<Self> {
        Self::build(
            server_url,
            server_passcode,
            retry_config,
            Duration::from_secs(30),
        )
    }

    /// Create a client from validated connector configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn from_config(config: &BlueBubblesConfig) -> BlueBubblesResult<Self> {
        Self::build(
            &config.server_url,
            &config.server_passcode,
            config.retry.clone(),
            Duration::from_millis(config.request_timeout_ms),
        )
    }

    fn build(
        server_url: &str,
        server_passcode: &str,
        retry_config: HttpRetryConfig,
        request_timeout: Duration,
    ) -> BlueBubblesResult<Self> {
        let client = Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(BlueBubblesError::Http)?;

        Ok(Self {
            client,
            server_url: server_url.trim().trim_end_matches('/').to_string(),
            server_passcode: server_passcode.trim().to_string(),
            retry_config,
            request_timeout,
        })
    }

    /// Get the server base URL (for diagnostics).
    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Get the configured request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
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
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles server info");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
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

                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Api {
                        status_code: 404,
                        message: "Server API not found (check URL)".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
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

                match decode_json::<ServerInfo>(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
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
        let server_passcode = self.server_passcode.clone();

        let body = SendMessageRequest {
            chat_guid: chat_guid.to_string(),
            message: text.to_string(),
            temp_guid: Some(uuid::Uuid::new_v4().to_string()),
            method: "apple-script".to_string(),
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let body = body.clone();
            async move {
                debug!(attempt, "Sending iMessage via BlueBubbles");
                let resp = match client
                    .post(&url)
                    .query(&[("password", &server_passcode)])
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
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
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
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

                match decode_json::<SendMessageResponse>(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
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
        let server_passcode = self.server_passcode.clone();
        let params = params.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let params = params.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles chats");
                let mut query: Vec<(&str, String)> = vec![("password", server_passcode)];
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
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
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

                match decode_json::<PaginatedResponse<Chat>>(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
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
        let guid = sanitize_path_segment(guid, "chat_guid")?;
        let url = format!("{}/api/v1/chat/{guid}", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let guid = guid.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let guid = guid.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles chat");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::ChatNotFound { guid });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
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

                match decode_json::<Chat>(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
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
        let chat_guid = sanitize_path_segment(chat_guid, "chat_guid")?;
        let url = format!("{}/api/v1/chat/{chat_guid}/message", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let chat_guid = chat_guid.to_string();
        let params = params.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let chat_guid = chat_guid.clone();
            let params = params.clone();
            async move {
                debug!(attempt, "Fetching BlueBubbles messages");
                let mut query: Vec<(&str, String)> = vec![("password", server_passcode)];
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
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::ChatNotFound {
                        guid: chat_guid,
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
                        },
                        retry_after,
                    };
                }

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

                match decode_json::<PaginatedResponse<Message>>(resp).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) => AttemptOutcome::Terminal(error),
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
        let guid = sanitize_path_segment(guid, "attachment_guid")?;
        let url = format!("{}/api/v1/attachment/{guid}/download", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            async move {
                debug!(attempt, "Downloading BlueBubbles attachment");
                let resp = match client
                    .get(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Api {
                        status_code: 404,
                        message: "Server API not found (check URL)".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
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
        let chat_guid = sanitize_path_segment(chat_guid, "chat_guid")?;
        let url = format!("{}/api/v1/chat/{chat_guid}/read", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            async move {
                debug!(attempt, "Marking BlueBubbles chat as read");
                let resp = match client
                    .post(&url)
                    .query(&[("password", &server_passcode)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: BlueBubblesError::from_transport_error(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 404 {
                    return AttemptOutcome::Terminal(BlueBubblesError::Api {
                        status_code: 404,
                        message: "Server API not found (check URL)".into(),
                    });
                }

                if status == 429 {
                    let retry_after = retry_after_from_headers(resp.headers());
                    return AttemptOutcome::Retryable {
                        error: BlueBubblesError::RateLimited {
                            retry_after_ms: duration_to_ms(
                                retry_after.unwrap_or(Duration::from_secs(30)),
                            ),
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
            .query(&[("password", &self.server_passcode)])
            .send()
            .await
            .map_err(BlueBubblesError::from_transport_error)?;

        let status = resp.status().as_u16();
        if status == 429 {
            let retry_after =
                retry_after_from_headers(resp.headers()).unwrap_or(Duration::from_secs(30));
            return Err(BlueBubblesError::RateLimited {
                retry_after_ms: duration_to_ms(retry_after),
            });
        }

        if resp.status().is_success() {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(BlueBubblesError::from_api_response(status, &text))
        }
    }
}
