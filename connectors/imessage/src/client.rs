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
    BlueBubblesConfig, Chat, Message, PaginatedResponse, QueryParams, SEND_METHOD_APPLE_SCRIPT,
    SEND_METHOD_PRIVATE_API, SendMessageRequest, SendMessageResponse, ServerInfo,
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

async fn decode_server_info(resp: reqwest::Response) -> Result<ServerInfo, BlueBubblesError> {
    let value = resp
        .json::<serde_json::Value>()
        .await
        .map_err(BlueBubblesError::Http)?;
    let info = value
        .get("data")
        .filter(|data| data.is_object())
        .unwrap_or(&value);
    serde_json::from_value(info.clone()).map_err(BlueBubblesError::Json)
}

fn parse_macos_major_version(version: Option<&str>) -> Option<u64> {
    let version = version?.trim();
    let digits: String = version.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Send-method decision used for `BlueBubbles` text sends.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SendMethodDecision {
    /// Explicit `BlueBubbles` request method.
    pub method: String,
    /// Stable reason code for logs/tests/operator diagnostics.
    pub reason: &'static str,
    /// Whether `/server/info` was available before sending.
    pub server_info_available: bool,
    /// Reported Private API state when known.
    pub private_api: Option<bool>,
    /// Reported macOS version when known.
    pub os_version: Option<String>,
    /// Optional warning for degraded-but-preserved fallback sends.
    pub warning: Option<String>,
}

impl SendMethodDecision {
    fn from_server_info(info: &ServerInfo) -> Self {
        let major = parse_macos_major_version(info.os_version.as_deref());
        if info.private_api && major.is_some_and(|major| major >= 26) {
            return Self {
                method: SEND_METHOD_PRIVATE_API.to_string(),
                reason: "macos26_private_api_available",
                server_info_available: true,
                private_api: Some(true),
                os_version: info.os_version.clone(),
                warning: None,
            };
        }

        let reason = match (info.private_api, major) {
            (true, Some(_)) => "plain_text_apple_script_supported",
            (true, None) => "private_api_available_macos_unknown",
            (false, Some(major)) if major >= 26 => {
                "macos26_private_api_disabled_apple_script_fallback"
            }
            (false, _) => "private_api_disabled_apple_script_fallback",
        };

        Self {
            method: SEND_METHOD_APPLE_SCRIPT.to_string(),
            reason,
            server_info_available: true,
            private_api: Some(info.private_api),
            os_version: info.os_version.clone(),
            warning: None,
        }
    }

    fn unavailable(error: &BlueBubblesError) -> Self {
        Self {
            method: SEND_METHOD_APPLE_SCRIPT.to_string(),
            reason: "server_info_unavailable_apple_script_fallback",
            server_info_available: false,
            private_api: None,
            os_version: None,
            warning: Some(format!(
                "BlueBubbles server info unavailable; using explicit apple-script fallback: {error}"
            )),
        }
    }
}

/// Result of a `BlueBubbles` send plus the method decision that shaped the request.
#[derive(Debug, Clone)]
pub struct SendMessageOutcome {
    /// Raw `BlueBubbles` send response.
    pub response: SendMessageResponse,
    /// Send method decision used for the request body.
    pub decision: SendMethodDecision,
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

                match decode_server_info(resp).await {
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
    ) -> BlueBubblesResult<SendMessageOutcome> {
        let url = format!("{}/api/v1/message/text", self.server_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let server_passcode = self.server_passcode.clone();
        let decision = match self.server_info(runtime).await {
            Ok(info) => SendMethodDecision::from_server_info(&info),
            Err(error) => SendMethodDecision::unavailable(&error),
        };

        let body = SendMessageRequest {
            chat_guid: chat_guid.to_string(),
            message: text.to_string(),
            temp_guid: Some(uuid::Uuid::new_v4().to_string()),
            method: decision.method.clone(),
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let server_passcode = server_passcode.clone();
            let body = body.clone();
            let decision = decision.clone();
            async move {
                debug!(
                    attempt,
                    send_method = %decision.method,
                    decision = decision.reason,
                    "Sending iMessage via BlueBubbles"
                );
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
                    Ok(response) => {
                        AttemptOutcome::Success(SendMessageOutcome { response, decision })
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn server_info(private_api: bool, os_version: Option<&str>) -> ServerInfo {
        ServerInfo {
            os_version: os_version.map(str::to_string),
            server_version: Some("1.9.0".into()),
            private_api,
            proxy_service: None,
        }
    }

    #[test]
    fn send_method_uses_private_api_for_macos26_when_available() {
        let decision = SendMethodDecision::from_server_info(&server_info(true, Some("26.0.1")));
        assert_eq!(decision.method, SEND_METHOD_PRIVATE_API);
        assert_eq!(decision.reason, "macos26_private_api_available");
        assert_eq!(decision.private_api, Some(true));
    }

    #[test]
    fn send_method_keeps_apple_script_for_older_macos_plain_text() {
        let decision = SendMethodDecision::from_server_info(&server_info(true, Some("15.5")));
        assert_eq!(decision.method, SEND_METHOD_APPLE_SCRIPT);
        assert_eq!(decision.reason, "plain_text_apple_script_supported");
    }

    #[test]
    fn send_method_falls_back_when_private_api_disabled_on_macos26() {
        let decision = SendMethodDecision::from_server_info(&server_info(false, Some("26.0")));
        assert_eq!(decision.method, SEND_METHOD_APPLE_SCRIPT);
        assert_eq!(
            decision.reason,
            "macos26_private_api_disabled_apple_script_fallback"
        );
        assert_eq!(decision.private_api, Some(false));
    }

    #[test]
    fn send_method_falls_back_when_server_info_is_unavailable() {
        let error = BlueBubblesError::ServerUnreachable;
        let decision = SendMethodDecision::unavailable(&error);
        assert_eq!(decision.method, SEND_METHOD_APPLE_SCRIPT);
        assert_eq!(
            decision.reason,
            "server_info_unavailable_apple_script_fallback"
        );
        assert!(!decision.server_info_available);
        assert!(decision.warning.is_some());
    }

    #[test]
    fn macos_major_version_parser_handles_known_shapes() {
        assert_eq!(parse_macos_major_version(Some("26.0.1")), Some(26));
        assert_eq!(parse_macos_major_version(Some(" 15.7 ")), Some(15));
        assert_eq!(parse_macos_major_version(Some("Tahoe")), None);
        assert_eq!(parse_macos_major_version(None), None);
    }
}
