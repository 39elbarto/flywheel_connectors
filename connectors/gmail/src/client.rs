//! Gmail API client.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument, warn};

use crate::{
    error::{GmailError, GmailResult},
    types::{
        GmailDraft, GmailLabel, GmailMessage, GmailThread, LabelsListResponse,
        MessagesListResponse,
    },
};

/// Default Gmail API base URL.
const DEFAULT_BASE_URL: &str = "https://gmail.googleapis.com/gmail/v1";

/// Gmail API client with retry logic and rate limit awareness.
#[derive(Debug)]
pub struct GmailClient {
    client: Client,
    token: String,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
}

impl GmailClient {
    /// Create a new Gmail client with an `OAuth2` access token.
    pub fn new(token: impl Into<String>) -> GmailResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-gmail/0.1.0")
            .build()
            .map_err(GmailError::Http)?;

        Ok(Self {
            client,
            token: token.into(),
            base_url: DEFAULT_BASE_URL.into(),
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            total_requests: AtomicU64::new(0),
        })
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub const fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.max_retries = max_retries;
        self.initial_delay_ms = initial_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    // ── Message operations ───────────────────────────────────────

    /// Get a single message by ID.
    #[instrument(skip(self))]
    pub async fn get_message(&self, message_id: &str) -> GmailResult<GmailMessage> {
        let url = format!("{}/users/me/messages/{message_id}", self.base_url);
        self.get(&url).await
    }

    /// List messages, optionally filtered by query.
    #[instrument(skip(self))]
    pub async fn list_messages(
        &self,
        query: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> GmailResult<MessagesListResponse> {
        let mut params = Vec::new();
        if let Some(q) = query {
            params.push(("q", q.to_string()));
        }
        if let Some(max) = max_results {
            params.push(("maxResults", max.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }

        let url = format!("{}/users/me/messages", self.base_url);
        self.get_with_params(&url, &params).await
    }

    /// Send a new message (RFC 2822 encoded, base64url).
    #[instrument(skip(self, raw_message))]
    pub async fn send_message(&self, raw_message: &str) -> GmailResult<GmailMessage> {
        let url = format!("{}/users/me/messages/send", self.base_url);
        let body = serde_json::json!({ "raw": raw_message });
        self.post_json(&url, &body).await
    }

    /// Modify message labels (add/remove).
    #[instrument(skip(self))]
    pub async fn modify_message(
        &self,
        message_id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> GmailResult<GmailMessage> {
        let url = format!("{}/users/me/messages/{message_id}/modify", self.base_url);
        let body = serde_json::json!({
            "addLabelIds": add_labels,
            "removeLabelIds": remove_labels,
        });
        self.post_json(&url, &body).await
    }

    /// Trash a message.
    #[instrument(skip(self))]
    pub async fn trash_message(&self, message_id: &str) -> GmailResult<GmailMessage> {
        let url = format!("{}/users/me/messages/{message_id}/trash", self.base_url);
        self.post_json(&url, &serde_json::json!({})).await
    }

    // ── Thread operations ────────────────────────────────────────

    /// Get a thread by ID.
    #[instrument(skip(self))]
    pub async fn get_thread(&self, thread_id: &str) -> GmailResult<GmailThread> {
        let url = format!("{}/users/me/threads/{thread_id}", self.base_url);
        self.get(&url).await
    }

    // ── Label operations ─────────────────────────────────────────

    /// List all labels.
    #[instrument(skip(self))]
    pub async fn list_labels(&self) -> GmailResult<Vec<GmailLabel>> {
        let url = format!("{}/users/me/labels", self.base_url);
        let resp: LabelsListResponse = self.get(&url).await?;
        Ok(resp.labels)
    }

    // ── Draft operations ─────────────────────────────────────────

    /// Get a draft by ID.
    #[instrument(skip(self))]
    pub async fn get_draft(&self, draft_id: &str) -> GmailResult<GmailDraft> {
        let url = format!("{}/users/me/drafts/{draft_id}", self.base_url);
        self.get(&url).await
    }

    /// Send a draft.
    #[instrument(skip(self))]
    pub async fn send_draft(&self, draft_id: &str) -> GmailResult<GmailMessage> {
        let url = format!("{}/users/me/drafts/send", self.base_url);
        let body = serde_json::json!({ "id": draft_id });
        self.post_json(&url, &body).await
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get<T: serde::de::DeserializeOwned>(&self, url: &str) -> GmailResult<T> {
        self.get_with_params(url, &[]).await
    }

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        params: &[(&str, String)],
    ) -> GmailResult<T> {
        let mut url = base_url.to_string();
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self.client.get(&url).bearer_auth(&self.token).send().await;

            match response {
                Ok(resp) => {
                    if let Some(retry_result) = Self::check_rate_limit(&resp) {
                        if attempt <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(GmailError::RateLimited {
                            retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                        });
                    }
                    if let Some(err) = Self::check_api_error(&resp) {
                        return Err(err);
                    }
                    return resp.json::<T>().await.map_err(Into::into);
                }
                Err(e) if e.is_timeout() && attempt <= self.max_retries => {
                    warn!(attempt, "Request timed out, retrying in {delay:?}");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GmailResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self
                .client
                .post(url)
                .bearer_auth(&self.token)
                .json(body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if let Some(retry_result) = Self::check_rate_limit(&resp) {
                        if attempt <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(GmailError::RateLimited {
                            retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                        });
                    }
                    if let Some(err) = Self::check_api_error(&resp) {
                        return Err(err);
                    }
                    return resp.json::<T>().await.map_err(Into::into);
                }
                Err(e) if e.is_timeout() && attempt <= self.max_retries => {
                    warn!(attempt, "Request timed out, retrying in {delay:?}");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &Response) -> Option<Option<Duration>> {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }

    fn check_api_error(response: &Response) -> Option<GmailError> {
        let status = response.status();
        if status.is_success() {
            return None;
        }

        if status == StatusCode::UNAUTHORIZED {
            return Some(GmailError::Unauthorized);
        }

        debug!(status = %status, "Gmail API returned error status");
        None
    }
}
