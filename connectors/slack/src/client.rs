//! Slack Web API client.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument, warn};

use crate::{
    error::{SlackError, SlackResult},
    types::{
        ChannelListData, FileUploadData, HistoryData, Message, PostMessageData, SearchData,
        SlackApiResponse, TopicSetData, UserInfoData,
    },
};

/// Default Slack API base URL.
const DEFAULT_BASE_URL: &str = "https://slack.com/api";

/// Slack Web API client with retry logic and rate limit awareness.
#[derive(Debug)]
pub struct SlackClient {
    client: Client,
    token: String,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
}

impl SlackClient {
    /// Create a new Slack client with a bot or user token.
    pub fn new(token: impl Into<String>) -> SlackResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-slack/0.1.0")
            .build()
            .map_err(SlackError::Http)?;

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

    /// Post a message to a channel.
    #[instrument(skip(self))]
    pub async fn post_message(
        &self,
        channel: &str,
        text: &str,
        thread_ts: Option<&str>,
    ) -> SlackResult<Message> {
        let mut body = serde_json::json!({
            "channel": channel,
            "text": text,
        });
        if let Some(ts) = thread_ts {
            body["thread_ts"] = serde_json::Value::String(ts.to_string());
        }

        let resp: SlackApiResponse<PostMessageData> =
            self.post_json("chat.postMessage", &body).await?;
        Self::check_response(&resp)?;
        Ok(resp.data.expect("ok response has data").message)
    }

    /// Get channel conversation history.
    #[instrument(skip(self))]
    pub async fn get_channel_history(
        &self,
        channel: &str,
        limit: Option<u32>,
    ) -> SlackResult<Vec<Message>> {
        let mut params = vec![("channel", channel.to_string())];
        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }

        let resp: SlackApiResponse<HistoryData> =
            self.get_with_params("conversations.history", &params).await?;
        Self::check_response(&resp)?;
        Ok(resp.data.expect("ok response has data").messages)
    }

    /// Search messages across the workspace.
    #[instrument(skip(self))]
    pub async fn search_messages(&self, query: &str) -> SlackResult<SearchData> {
        let params = [("query", query.to_string())];
        let resp: SlackApiResponse<SearchData> =
            self.get_with_params("search.messages", &params).await?;
        Self::check_response(&resp)?;
        Ok(resp.data.expect("ok response has data"))
    }

    // ── Channel operations ───────────────────────────────────────

    /// List channels in the workspace.
    #[instrument(skip(self))]
    pub async fn list_channels(&self, types: Option<&str>) -> SlackResult<Vec<crate::types::Channel>> {
        let mut params: Vec<(&str, String)> = vec![];
        if let Some(types) = types {
            params.push(("types", types.to_string()));
        }

        let resp: SlackApiResponse<ChannelListData> =
            self.get_with_params("conversations.list", &params).await?;
        Self::check_response(&resp)?;
        Ok(resp.data.expect("ok response has data").channels)
    }

    /// Set the topic for a channel.
    #[instrument(skip(self))]
    pub async fn set_channel_topic(
        &self,
        channel: &str,
        topic: &str,
    ) -> SlackResult<String> {
        let body = serde_json::json!({
            "channel": channel,
            "topic": topic,
        });
        let resp: SlackApiResponse<TopicSetData> =
            self.post_json("conversations.setTopic", &body).await?;
        Self::check_response(&resp)?;
        Ok(resp.data.expect("ok response has data").topic)
    }

    // ── User operations ──────────────────────────────────────────

    /// Get information about a user.
    #[instrument(skip(self))]
    pub async fn get_user_info(&self, user: &str) -> SlackResult<crate::types::User> {
        let params = [("user", user.to_string())];
        let resp: SlackApiResponse<UserInfoData> =
            self.get_with_params("users.info", &params).await?;
        Self::check_response(&resp)?;
        Ok(resp.data.expect("ok response has data").user)
    }

    // ── File operations ──────────────────────────────────────────

    /// Upload a file to channels.
    #[instrument(skip(self, content))]
    pub async fn upload_file(
        &self,
        channels: &str,
        content: &str,
        filename: Option<&str>,
    ) -> SlackResult<crate::types::SlackFile> {
        let body = serde_json::json!({
            "channels": channels,
            "content": content,
            "filename": filename.unwrap_or("upload.txt"),
        });
        let resp: SlackApiResponse<FileUploadData> =
            self.post_json("files.upload", &body).await?;
        Self::check_response(&resp)?;
        Ok(resp.data.expect("ok response has data").file)
    }

    /// Download a file by ID (returns the file info with download URL).
    #[instrument(skip(self))]
    pub async fn get_file_info(&self, file_id: &str) -> SlackResult<crate::types::SlackFile> {
        let params = [("file", file_id.to_string())];
        let resp: SlackApiResponse<FileUploadData> =
            self.get_with_params("files.info", &params).await?;
        Self::check_response(&resp)?;
        Ok(resp.data.expect("ok response has data").file)
    }

    // ── Reaction operations ──────────────────────────────────────

    /// Add a reaction to a message.
    #[instrument(skip(self))]
    pub async fn add_reaction(
        &self,
        channel: &str,
        timestamp: &str,
        name: &str,
    ) -> SlackResult<bool> {
        let body = serde_json::json!({
            "channel": channel,
            "timestamp": timestamp,
            "name": name,
        });
        let resp: SlackApiResponse<serde_json::Value> =
            self.post_json("reactions.add", &body).await?;
        Self::check_response(&resp)?;
        Ok(true)
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &[(&str, String)],
    ) -> SlackResult<T> {
        let mut url = format!("{}/{method}", self.base_url);
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC);
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if let Some(retry_result) = Self::check_rate_limit(&resp) {
                        if attempt <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(method, attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(SlackError::RateLimited {
                            retry_after_secs: retry_result
                                .map_or(60, |d| d.as_secs()),
                        });
                    }
                    return resp.json::<T>().await.map_err(Into::into);
                }
                Err(e) if e.is_timeout() && attempt <= self.max_retries => {
                    warn!(method, attempt, "Request timed out, retrying in {delay:?}");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> SlackResult<T> {
        let url = format!("{}/{method}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self
                .client
                .post(&url)
                .bearer_auth(&self.token)
                .json(body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if let Some(retry_result) = Self::check_rate_limit(&resp) {
                        if attempt <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(method, attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(SlackError::RateLimited {
                            retry_after_secs: retry_result
                                .map_or(60, |d| d.as_secs()),
                        });
                    }
                    return resp.json::<T>().await.map_err(Into::into);
                }
                Err(e) if e.is_timeout() && attempt <= self.max_retries => {
                    warn!(method, attempt, "Request timed out, retrying in {delay:?}");
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

    fn check_response<T>(resp: &SlackApiResponse<T>) -> SlackResult<()> {
        if resp.ok {
            Ok(())
        } else {
            let error = resp.error.clone().unwrap_or_else(|| "unknown_error".into());
            debug!(error = %error, "Slack API returned error");
            Err(SlackError::Api {
                error,
                code: None,
                ok: false,
            })
        }
    }
}
