//! Google Calendar API client.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument, warn};

use crate::{
    error::{GCalResult, GoogleCalendarError},
    types::{CalendarListResponse, Event, EventsListResponse},
};

/// Default Google Calendar API base URL.
const DEFAULT_BASE_URL: &str = "https://www.googleapis.com/calendar/v3";

/// Google Calendar API client with retry logic and rate limit awareness.
#[derive(Debug)]
pub struct GoogleCalendarClient {
    client: Client,
    token: String,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
}

impl GoogleCalendarClient {
    /// Create a new Google Calendar client with an `OAuth2` access token.
    pub fn new(token: impl Into<String>) -> GCalResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-calendar/0.1.0")
            .build()
            .map_err(GoogleCalendarError::Http)?;

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

    // ── Calendar operations ─────────────────────────────────────

    /// List all calendars for the authenticated user.
    #[instrument(skip(self))]
    pub async fn list_calendars(&self) -> GCalResult<CalendarListResponse> {
        let url = format!("{}/users/me/calendarList", self.base_url);
        self.get(&url).await
    }

    // ── Event operations ────────────────────────────────────────

    /// Get a single event by ID.
    #[instrument(skip(self))]
    pub async fn get_event(&self, calendar_id: &str, event_id: &str) -> GCalResult<Event> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_evt =
            percent_encoding::utf8_percent_encode(event_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!(
            "{}/calendars/{encoded_cal}/events/{encoded_evt}",
            self.base_url
        );
        self.get(&url).await
    }

    /// List events in a calendar.
    #[instrument(skip(self))]
    pub async fn list_events(
        &self,
        calendar_id: &str,
        time_min: Option<&str>,
        time_max: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> GCalResult<EventsListResponse> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let base = format!("{}/calendars/{encoded_cal}/events", self.base_url);

        let mut params = Vec::new();
        if let Some(t_min) = time_min {
            params.push(("timeMin", t_min.to_string()));
        }
        if let Some(t_max) = time_max {
            params.push(("timeMax", t_max.to_string()));
        }
        if let Some(max) = max_results {
            params.push(("maxResults", max.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }

        self.get_with_params(&base, &params).await
    }

    /// Create a new event in a calendar.
    #[instrument(skip(self, event))]
    pub async fn create_event(&self, calendar_id: &str, event: &Event) -> GCalResult<Event> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!("{}/calendars/{encoded_cal}/events", self.base_url);
        let body = serde_json::to_value(event).map_err(GoogleCalendarError::Json)?;
        self.post_json(&url, &body).await
    }

    /// Update an existing event.
    #[instrument(skip(self, event))]
    pub async fn update_event(
        &self,
        calendar_id: &str,
        event_id: &str,
        event: &Event,
    ) -> GCalResult<Event> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_evt =
            percent_encoding::utf8_percent_encode(event_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!(
            "{}/calendars/{encoded_cal}/events/{encoded_evt}",
            self.base_url
        );
        let body = serde_json::to_value(event).map_err(GoogleCalendarError::Json)?;
        self.put_json(&url, &body).await
    }

    /// Delete an event.
    #[instrument(skip(self))]
    pub async fn delete_event(&self, calendar_id: &str, event_id: &str) -> GCalResult<()> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_evt =
            percent_encoding::utf8_percent_encode(event_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!(
            "{}/calendars/{encoded_cal}/events/{encoded_evt}",
            self.base_url
        );
        self.delete(&url).await
    }

    /// Quick-add an event using natural language.
    #[instrument(skip(self))]
    pub async fn quick_add(&self, calendar_id: &str, text: &str) -> GCalResult<Event> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_text =
            percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC);
        let url = format!(
            "{}/calendars/{encoded_cal}/events/quickAdd?text={encoded_text}",
            self.base_url
        );
        self.post_json(&url, &serde_json::json!({})).await
    }

    // ── Internal HTTP helpers ───────────────────────────────────

    async fn get<T: serde::de::DeserializeOwned>(&self, url: &str) -> GCalResult<T> {
        self.get_with_params(url, &[]).await
    }

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        params: &[(&str, String)],
    ) -> GCalResult<T> {
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
                        return Err(GoogleCalendarError::RateLimited {
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
    ) -> GCalResult<T> {
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
                        return Err(GoogleCalendarError::RateLimited {
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

    async fn put_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GCalResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self
                .client
                .put(url)
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
                        return Err(GoogleCalendarError::RateLimited {
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

    async fn delete(&self, url: &str) -> GCalResult<()> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self
                .client
                .delete(url)
                .bearer_auth(&self.token)
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
                        return Err(GoogleCalendarError::RateLimited {
                            retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                        });
                    }
                    if let Some(err) = Self::check_api_error(&resp) {
                        return Err(err);
                    }
                    return Ok(());
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

    fn check_api_error(response: &Response) -> Option<GoogleCalendarError> {
        let status = response.status();
        if status.is_success() {
            return None;
        }

        if status == StatusCode::UNAUTHORIZED {
            return Some(GoogleCalendarError::Unauthorized);
        }

        debug!(status = %status, "Google Calendar API returned error status");
        None
    }
}
