//! Microsoft Graph REST API client.
//!
//! Uses Bearer token auth and JSON bodies for POST/PUT/PATCH.
//! Handles OData pagination via `@odata.nextLink`.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use reqwest::{Client, StatusCode, header};
use tracing::{debug, warn};

use crate::{
    error::{M365Error, M365Result},
    types::GraphListResponse,
};

const DEFAULT_API_URL: &str = "https://graph.microsoft.com/v1.0";

/// Microsoft Graph REST API client.
pub struct M365Client {
    http: Client,
    api_url: String,
    max_retries: u32,
}

impl M365Client {
    /// Create a new Graph API client with a Bearer access token.
    pub fn new(access_token: &str) -> M365Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {access_token}").parse().unwrap(),
        );

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-microsoft365/0.1.0")
            .build()
            .map_err(M365Error::Http)?;

        Ok(Self {
            http,
            api_url: DEFAULT_API_URL.to_string(),
            max_retries: 2,
        })
    }

    /// Set a custom API URL (for testing).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    // ── Mail operations ──────────────────────────────────────────

    /// List messages in a user's mailbox.
    pub async fn list_messages(
        &self,
        user_id: &str,
        folder_id: Option<&str>,
        top: Option<u32>,
        skip: Option<u32>,
        filter: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let folder_part = folder_id.map_or(String::new(), |f| format!("/mailFolders/{f}"));
        let mut url = format!("{}/users/{user_id}{folder_part}/messages", self.api_url);
        let mut params = Vec::new();
        if let Some(t) = top {
            params.push(format!("$top={t}"));
        }
        if let Some(s) = skip {
            params.push(format!("$skip={s}"));
        }
        if let Some(f) = filter {
            params.push(format!("$filter={f}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a specific message.
    pub async fn get_message(
        &self,
        user_id: &str,
        message_id: &str,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/users/{user_id}/messages/{message_id}", self.api_url);
        self.get(&url).await
    }

    /// Send a mail message.
    pub async fn send_message(
        &self,
        user_id: &str,
        message: &serde_json::Value,
    ) -> M365Result<()> {
        let url = format!("{}/users/{user_id}/sendMail", self.api_url);
        let body = serde_json::json!({ "message": message });
        self.post_json_no_content(&url, &body).await
    }

    /// Create a draft message.
    pub async fn create_draft(
        &self,
        user_id: &str,
        message: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/users/{user_id}/messages", self.api_url);
        self.post_json(&url, message).await
    }

    // ── Files operations ─────────────────────────────────────────

    /// List files and folders in OneDrive.
    pub async fn list_items(
        &self,
        user_id: &str,
        path: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let url = match path {
            Some(p) if !p.is_empty() => {
                format!("{}/users/{user_id}/drive/root:/{p}:/children", self.api_url)
            }
            _ => format!("{}/users/{user_id}/drive/root/children", self.api_url),
        };
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Download a file from OneDrive. Returns base64-encoded content.
    pub async fn download_file(
        &self,
        user_id: &str,
        item_id: &str,
    ) -> M365Result<(String, serde_json::Value)> {
        // First get metadata for name/size
        let meta_url = format!("{}/users/{user_id}/drive/items/{item_id}", self.api_url);
        let metadata = self.get(&meta_url).await?;

        // Then download the content
        let url = format!(
            "{}/users/{user_id}/drive/items/{item_id}/content",
            self.api_url
        );
        let bytes = self.get_bytes(&url).await?;
        let content = BASE64.encode(&bytes);
        Ok((content, metadata))
    }

    /// Upload a file to OneDrive (simple upload, up to 4 MB).
    pub async fn upload_file(
        &self,
        user_id: &str,
        path: &str,
        content: &[u8],
    ) -> M365Result<serde_json::Value> {
        let url = format!(
            "{}/users/{user_id}/drive/root:/{path}:/content",
            self.api_url
        );
        self.put_bytes(&url, content).await
    }

    /// Delete a drive item.
    pub async fn delete_item(&self, user_id: &str, item_id: &str) -> M365Result<()> {
        let url = format!("{}/users/{user_id}/drive/items/{item_id}", self.api_url);
        self.delete_no_content(&url).await
    }

    // ── Calendar operations ──────────────────────────────────────

    /// List calendar events within a time range.
    pub async fn list_events(
        &self,
        user_id: &str,
        start_datetime: Option<&str>,
        end_datetime: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let url = match (start_datetime, end_datetime) {
            (Some(start), Some(end)) => {
                format!(
                    "{}/users/{user_id}/calendarView?startDateTime={start}&endDateTime={end}",
                    self.api_url
                )
            }
            _ => format!("{}/users/{user_id}/events", self.api_url),
        };
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a calendar event.
    pub async fn create_event(
        &self,
        user_id: &str,
        event: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/users/{user_id}/events", self.api_url);
        self.post_json(&url, event).await
    }

    /// Delete a calendar event.
    pub async fn delete_event(&self, user_id: &str, event_id: &str) -> M365Result<()> {
        let url = format!("{}/users/{user_id}/events/{event_id}", self.api_url);
        self.delete_no_content(&url).await
    }

    /// Get free/busy schedule for users.
    pub async fn get_freebusy(
        &self,
        schedules: &[String],
        start_time: &serde_json::Value,
        end_time: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/me/calendar/getSchedule", self.api_url);
        let body = serde_json::json!({
            "schedules": schedules,
            "startTime": start_time,
            "endTime": end_time,
        });
        self.post_json(&url, &body).await
    }

    // ── Tasks operations ─────────────────────────────────────────

    /// List all To Do task lists.
    pub async fn list_task_lists(&self, user_id: &str) -> M365Result<GraphListResponse> {
        let url = format!("{}/users/{user_id}/todo/lists", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List tasks in a To Do list.
    pub async fn list_tasks(
        &self,
        user_id: &str,
        list_id: &str,
    ) -> M365Result<GraphListResponse> {
        let url = format!(
            "{}/users/{user_id}/todo/lists/{list_id}/tasks",
            self.api_url
        );
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a task in a To Do list.
    pub async fn create_task(
        &self,
        user_id: &str,
        list_id: &str,
        task: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!(
            "{}/users/{user_id}/todo/lists/{list_id}/tasks",
            self.api_url
        );
        self.post_json(&url, task).await
    }

    // ── Subscription operations ──────────────────────────────────

    /// Create a webhook subscription.
    pub async fn create_subscription(
        &self,
        subscription: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/subscriptions", self.api_url);
        self.post_json(&url, subscription).await
    }

    /// Renew a webhook subscription.
    pub async fn renew_subscription(
        &self,
        subscription_id: &str,
        expiration_datetime: &str,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/subscriptions/{subscription_id}", self.api_url);
        let body = serde_json::json!({
            "expirationDateTime": expiration_datetime,
        });
        self.patch_json(&url, &body).await
    }

    /// Delete a webhook subscription.
    pub async fn delete_subscription(&self, subscription_id: &str) -> M365Result<()> {
        let url = format!("{}/subscriptions/{subscription_id}", self.api_url);
        self.delete_no_content(&url).await
    }

    // ── Delta operations ─────────────────────────────────────────

    /// Perform a delta query for incremental sync.
    pub async fn delta_sync(
        &self,
        resource: &str,
        delta_token: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let url = match delta_token {
            Some(token) => format!("{}{resource}/delta?$deltatoken={token}", self.api_url),
            None => format!("{}{resource}/delta", self.api_url),
        };

        // Follow all pages to collect all changes
        let mut all_values = Vec::new();
        let mut current_url = url;
        let mut final_delta_link;

        loop {
            let data = self.get(&current_url).await?;
            let page: GraphListResponse = serde_json::from_value(data)?;
            all_values.extend(page.value);
            final_delta_link = page.delta_link.clone();

            if let Some(next) = page.next_link {
                current_url = next;
            } else {
                break;
            }
        }

        Ok(GraphListResponse {
            value: all_values,
            next_link: None,
            delta_link: final_delta_link,
        })
    }

    // ── HTTP helpers ─────────────────────────────────────────────

    async fn get(&self, url: &str) -> M365Result<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn get_bytes(&self, url: &str) -> M365Result<Vec<u8>> {
        self.execute_bytes(|| self.http.get(url)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn post_json_no_content(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> M365Result<()> {
        self.execute_no_content(|| self.http.post(url).json(body))
            .await
    }

    async fn patch_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        self.execute(|| self.http.patch(url).json(body)).await
    }

    async fn put_bytes(
        &self,
        url: &str,
        content: &[u8],
    ) -> M365Result<serde_json::Value> {
        let content = content.to_vec();
        self.execute(|| {
            self.http
                .put(url)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(content.clone())
        })
        .await
    }

    async fn delete_no_content(&self, url: &str) -> M365Result<()> {
        self.execute_no_content(|| self.http.delete(url)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> M365Result<serde_json::Value> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return Err(err),
                        ErrorAction::Retry(err) => {
                            last_err = Some(err);
                            continue;
                        }
                        ErrorAction::Success => {}
                    }

                    let body = response.text().await.map_err(M365Error::Http)?;
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(M365Error::Http(e));
                        continue;
                    }
                    return Err(M365Error::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(M365Error::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_code: None,
        }))
    }

    async fn execute_bytes(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> M365Result<Vec<u8>> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return Err(err),
                        ErrorAction::Retry(err) => {
                            last_err = Some(err);
                            continue;
                        }
                        ErrorAction::Success => {}
                    }

                    let bytes = response.bytes().await.map_err(M365Error::Http)?;
                    return Ok(bytes.to_vec());
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(M365Error::Http(e));
                        continue;
                    }
                    return Err(M365Error::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(M365Error::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_code: None,
        }))
    }

    async fn execute_no_content(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> M365Result<()> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return Err(err),
                        ErrorAction::Retry(err) => {
                            last_err = Some(err);
                            continue;
                        }
                        ErrorAction::Success => {}
                    }
                    return Ok(());
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(M365Error::Http(e));
                        continue;
                    }
                    return Err(M365Error::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(M365Error::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_code: None,
        }))
    }

    async fn handle_error_status(
        &self,
        status: StatusCode,
        response: &reqwest::Response,
        attempt: u32,
    ) -> ErrorAction {
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return ErrorAction::Return(M365Error::Api {
                message: format!("Authentication failed: HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            });
        }

        if status == StatusCode::NOT_FOUND {
            return ErrorAction::Return(M365Error::Api {
                message: format!("Resource not found: HTTP {status}"),
                status_code: Some(404),
                error_code: Some("NotFound".into()),
            });
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map_or(60_000, |s| s * 1000);

            let err = M365Error::RateLimit {
                retry_after_ms: retry_after,
            };
            if attempt < self.max_retries {
                warn!(attempt, "rate limited, will retry");
                return ErrorAction::Retry(err);
            }
            return ErrorAction::Return(err);
        }

        if status.is_server_error() {
            let err = M365Error::Api {
                message: format!("Server error: HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            };
            if attempt < self.max_retries {
                warn!(attempt, status = %status, "server error, will retry");
                return ErrorAction::Retry(err);
            }
            return ErrorAction::Return(err);
        }

        if !status.is_success() && status != StatusCode::NO_CONTENT {
            return ErrorAction::Return(M365Error::Api {
                message: format!("HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            });
        }

        ErrorAction::Success
    }
}

enum ErrorAction {
    Return(M365Error),
    Retry(M365Error),
    Success,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[fcp_async_core::runtime::test]
    async fn test_list_messages() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/me/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "msg_1", "subject": "Hello" },
                    { "id": "msg_2", "subject": "World" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client
            .list_messages("me", None, None, None, None)
            .await
            .unwrap();
        assert_eq!(result.value.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_message() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/me/messages/msg_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_123",
                "subject": "Test Message"
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client.get_message("me", "msg_123").await.unwrap();
        assert_eq!(result["id"], "msg_123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/users/me/sendMail"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let message = serde_json::json!({
            "subject": "Hello",
            "body": { "contentType": "Text", "content": "Hi" },
            "toRecipients": [{ "emailAddress": { "address": "bob@contoso.com" } }]
        });

        client.send_message("me", &message).await.unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_items() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/me/drive/root/children"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "item_1", "name": "Documents", "folder": { "childCount": 5 } },
                    { "id": "item_2", "name": "photo.jpg", "file": { "mimeType": "image/jpeg" } }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client.list_items("me", None).await.unwrap();
        assert_eq!(result.value.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_events() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/me/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "evt_1", "subject": "Standup" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client.list_events("me", None, None).await.unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_task_lists() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/me/todo/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "list_1", "displayName": "Tasks" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client.list_task_lists("me").await.unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_subscription() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "sub_123",
                "resource": "/me/messages",
                "changeType": "created",
                "expirationDateTime": "2026-03-04T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let sub = serde_json::json!({
            "changeType": "created",
            "notificationUrl": "https://webhook.example.com",
            "resource": "/me/messages",
            "expirationDateTime": "2026-03-04T00:00:00Z"
        });

        let result = client.create_subscription(&sub).await.unwrap();
        assert_eq!(result["id"], "sub_123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/me/messages"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("bad_token")
            .unwrap()
            .with_api_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.list_messages("me", None, None, None, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            M365Error::Api { status_code, .. } => assert_eq!(status_code, Some(401)),
            e => panic!("Expected Api error with 401, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/me/messages/nonexistent"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.get_message("me", "nonexistent").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            M365Error::Api { status_code, .. } => assert_eq!(status_code, Some(404)),
            e => panic!("Expected Api error with 404, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/me/messages"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.list_messages("me", None, None, None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), M365Error::RateLimit { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_event() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/users/me/events/evt_123"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        client.delete_event("me", "evt_123").await.unwrap();
    }

    #[test]
    fn test_error_is_retryable() {
        let err = M365Error::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = M365Error::InvalidConfig("bad".into());
        assert!(!err.is_retryable());

        let err = M365Error::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(err.is_retryable());
    }
}
