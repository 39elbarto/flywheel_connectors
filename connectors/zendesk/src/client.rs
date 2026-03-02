//! Zendesk REST API client.
//!
//! Uses Basic auth with `{email}/token:{api_token}` and base64 encoding.
//! All POST/PUT bodies use JSON (`.json()`). Query params are built manually.

use base64::Engine;
use reqwest::{Client, StatusCode, header};
use tracing::{debug, warn};

use crate::error::{ZendeskError, ZendeskResult};
use crate::types::ApiErrorResponse;

/// Zendesk REST API client.
pub struct ZendeskClient {
    http: Client,
    base_url: String,
    max_retries: u32,
}

impl ZendeskClient {
    /// Create a new Zendesk client.
    ///
    /// # Arguments
    /// * `subdomain` - Zendesk subdomain (e.g. "mycompany")
    /// * `email` - User email for authentication
    /// * `api_token` - Zendesk API token
    pub fn new(subdomain: &str, email: &str, api_token: &str) -> ZendeskResult<Self> {
        let credentials = format!("{email}/token:{api_token}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-zendesk/0.1.0")
            .build()
            .map_err(ZendeskError::Http)?;

        let base_url = format!("https://{subdomain}.zendesk.com/api/v2");

        Ok(Self {
            http,
            base_url,
            max_retries: 2,
        })
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    // ── Ticket operations ─────────────────────────────────────────

    /// Create a new ticket.
    pub async fn create_ticket(
        &self,
        ticket_data: &serde_json::Value,
    ) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets.json", self.base_url);
        let body = serde_json::json!({ "ticket": ticket_data });
        let data = self.post_json(&url, &body).await?;
        Ok(data)
    }

    /// Get a ticket by ID.
    pub async fn get_ticket(&self, ticket_id: i64) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets/{ticket_id}.json", self.base_url);
        self.get(&url).await
    }

    /// Update a ticket.
    pub async fn update_ticket(
        &self,
        ticket_id: i64,
        ticket_data: &serde_json::Value,
    ) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets/{ticket_id}.json", self.base_url);
        let body = serde_json::json!({ "ticket": ticket_data });
        self.put_json(&url, &body).await
    }

    /// Delete a ticket.
    pub async fn delete_ticket(&self, ticket_id: i64) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets/{ticket_id}.json", self.base_url);
        self.delete(&url).await
    }

    // ── Search operations ─────────────────────────────────────────

    /// Search tickets using Zendesk search syntax.
    pub async fn search_tickets(
        &self,
        query: &str,
        sort_by: Option<&str>,
        sort_order: Option<&str>,
        page: Option<i64>,
        per_page: Option<i64>,
    ) -> ZendeskResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!(
            "{}/search.json?query=type:ticket {}",
            self.base_url, encoded_query
        );
        if let Some(sb) = sort_by {
            url = format!("{url}&sort_by={sb}");
        }
        if let Some(so) = sort_order {
            url = format!("{url}&sort_order={so}");
        }
        if let Some(p) = page {
            url = format!("{url}&page={p}");
        }
        if let Some(pp) = per_page {
            url = format!("{url}&per_page={pp}");
        }
        self.get(&url).await
    }

    // ── Comment operations ────────────────────────────────────────

    /// List comments on a ticket.
    pub async fn list_ticket_comments(
        &self,
        ticket_id: i64,
        sort_order: Option<&str>,
    ) -> ZendeskResult<serde_json::Value> {
        let mut url = format!("{}/tickets/{ticket_id}/comments.json", self.base_url);
        if let Some(so) = sort_order {
            url = format!("{url}?sort_order={so}");
        }
        self.get(&url).await
    }

    // ── Knowledge Base operations ─────────────────────────────────

    /// Search Help Center articles.
    pub async fn search_articles(
        &self,
        query: &str,
        locale: Option<&str>,
        category_id: Option<i64>,
        per_page: Option<i64>,
    ) -> ZendeskResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!(
            "{}/help_center/articles/search.json?query={encoded_query}",
            self.base_url
        );
        if let Some(l) = locale {
            url = format!("{url}&locale={l}");
        }
        if let Some(cid) = category_id {
            url = format!("{url}&category={cid}");
        }
        if let Some(pp) = per_page {
            url = format!("{url}&per_page={pp}");
        }
        self.get(&url).await
    }

    /// Get a Help Center article by ID.
    pub async fn get_article(
        &self,
        article_id: i64,
        locale: Option<&str>,
    ) -> ZendeskResult<serde_json::Value> {
        let url = if let Some(l) = locale {
            format!(
                "{}/help_center/{l}/articles/{article_id}.json",
                self.base_url
            )
        } else {
            format!("{}/help_center/articles/{article_id}.json", self.base_url)
        };
        self.get(&url).await
    }

    // ── User operations ───────────────────────────────────────────

    /// Search Zendesk users.
    pub async fn search_users(&self, query: &str) -> ZendeskResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let url = format!("{}/users/search.json?query={encoded_query}", self.base_url);
        self.get(&url).await
    }

    // ── Macro operations ──────────────────────────────────────────

    /// Apply a macro to a ticket.
    pub async fn apply_macro(
        &self,
        ticket_id: i64,
        macro_id: i64,
    ) -> ZendeskResult<serde_json::Value> {
        let url = format!(
            "{}/tickets/{ticket_id}/macros/{macro_id}/apply.json",
            self.base_url
        );
        // The apply macro endpoint is a GET in Zendesk API v2
        // but we use PUT to actually apply it to the ticket
        let result = self.get(&url).await?;
        Ok(result)
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> ZendeskResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> ZendeskResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn put_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> ZendeskResult<serde_json::Value> {
        self.execute(|| self.http.put(url).json(body)).await
    }

    async fn delete(&self, url: &str) -> ZendeskResult<serde_json::Value> {
        self.execute(|| self.http.delete(url)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> ZendeskResult<serde_json::Value> {
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

                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        let body = response.text().await.unwrap_or_default();
                        return Err(ZendeskError::Api {
                            message: format!("Authentication failed: {body}"),
                            status_code: Some(status.as_u16()),
                        });
                    }

                    if status == StatusCode::NOT_FOUND {
                        let body = response.text().await.unwrap_or_default();
                        return Err(ZendeskError::Api {
                            message: format!("Not found: {body}"),
                            status_code: Some(404),
                        });
                    }

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map_or(60_000, |s| s * 1000);

                        let err = ZendeskError::RateLimit {
                            retry_after_ms: retry_after,
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, "rate limited, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if status.is_server_error() {
                        let body = response.text().await.unwrap_or_default();
                        let err = ZendeskError::Api {
                            message: format!("Server error {status}: {body}"),
                            status_code: Some(status.as_u16()),
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, status = %status, "server error, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        let api_err: Option<ApiErrorResponse> =
                            serde_json::from_str(&body).ok();
                        let message = api_err
                            .as_ref()
                            .and_then(|e| {
                                e.message
                                    .clone()
                                    .or(e.description.clone())
                                    .or(e.error.clone())
                            })
                            .unwrap_or(format!("HTTP {status}: {body}"));
                        return Err(ZendeskError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                        });
                    }

                    // For DELETE with 204 No Content, return empty object
                    if status == StatusCode::NO_CONTENT {
                        return Ok(serde_json::json!({ "deleted": true }));
                    }

                    let body = response.text().await.map_err(ZendeskError::Http)?;
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(ZendeskError::Http(e));
                        continue;
                    }
                    return Err(ZendeskError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(ZendeskError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
        }))
    }
}

/// Simple percent encoding for query parameters.
fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 2);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => {
                encoded.push('%');
                encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
                encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0x0F)]));
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[fcp_async_core::runtime::test]
    async fn test_create_ticket() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v2/tickets.json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "ticket": {
                    "id": 1,
                    "subject": "Test ticket",
                    "status": "new",
                    "priority": "normal"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let ticket_data = serde_json::json!({
            "subject": "Test ticket",
            "priority": "normal"
        });
        let result = client.create_ticket(&ticket_data).await.unwrap();
        assert_eq!(result["ticket"]["id"], 1);
        assert_eq!(result["ticket"]["subject"], "Test ticket");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_ticket() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v2/tickets/123.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ticket": {
                    "id": 123,
                    "subject": "Existing ticket",
                    "status": "open"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let result = client.get_ticket(123).await.unwrap();
        assert_eq!(result["ticket"]["id"], 123);
        assert_eq!(result["ticket"]["status"], "open");
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_ticket() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/api/v2/tickets/123.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ticket": {
                    "id": 123,
                    "subject": "Updated ticket",
                    "status": "solved"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let update = serde_json::json!({ "status": "solved" });
        let result = client.update_ticket(123, &update).await.unwrap();
        assert_eq!(result["ticket"]["status"], "solved");
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_ticket() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/api/v2/tickets/123.json"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let result = client.delete_ticket(123).await.unwrap();
        assert_eq!(result["deleted"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_tickets() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    { "id": 1, "subject": "Ticket A" },
                    { "id": 2, "subject": "Ticket B" }
                ],
                "count": 2,
                "next_page": null
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let result = client
            .search_tickets("status:open", Some("created_at"), Some("desc"), None, None)
            .await
            .unwrap();
        assert_eq!(result["count"], 2);
        assert_eq!(result["results"].as_array().unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_ticket_comments() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v2/tickets/123/comments.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "comments": [
                    { "id": 1, "body": "First comment", "public": true },
                    { "id": 2, "body": "Second comment", "public": false }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let result = client.list_ticket_comments(123, None).await.unwrap();
        assert_eq!(result["comments"].as_array().unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_articles() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    { "id": 100, "title": "How to reset password" }
                ],
                "count": 1
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let result = client
            .search_articles("password reset", Some("en-us"), None, None)
            .await
            .unwrap();
        assert_eq!(result["count"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_article() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v2/help_center/articles/100.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "article": {
                    "id": 100,
                    "title": "Password Reset Guide",
                    "body": "<p>To reset your password...</p>"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let result = client.get_article(100, None).await.unwrap();
        assert_eq!(result["article"]["id"], 100);
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_users() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "users": [
                    { "id": 1, "name": "John Doe", "email": "john@example.com" }
                ],
                "count": 1
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let result = client.search_users("john@example.com").await.unwrap();
        assert_eq!(result["count"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_apply_macro() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v2/tickets/123/macros/456/apply.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "ticket": {
                        "id": 123,
                        "status": "solved"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()));

        let result = client.apply_macro(123, 456).await.unwrap();
        assert!(result["result"].is_object());
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v2/tickets/1.json"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "Couldn't authenticate you"
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "bad@example.com", "bad_token")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_ticket(1).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ZendeskError::Api { status_code: Some(401), .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v2/tickets/999.json"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": "RecordNotFound",
                "description": "Not found"
            })))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_ticket(999).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ZendeskError::Api { status_code: Some(404), .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v2/tickets/1.json"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&format!("{}/api/v2", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_ticket(1).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ZendeskError::RateLimit { .. }));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = ZendeskError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = ZendeskError::InvalidConfig("bad config".into());
        assert!(!err.is_retryable());

        let err = ZendeskError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = ZendeskError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello world"), "hello+world");
        assert_eq!(percent_encode("type:ticket"), "type:ticket");
        assert_eq!(percent_encode("status:open priority:urgent"), "status:open+priority:urgent");
    }
}
