//! Mastodon API client.

use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop, classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{MastodonError, MastodonResult};
use crate::types::{Account, Instance, Notification, SearchResults, Status};

/// Mastodon API client with retry and runtime integration.
pub struct MastodonClient {
    client: Client,
    base_url: String,
    access_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for MastodonClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MastodonClient")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl MastodonClient {
    /// Create a new Mastodon client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        instance_url: &str,
        access_token: &str,
        retry_config: HttpRetryConfig,
    ) -> MastodonResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(MastodonError::Http)?;

        Ok(Self {
            client,
            base_url: format!("{}/api/v1", instance_url.trim_end_matches('/')),
            access_token: access_token.to_string(),
            retry_config,
        })
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Sanitize a path segment to prevent path traversal.
    fn sanitize_path_segment(segment: &str) -> MastodonResult<&str> {
        if segment.trim().is_empty() {
            return Err(MastodonError::Config(
                "Path segment must not be empty".to_string(),
            ));
        }
        let lower = segment.to_ascii_lowercase();
        if segment.contains('/')
            || segment.contains('\\')
            || segment.contains("..")
            || segment.contains('\0')
            || lower.contains("%2f")
            || lower.contains("%5c")
        {
            return Err(MastodonError::Config(
                "Path segment contains traversal characters".to_string(),
            ));
        }
        Ok(segment)
    }

    /// Execute a GET request with retry.
    async fn get_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        query: &[(String, String)],
    ) -> MastodonResult<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let query = query.to_vec();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let query = query.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, url = %url, "Mastodon GET request");
                let mut request = if token.is_empty() {
                    client.get(&url)
                } else {
                    client.get(&url).bearer_auth(&token)
                };
                if !query.is_empty() {
                    request = request.query(&query);
                }

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: MastodonError::Http(e),
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
                        error: MastodonError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 || status == 403 {
                    let text = resp.text().await.unwrap_or_default();
                    return AttemptOutcome::Terminal(MastodonError::Unauthorized(text));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Mastodon API request failed");
                    let decision = classify_http_status(status, None);
                    let err = MastodonError::Api {
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
                    Err(e) => AttemptOutcome::Terminal(MastodonError::Http(e)),
                }
            }
        })
        .await
    }

    /// Execute a POST request with retry.
    async fn post_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> MastodonResult<T> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let body = body.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, url = %url, "Mastodon POST request");
                let request = if token.is_empty() {
                    client.post(&url)
                } else {
                    client.post(&url).bearer_auth(&token)
                };
                let request = request.json(&body);

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: MastodonError::Http(e),
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
                        error: MastodonError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 || status == 403 {
                    let text = resp.text().await.unwrap_or_default();
                    return AttemptOutcome::Terminal(MastodonError::Unauthorized(text));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Mastodon POST request failed");
                    let decision = classify_http_status(status, None);
                    let err = MastodonError::Api {
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
                    Err(e) => AttemptOutcome::Terminal(MastodonError::Http(e)),
                }
            }
        })
        .await
    }

    /// Execute a DELETE request with retry.
    async fn delete_with_retry(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> MastodonResult<Status> {
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, url = %url, "Mastodon DELETE request");
                let request = if token.is_empty() {
                    client.delete(&url)
                } else {
                    client.delete(&url).bearer_auth(&token)
                };

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: MastodonError::Http(e),
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
                        error: MastodonError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 || status == 403 {
                    let text = resp.text().await.unwrap_or_default();
                    return AttemptOutcome::Terminal(MastodonError::Unauthorized(text));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Mastodon DELETE request failed");
                    let decision = classify_http_status(status, None);
                    let err = MastodonError::Api {
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

                match resp.json::<Status>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(MastodonError::Http(e)),
                }
            }
        })
        .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get home timeline.
    pub async fn get_home_timeline(
        &self,
        runtime: &ConnectorRuntime,
        limit: Option<u32>,
    ) -> MastodonResult<Vec<Status>> {
        let url = format!("{}/timelines/home", self.base_url);
        let mut query = Vec::new();
        if let Some(limit) = limit {
            query.push(("limit".into(), limit.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get public timeline.
    pub async fn get_public_timeline(
        &self,
        runtime: &ConnectorRuntime,
        local: bool,
        limit: Option<u32>,
    ) -> MastodonResult<Vec<Status>> {
        let url = format!("{}/timelines/public", self.base_url);
        let mut query = Vec::new();
        if local {
            query.push(("local".into(), "true".into()));
        }
        if let Some(limit) = limit {
            query.push(("limit".into(), limit.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Get a single status by ID.
    pub async fn get_status(
        &self,
        runtime: &ConnectorRuntime,
        id: &str,
    ) -> MastodonResult<Status> {
        let id = Self::sanitize_path_segment(id)?;
        let url = format!("{}/statuses/{}", self.base_url, id);
        self.get_with_retry(runtime, &url, &[]).await
    }

    /// Post a new status.
    pub async fn post_status(
        &self,
        runtime: &ConnectorRuntime,
        status: &str,
        visibility: Option<&str>,
        in_reply_to_id: Option<&str>,
        sensitive: bool,
        spoiler_text: Option<&str>,
    ) -> MastodonResult<Status> {
        let url = format!("{}/statuses", self.base_url);
        let mut body = serde_json::json!({
            "status": status,
        });
        if let Some(vis) = visibility {
            body["visibility"] = serde_json::json!(vis);
        }
        if let Some(reply_id) = in_reply_to_id {
            body["in_reply_to_id"] = serde_json::json!(reply_id);
        }
        if sensitive {
            body["sensitive"] = serde_json::json!(true);
        }
        if let Some(spoiler) = spoiler_text {
            body["spoiler_text"] = serde_json::json!(spoiler);
        }
        self.post_with_retry(runtime, &url, &body).await
    }

    /// Delete a status.
    pub async fn delete_status(
        &self,
        runtime: &ConnectorRuntime,
        id: &str,
    ) -> MastodonResult<Status> {
        let id = Self::sanitize_path_segment(id)?;
        let url = format!("{}/statuses/{}", self.base_url, id);
        self.delete_with_retry(runtime, &url).await
    }

    /// Favourite a status.
    pub async fn favourite_status(
        &self,
        runtime: &ConnectorRuntime,
        id: &str,
    ) -> MastodonResult<Status> {
        let id = Self::sanitize_path_segment(id)?;
        let url = format!("{}/statuses/{}/favourite", self.base_url, id);
        self.post_with_retry(runtime, &url, &serde_json::json!({}))
            .await
    }

    /// Boost (reblog) a status.
    pub async fn boost_status(
        &self,
        runtime: &ConnectorRuntime,
        id: &str,
    ) -> MastodonResult<Status> {
        let id = Self::sanitize_path_segment(id)?;
        let url = format!("{}/statuses/{}/reblog", self.base_url, id);
        self.post_with_retry(runtime, &url, &serde_json::json!({}))
            .await
    }

    /// Get an account by ID.
    pub async fn get_account(
        &self,
        runtime: &ConnectorRuntime,
        id: &str,
    ) -> MastodonResult<Account> {
        let id = Self::sanitize_path_segment(id)?;
        let url = format!("{}/accounts/{}", self.base_url, id);
        self.get_with_retry(runtime, &url, &[]).await
    }

    /// Verify the current user's credentials (account info).
    pub async fn verify_credentials(
        &self,
        runtime: &ConnectorRuntime,
    ) -> MastodonResult<Account> {
        let url = format!("{}/accounts/verify_credentials", self.base_url);
        self.get_with_retry(runtime, &url, &[]).await
    }

    /// Get notifications.
    pub async fn get_notifications(
        &self,
        runtime: &ConnectorRuntime,
        limit: Option<u32>,
    ) -> MastodonResult<Vec<Notification>> {
        let url = format!("{}/notifications", self.base_url);
        let mut query = Vec::new();
        if let Some(limit) = limit {
            query.push(("limit".into(), limit.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Search for content.
    pub async fn search(
        &self,
        runtime: &ConnectorRuntime,
        q: &str,
        search_type: Option<&str>,
        limit: Option<u32>,
    ) -> MastodonResult<SearchResults> {
        let url = format!(
            "{}/search",
            self.base_url.replace("/api/v1", "/api/v2")
        );
        let mut query = vec![("q".into(), q.to_string())];
        if let Some(t) = search_type {
            query.push(("type".into(), t.into()));
        }
        if let Some(limit) = limit {
            query.push(("limit".into(), limit.to_string()));
        }
        self.get_with_retry(runtime, &url, &query).await
    }

    /// Health check: get instance info.
    pub async fn health_check(&self) -> MastodonResult<Instance> {
        let url = format!(
            "{}/instance",
            self.base_url.replace("/api/v1", "/api/v2")
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(MastodonError::Http)?;

        let status = resp.status().as_u16();
        if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60)
                * 1000;
            return Err(MastodonError::RateLimited { retry_after_ms });
        }

        if !resp.status().is_success() {
            // Try v1 fallback
            let url_v1 = format!("{}/instance", self.base_url);
            let resp_v1 = self
                .client
                .get(&url_v1)
                .send()
                .await
                .map_err(MastodonError::Http)?;
            if resp_v1.status().is_success() {
                return resp_v1.json::<Instance>().await.map_err(MastodonError::Http);
            }
            return Err(MastodonError::Api {
                status,
                message: format!("Health check failed with HTTP {status}"),
            });
        }

        resp.json::<Instance>().await.map_err(MastodonError::Http)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn client_creation() {
        let client =
            MastodonClient::new("https://mastodon.social", "test_token", HttpRetryConfig::default());
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_formation() {
        let client = MastodonClient::new(
            "https://mastodon.social/",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.base_url().ends_with("/api/v1"));
        assert!(!client.base_url().contains("//api"));
    }

    #[test]
    fn debug_redacts_access_token() {
        let client = MastodonClient::new(
            "https://mastodon.social",
            "super_secret_token_value",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_token_value"),
            "Debug output must not contain the raw access_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for access_token"
        );
    }

    #[test]
    fn sanitize_path_valid() {
        assert!(MastodonClient::sanitize_path_segment("12345").is_ok());
        assert!(MastodonClient::sanitize_path_segment("abc_def").is_ok());
    }

    #[test]
    fn sanitize_path_invalid() {
        assert!(MastodonClient::sanitize_path_segment("../etc/passwd").is_err());
        assert!(MastodonClient::sanitize_path_segment("foo/bar").is_err());
        assert!(MastodonClient::sanitize_path_segment("").is_err());
        assert!(MastodonClient::sanitize_path_segment("foo\0bar").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/instance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "Test Instance",
                "version": "4.2.0"
            })))
            .mount(&mock_server)
            .await;

        let client = MastodonClient::new(
            &mock_server.uri(),
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let result = client.health_check().await;
        assert!(result.is_ok());
        let instance = result.unwrap();
        assert_eq!(instance.title, "Test Instance");
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_v1_fallback() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/instance"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/instance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": "test.instance",
                "title": "Test v1 Instance",
                "version": "3.5.0"
            })))
            .mount(&mock_server)
            .await;

        let client = MastodonClient::new(
            &mock_server.uri(),
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let result = client.health_check().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().title, "Test v1 Instance");
    }
}
