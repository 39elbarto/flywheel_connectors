//! Twitter REST API client.

use std::time::Duration;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use tracing::{debug, instrument, warn};

/// Characters that must be percent-encoded in URL query strings.
/// See RFC 3986 Section 2.2: <https://www.rfc-editor.org/rfc/rfc3986#section-2.2>
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'&')
    .add(b'=')
    .add(b'+');

use crate::{
    config::{RateLimitInfo, TwitterConfig},
    error::{TwitterError, TwitterResult},
    oauth::OAuthSigner,
    types::{
        CreateTweetRequest, CreateTweetResponse, DeleteTweetResponse, SearchTweetsParams,
        StreamRule, StreamRulesResponse, Tweet, TwitterResponse, User,
    },
};

/// Twitter REST API client.
#[derive(Debug)]
pub struct TwitterApiClient {
    client: Client,
    base_url: String,
    oauth_signer: OAuthSigner,
    bearer_token: Option<String>,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
}

impl TwitterApiClient {
    /// Create a new API client from configuration.
    pub fn new(config: &TwitterConfig) -> TwitterResult<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(format!("fcp-twitter/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self {
            client,
            base_url: config.api_url.trim_end_matches('/').to_string(),
            oauth_signer: OAuthSigner::new(config),
            bearer_token: config.bearer_token.clone(),
            max_retries: config.retry.max_attempts,
            initial_delay_ms: config.retry.initial_delay_ms,
            max_delay_ms: config.retry.max_delay_ms,
        })
    }

    /// Make an authenticated GET request using OAuth 1.0a.
    #[instrument(skip(self))]
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> TwitterResult<T> {
        self.request_oauth("GET", endpoint, None::<&()>, &[]).await
    }

    /// Make an authenticated GET request with query parameters.
    #[instrument(skip(self, params))]
    pub async fn get_with_params<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        params: &[(String, String)],
    ) -> TwitterResult<T> {
        self.request_oauth("GET", endpoint, None::<&()>, params)
            .await
    }

    /// Make an authenticated POST request using OAuth 1.0a.
    #[instrument(skip(self, body))]
    pub async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> TwitterResult<T> {
        self.request_oauth("POST", endpoint, Some(body), &[]).await
    }

    /// Make an authenticated DELETE request using OAuth 1.0a.
    #[instrument(skip(self))]
    pub async fn delete<T: DeserializeOwned>(&self, endpoint: &str) -> TwitterResult<T> {
        self.request_oauth("DELETE", endpoint, None::<&()>, &[])
            .await
    }

    /// Make a request using app-only (Bearer) authentication.
    #[instrument(skip(self))]
    pub async fn get_app_only<T: DeserializeOwned>(&self, endpoint: &str) -> TwitterResult<T> {
        let bearer = self.bearer_token.as_ref().ok_or_else(|| {
            TwitterError::Config("Bearer token required for app-only auth".into())
        })?;

        self.request_bearer("GET", endpoint, None::<&()>, bearer)
            .await
    }

    async fn request_oauth<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&B>,
        params: &[(String, String)],
    ) -> TwitterResult<T> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(
                attempt = attempts,
                method, endpoint, "Making Twitter API request"
            );

            // Build the full URL with query params for signing (URL-encode values)
            let full_url = if params.is_empty() {
                url.clone()
            } else {
                let query = params
                    .iter()
                    .map(|(k, v)| {
                        let encoded_v = utf8_percent_encode(v, QUERY_ENCODE_SET);
                        format!("{k}={encoded_v}")
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                format!("{url}?{query}")
            };

            // Generate OAuth signature
            let auth_header = self.oauth_signer.sign(method, &url, params)?;

            let mut req = match method {
                "GET" => self.client.get(&full_url),
                "POST" => self.client.post(&url),
                "DELETE" => self.client.delete(&url),
                "PUT" => self.client.put(&url),
                _ => self.client.get(&full_url),
            };

            req = req.header("Authorization", &auth_header);

            if let Some(b) = body {
                req = req.json(b);
            }

            let result = req.send().await;

            match result {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => return Ok(data),
                    Err(e) if e.is_retryable() && attempts < self.max_retries => {
                        if let Some(retry_after) = e.retry_after() {
                            delay = retry_after;
                        }
                        warn!(
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            error = %e,
                            "Retrying Twitter API request"
                        );
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if e.is_timeout() || e.is_connect() => {
                    if attempts < self.max_retries {
                        warn!(
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            error = %e,
                            "Retrying after connection error"
                        );
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    } else {
                        return Err(TwitterError::Http(e));
                    }
                }
                Err(e) => return Err(TwitterError::Http(e)),
            }
        }
    }

    async fn request_bearer<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&B>,
        bearer: &str,
    ) -> TwitterResult<T> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut delay = Duration::from_millis(self.initial_delay_ms);
        let mut attempts = 0;

        loop {
            attempts += 1;
            debug!(
                attempt = attempts,
                method, endpoint, "Making Twitter API request (bearer auth)"
            );

            let mut req = match method {
                "GET" => self.client.get(&url),
                "POST" => self.client.post(&url),
                "DELETE" => self.client.delete(&url),
                _ => self.client.get(&url),
            };

            req = req.header("Authorization", format!("Bearer {bearer}"));

            if let Some(b) = body {
                req = req.json(b);
            }

            let result = req.send().await;

            match result {
                Ok(response) => match self.handle_response(response).await {
                    Ok(data) => return Ok(data),
                    Err(e) if e.is_retryable() && attempts < self.max_retries => {
                        if let Some(retry_after) = e.retry_after() {
                            delay = retry_after;
                        }
                        warn!(
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            error = %e,
                            "Retrying Twitter API request"
                        );
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    }
                    Err(e) => return Err(e),
                },
                Err(e) if e.is_timeout() || e.is_connect() => {
                    if attempts < self.max_retries {
                        warn!(
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            error = %e,
                            "Retrying after connection error"
                        );
                        tokio::time::sleep(delay).await;
                        delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                    } else {
                        return Err(TwitterError::Http(e));
                    }
                }
                Err(e) => return Err(TwitterError::Http(e)),
            }
        }
    }

    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> TwitterResult<T> {
        let status = response.status();

        // Extract rate limit info from headers
        let rate_limit = RateLimitInfo::from_headers(response.headers());
        if rate_limit.is_exhausted() {
            debug!(
                reset = ?rate_limit.reset,
                "Rate limit exhausted"
            );
        }

        // Handle rate limiting
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = rate_limit.time_until_reset().map_or(60, |d| d.as_secs());

            return Err(TwitterError::RateLimited { retry_after });
        }

        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(TwitterError::from)
        } else {
            // Try to parse Twitter error
            #[derive(serde::Deserialize)]
            struct TwitterErrorResponse {
                #[serde(default)]
                title: Option<String>,
                #[serde(default)]
                detail: Option<String>,
                #[serde(default, rename = "type")]
                error_type: Option<String>,
                #[serde(default)]
                status: Option<u16>,
                #[serde(default)]
                errors: Option<Vec<serde_json::Value>>,
            }

            let error_response: TwitterErrorResponse = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| TwitterErrorResponse {
                    title: Some("Unknown error".into()),
                    detail: Some(String::from_utf8_lossy(&bytes).into_owned()),
                    error_type: None,
                    status: Some(status.as_u16()),
                    errors: None,
                });

            let message = error_response
                .detail
                .or(error_response.title)
                .unwrap_or_else(|| "Unknown error".into());

            Err(TwitterError::Api {
                status: status.as_u16(),
                message,
                error_code: None,
                retry_after: rate_limit.time_until_reset().map(|d| d.as_secs()),
            })
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the authenticated user.
    pub async fn get_me(&self) -> TwitterResult<TwitterResponse<User>> {
        let params = vec![(
            "user.fields".to_string(),
            "id,name,username,description,profile_image_url,verified,created_at,public_metrics"
                .to_string(),
        )];
        self.get_with_params("/2/users/me", &params).await
    }

    /// Get a user by ID.
    pub async fn get_user(&self, user_id: &str) -> TwitterResult<TwitterResponse<User>> {
        let params = vec![(
            "user.fields".to_string(),
            "id,name,username,description,profile_image_url,verified,created_at,public_metrics"
                .to_string(),
        )];
        self.get_with_params(&format!("/2/users/{user_id}"), &params)
            .await
    }

    /// Get a user by username.
    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> TwitterResult<TwitterResponse<User>> {
        let params = vec![(
            "user.fields".to_string(),
            "id,name,username,description,profile_image_url,verified,created_at,public_metrics"
                .to_string(),
        )];
        self.get_with_params(&format!("/2/users/by/username/{username}"), &params)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tweet endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a tweet by ID.
    pub async fn get_tweet(&self, tweet_id: &str) -> TwitterResult<TwitterResponse<Tweet>> {
        let params =
            vec![
            (
                "tweet.fields".to_string(),
                "id,text,author_id,created_at,public_metrics,entities,attachments,conversation_id"
                    .to_string(),
            ),
            ("expansions".to_string(), "author_id,attachments.media_keys".to_string()),
            (
                "user.fields".to_string(),
                "id,name,username,profile_image_url".to_string(),
            ),
            (
                "media.fields".to_string(),
                "media_key,type,url,preview_image_url".to_string(),
            ),
        ];
        self.get_with_params(&format!("/2/tweets/{tweet_id}"), &params)
            .await
    }

    /// Get multiple tweets by ID.
    pub async fn get_tweets(
        &self,
        tweet_ids: &[&str],
    ) -> TwitterResult<TwitterResponse<Vec<Tweet>>> {
        let params = vec![
            ("ids".to_string(), tweet_ids.join(",")),
            (
                "tweet.fields".to_string(),
                "id,text,author_id,created_at,public_metrics,entities".to_string(),
            ),
            ("expansions".to_string(), "author_id".to_string()),
            (
                "user.fields".to_string(),
                "id,name,username,profile_image_url".to_string(),
            ),
        ];
        self.get_with_params("/2/tweets", &params).await
    }

    /// Create a new tweet.
    pub async fn create_tweet(
        &self,
        request: &CreateTweetRequest,
    ) -> TwitterResult<CreateTweetResponse> {
        self.post("/2/tweets", request).await
    }

    /// Delete a tweet.
    pub async fn delete_tweet(&self, tweet_id: &str) -> TwitterResult<DeleteTweetResponse> {
        self.delete(&format!("/2/tweets/{tweet_id}")).await
    }

    /// Get user's timeline.
    pub async fn get_user_tweets(
        &self,
        user_id: &str,
        max_results: Option<u32>,
        pagination_token: Option<&str>,
    ) -> TwitterResult<TwitterResponse<Vec<Tweet>>> {
        let mut params = vec![
            (
                "tweet.fields".to_string(),
                "id,text,author_id,created_at,public_metrics,entities".to_string(),
            ),
            (
                "max_results".to_string(),
                max_results.unwrap_or(10).to_string(),
            ),
        ];
        if let Some(token) = pagination_token {
            params.push(("pagination_token".to_string(), token.to_string()));
        }

        self.get_with_params(&format!("/2/users/{user_id}/tweets"), &params)
            .await
    }

    /// Get user's mentions.
    pub async fn get_user_mentions(
        &self,
        user_id: &str,
        max_results: Option<u32>,
        pagination_token: Option<&str>,
    ) -> TwitterResult<TwitterResponse<Vec<Tweet>>> {
        let mut params = vec![
            (
                "tweet.fields".to_string(),
                "id,text,author_id,created_at,public_metrics,entities".to_string(),
            ),
            ("expansions".to_string(), "author_id".to_string()),
            (
                "user.fields".to_string(),
                "id,name,username,profile_image_url".to_string(),
            ),
            (
                "max_results".to_string(),
                max_results.unwrap_or(10).to_string(),
            ),
        ];
        if let Some(token) = pagination_token {
            params.push(("pagination_token".to_string(), token.to_string()));
        }

        self.get_with_params(&format!("/2/users/{user_id}/mentions"), &params)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Search endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Search recent tweets (last 7 days).
    pub async fn search_recent(
        &self,
        search_params: &SearchTweetsParams,
    ) -> TwitterResult<TwitterResponse<Vec<Tweet>>> {
        let mut params = vec![
            ("query".to_string(), search_params.query.clone()),
            (
                "tweet.fields".to_string(),
                search_params
                    .tweet_fields
                    .clone()
                    .unwrap_or_else(|| {
                        vec![
                            "id".to_string(),
                            "text".to_string(),
                            "author_id".to_string(),
                            "created_at".to_string(),
                            "public_metrics".to_string(),
                            "entities".to_string(),
                        ]
                    })
                    .join(","),
            ),
            (
                "max_results".to_string(),
                search_params.max_results.unwrap_or(10).to_string(),
            ),
        ];

        if let Some(ref token) = search_params.next_token {
            params.push(("next_token".to_string(), token.clone()));
        }
        if let Some(ref since_id) = search_params.since_id {
            params.push(("since_id".to_string(), since_id.clone()));
        }
        if let Some(ref until_id) = search_params.until_id {
            params.push(("until_id".to_string(), until_id.clone()));
        }
        if let Some(ref start_time) = search_params.start_time {
            params.push(("start_time".to_string(), start_time.clone()));
        }
        if let Some(ref end_time) = search_params.end_time {
            params.push(("end_time".to_string(), end_time.clone()));
        }
        if let Some(ref sort_order) = search_params.sort_order {
            params.push(("sort_order".to_string(), sort_order.clone()));
        }
        if let Some(ref expansions) = search_params.expansions {
            params.push(("expansions".to_string(), expansions.join(",")));
        }
        if let Some(ref user_fields) = search_params.user_fields {
            params.push(("user.fields".to_string(), user_fields.join(",")));
        }

        self.get_with_params("/2/tweets/search/recent", &params)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stream rules endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get current stream rules.
    pub async fn get_stream_rules(&self) -> TwitterResult<StreamRulesResponse> {
        let bearer = self
            .bearer_token
            .as_ref()
            .ok_or_else(|| TwitterError::Config("Bearer token required for stream rules".into()))?;

        self.request_bearer("GET", "/2/tweets/search/stream/rules", None::<&()>, bearer)
            .await
    }

    /// Add stream rules.
    pub async fn add_stream_rules(
        &self,
        rules: &[StreamRule],
    ) -> TwitterResult<StreamRulesResponse> {
        #[derive(serde::Serialize)]
        struct AddRulesRequest<'a> {
            add: &'a [StreamRule],
        }

        let bearer = self
            .bearer_token
            .as_ref()
            .ok_or_else(|| TwitterError::Config("Bearer token required for stream rules".into()))?;

        let body = AddRulesRequest { add: rules };
        self.request_bearer("POST", "/2/tweets/search/stream/rules", Some(&body), bearer)
            .await
    }

    /// Delete stream rules by ID.
    pub async fn delete_stream_rules(
        &self,
        rule_ids: &[&str],
    ) -> TwitterResult<StreamRulesResponse> {
        #[derive(serde::Serialize)]
        struct DeleteRulesRequest<'a> {
            delete: DeleteIds<'a>,
        }

        #[derive(serde::Serialize)]
        struct DeleteIds<'a> {
            ids: &'a [&'a str],
        }

        let bearer = self
            .bearer_token
            .as_ref()
            .ok_or_else(|| TwitterError::Config("Bearer token required for stream rules".into()))?;

        let body = DeleteRulesRequest {
            delete: DeleteIds { ids: rule_ids },
        };

        self.request_bearer("POST", "/2/tweets/search/stream/rules", Some(&body), bearer)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_testkit::LogCapture;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header_exists, method, path},
    };

    /// Create a test config pointing to the mock server.
    fn test_config(mock_server: &MockServer) -> TwitterConfig {
        TwitterConfig {
            consumer_key: "test_consumer_key".into(),
            consumer_secret: "test_consumer_secret".into(),
            access_token: "test_access_token".into(),
            access_token_secret: "test_access_token_secret".into(),
            bearer_token: Some("test_bearer_token".into()),
            api_url: mock_server.uri(),
            retry: crate::config::RetryConfig {
                max_attempts: 1,
                initial_delay_ms: 10,
                max_delay_ms: 100,
                jitter: 0.0,
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_get_me_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/2/users/me"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "id": "123456789",
                    "name": "Test User",
                    "username": "testuser"
                }
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = TwitterApiClient::new(&config).unwrap();

        let response = client.get_me().await.unwrap();
        let user = response.data.unwrap();
        assert_eq!(user.id, "123456789");
        assert_eq!(user.username, "testuser");
    }

    #[tokio::test]
    async fn test_create_tweet_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/2/tweets"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "data": {
                    "id": "1234567890",
                    "text": "Hello, Twitter!"
                }
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = TwitterApiClient::new(&config).unwrap();

        let request = CreateTweetRequest {
            text: Some("Hello, Twitter!".into()),
            ..Default::default()
        };

        let response = client.create_tweet(&request).await.unwrap();
        assert_eq!(response.data.id, "1234567890");
        assert_eq!(response.data.text, "Hello, Twitter!");
    }

    #[tokio::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/2/users/me"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("x-rate-limit-reset", "1700000000")
                    .set_body_json(serde_json::json!({
                        "title": "Too Many Requests",
                        "detail": "Too Many Requests",
                        "type": "about:blank",
                        "status": 429
                    })),
            )
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = TwitterApiClient::new(&config).unwrap();

        let result = client.get_me().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TwitterError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn test_search_recent_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/2/tweets/search/recent"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "id": "1234",
                        "text": "Hello world"
                    },
                    {
                        "id": "5678",
                        "text": "Test tweet"
                    }
                ],
                "meta": {
                    "result_count": 2,
                    "newest_id": "1234",
                    "oldest_id": "5678"
                }
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = TwitterApiClient::new(&config).unwrap();

        let params = SearchTweetsParams {
            query: "hello".into(),
            max_results: Some(10),
            ..Default::default()
        };

        let response = client.search_recent(&params).await.unwrap();
        let tweets = response.data.unwrap();
        assert_eq!(tweets.len(), 2);
        assert_eq!(tweets[0].text, "Hello world");
    }

    #[tokio::test]
    async fn test_delete_tweet_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/2/tweets/1234567890"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "deleted": true
                }
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = TwitterApiClient::new(&config).unwrap();

        let response = client.delete_tweet("1234567890").await.unwrap();
        assert!(response.data.deleted);
    }

    #[tokio::test]
    async fn test_error_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/2/users/me"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "title": "Unauthorized",
                "detail": "Unauthorized",
                "type": "about:blank",
                "status": 401
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = TwitterApiClient::new(&config).unwrap();

        let result = client.get_me().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TwitterError::Api { status: 401, .. }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_logs_redact_credentials_and_tweet_text() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/2/tweets"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "data": {
                    "id": "1234567890",
                    "text": "Hello, Twitter!"
                }
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server);
        let client = TwitterApiClient::new(&config).unwrap();

        let secret_tweet = "TopSecretTweet";
        let request = CreateTweetRequest {
            text: Some(secret_tweet.into()),
            ..Default::default()
        };

        let _ = client.create_tweet(&request).await.unwrap();

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs to be captured"
        );
        assert!(!logs.contains("test_consumer_key"));
        assert!(!logs.contains("test_consumer_secret"));
        assert!(!logs.contains("test_access_token"));
        assert!(!logs.contains("test_access_token_secret"));
        assert!(!logs.contains("test_bearer_token"));
        assert!(!logs.contains(secret_tweet));
    }
}
