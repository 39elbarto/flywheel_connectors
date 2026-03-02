//! YouTube Data API v3 HTTP client.

use std::fmt::Write as _;

use reqwest::{Client, StatusCode, header};
use tracing::{debug, warn};

use crate::{
    error::{YouTubeError, YouTubeResult},
    types::{
        ApiErrorResponse, CaptionListResponse, ChannelListResponse, Comment,
        CommentThreadListResponse, PlaylistItemListResponse, SearchListResponse, VideoListResponse,
    },
};

const DEFAULT_BASE_URL: &str = "https://www.googleapis.com/youtube/v3";

/// YouTube Data API v3 client.
pub struct YouTubeClient {
    http: Client,
    api_key: String,
    base_url: String,
    max_retries: u32,
}

impl YouTubeClient {
    /// Create a new YouTube client with an API key.
    pub fn new(api_key: &str) -> YouTubeResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-youtube/0.1.0")
            .build()
            .map_err(YouTubeError::Http)?;

        Ok(Self {
            http,
            api_key: api_key.to_string(),
            base_url: DEFAULT_BASE_URL.to_string(),
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

    // ── API Methods ──────────────────────────────────────────────

    /// Search for videos, channels, or playlists.
    pub async fn search(
        &self,
        query: &str,
        max_results: Option<u32>,
        result_type: Option<&str>,
    ) -> YouTubeResult<SearchListResponse> {
        let mut url = format!(
            "{}/search?part=snippet&q={}&key={}",
            self.base_url,
            urlencoding::encode(query),
            self.api_key
        );

        if let Some(max) = max_results {
            let _ = write!(url, "&maxResults={max}");
        }
        if let Some(t) = result_type {
            let _ = write!(url, "&type={}", urlencoding::encode(t));
        }

        self.get_json(&url).await
    }

    /// Get video details by ID.
    pub async fn get_video(&self, video_id: &str) -> YouTubeResult<VideoListResponse> {
        let url = format!(
            "{}/videos?part=snippet,contentDetails,statistics&id={}&key={}",
            self.base_url,
            urlencoding::encode(video_id),
            self.api_key
        );

        self.get_json(&url).await
    }

    /// Get channel details by ID.
    pub async fn get_channel(&self, channel_id: &str) -> YouTubeResult<ChannelListResponse> {
        let url = format!(
            "{}/channels?part=snippet,statistics,contentDetails&id={}&key={}",
            self.base_url,
            urlencoding::encode(channel_id),
            self.api_key
        );

        self.get_json(&url).await
    }

    /// List items in a playlist.
    pub async fn list_playlist_items(
        &self,
        playlist_id: &str,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> YouTubeResult<PlaylistItemListResponse> {
        let mut url = format!(
            "{}/playlistItems?part=snippet,contentDetails&playlistId={}&key={}",
            self.base_url,
            urlencoding::encode(playlist_id),
            self.api_key
        );

        if let Some(max) = max_results {
            let _ = write!(url, "&maxResults={max}");
        }
        if let Some(token) = page_token {
            let _ = write!(url, "&pageToken={}", urlencoding::encode(token));
        }

        self.get_json(&url).await
    }

    /// List comment threads on a video.
    pub async fn list_comments(
        &self,
        video_id: &str,
        max_results: Option<u32>,
    ) -> YouTubeResult<CommentThreadListResponse> {
        let mut url = format!(
            "{}/commentThreads?part=snippet&videoId={}&key={}",
            self.base_url,
            urlencoding::encode(video_id),
            self.api_key
        );

        if let Some(max) = max_results {
            let _ = write!(url, "&maxResults={max}");
        }

        self.get_json(&url).await
    }

    /// Post a comment on a video (requires OAuth token, not API key).
    pub async fn post_comment(&self, video_id: &str, text: &str) -> YouTubeResult<Comment> {
        let url = format!(
            "{}/commentThreads?part=snippet&key={}",
            self.base_url, self.api_key
        );

        let body = serde_json::json!({
            "snippet": {
                "videoId": video_id,
                "topLevelComment": {
                    "snippet": {
                        "textOriginal": text
                    }
                }
            }
        });

        self.post_json(&url, &body).await
    }

    /// Get available captions for a video.
    pub async fn get_captions(&self, video_id: &str) -> YouTubeResult<CaptionListResponse> {
        let url = format!(
            "{}/captions?part=snippet&videoId={}&key={}",
            self.base_url,
            urlencoding::encode(video_id),
            self.api_key
        );

        self.get_json(&url).await
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> YouTubeResult<T> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let redacted_url = redact_key(url);
            debug!(url = %redacted_url, "GET request");

            let result = self.http.get(url).send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        let text = response.text().await.map_err(YouTubeError::Http)?;
                        let parsed: T = serde_json::from_str(&text)?;
                        return Ok(parsed);
                    }

                    let err =
                        parse_error_response(status, &response.text().await.unwrap_or_default());
                    if err.is_retryable() && attempt < self.max_retries {
                        warn!(attempt, status = %status, "retryable error");
                        last_err = Some(err);
                        continue;
                    }
                    return Err(err);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(YouTubeError::Http(e));
                        continue;
                    }
                    return Err(YouTubeError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(YouTubeError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
        }))
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> YouTubeResult<T> {
        let redacted_url = redact_key(url);
        debug!(url = %redacted_url, "POST request");

        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(YouTubeError::Http)?;

        let status = response.status();
        if status.is_success() {
            let text = response.text().await.map_err(YouTubeError::Http)?;
            let parsed: T = serde_json::from_str(&text)?;
            return Ok(parsed);
        }

        let body_text = response.text().await.unwrap_or_default();
        Err(parse_error_response(status, &body_text))
    }
}

/// Parse an error response from the YouTube API.
fn parse_error_response(status: StatusCode, body: &str) -> YouTubeError {
    if let Ok(err_resp) = serde_json::from_str::<ApiErrorResponse>(body) {
        if let Some(error) = err_resp.error {
            let message = error.message.unwrap_or_else(|| format!("HTTP {status}"));
            let reason = error
                .errors
                .as_ref()
                .and_then(|e| e.first())
                .and_then(|e| e.reason.as_deref());

            if status == StatusCode::UNAUTHORIZED {
                return YouTubeError::Unauthorized;
            }

            if status == StatusCode::FORBIDDEN {
                if reason == Some("quotaExceeded") || reason == Some("dailyLimitExceeded") {
                    return YouTubeError::QuotaExceeded;
                }
                return YouTubeError::Forbidden { message };
            }

            if status == StatusCode::NOT_FOUND {
                return YouTubeError::NotFound { resource: message };
            }

            if status == StatusCode::TOO_MANY_REQUESTS {
                return YouTubeError::RateLimited {
                    retry_after_ms: 60_000,
                };
            }

            return YouTubeError::Api {
                message,
                status_code: Some(status.as_u16()),
            };
        }
    }

    YouTubeError::Api {
        message: format!("HTTP {status}: {body}"),
        status_code: Some(status.as_u16()),
    }
}

/// Redact the API key from a URL for logging.
fn redact_key(url: &str) -> String {
    if let Some(idx) = url.find("key=") {
        let end = url[idx..].find('&').map_or(url.len(), |i| idx + i);
        format!("{}key=REDACTED{}", &url[..idx], &url[end..])
    } else {
        url.to_string()
    }
}

/// Simple URL encoding helper.
mod urlencoding {
    use std::fmt::Write;

    pub fn encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    let _ = write!(encoded, "%{byte:02X}");
                }
            }
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    #[fcp_async_core::runtime::test]
    async fn test_search() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/search.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "youtube#searchListResponse",
                "etag": "abc123",
                "pageInfo": { "totalResults": 1, "resultsPerPage": 5 },
                "items": [{
                    "kind": "youtube#searchResult",
                    "etag": "def456",
                    "id": { "kind": "youtube#video", "videoId": "dQw4w9WgXcQ" },
                    "snippet": {
                        "title": "Test Video",
                        "description": "A test video",
                        "thumbnails": {}
                    }
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let results = client.search("test", Some(5), Some("video")).await.unwrap();
        assert_eq!(results.items.len(), 1);
        assert_eq!(results.items[0].id.video_id.as_deref(), Some("dQw4w9WgXcQ"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_video() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/videos.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "youtube#videoListResponse",
                "etag": "abc",
                "pageInfo": { "totalResults": 1, "resultsPerPage": 1 },
                "items": [{
                    "kind": "youtube#video",
                    "etag": "def",
                    "id": "dQw4w9WgXcQ",
                    "snippet": {
                        "title": "Rick Astley - Never Gonna Give You Up",
                        "description": "Official music video",
                        "thumbnails": {}
                    },
                    "contentDetails": {
                        "duration": "PT3M33S",
                        "definition": "hd"
                    },
                    "statistics": {
                        "viewCount": "1500000000",
                        "likeCount": "15000000"
                    }
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let result = client.get_video("dQw4w9WgXcQ").await.unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].id, "dQw4w9WgXcQ");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_channel() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/channels.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "youtube#channelListResponse",
                "etag": "abc",
                "pageInfo": { "totalResults": 1, "resultsPerPage": 1 },
                "items": [{
                    "kind": "youtube#channel",
                    "etag": "def",
                    "id": "UCuAXFkgsw1L7xaCfnd5JJOw",
                    "snippet": {
                        "title": "Rick Astley",
                        "description": "Official channel"
                    },
                    "statistics": {
                        "subscriberCount": "5000000",
                        "videoCount": "100"
                    }
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let result = client
            .get_channel("UCuAXFkgsw1L7xaCfnd5JJOw")
            .await
            .unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(
            result.items[0].snippet.as_ref().unwrap().title,
            "Rick Astley"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_playlist_items() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/playlistItems.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "youtube#playlistItemListResponse",
                "etag": "abc",
                "pageInfo": { "totalResults": 2, "resultsPerPage": 5 },
                "items": [
                    {
                        "kind": "youtube#playlistItem",
                        "etag": "d1",
                        "id": "item1",
                        "snippet": {
                            "title": "Video 1",
                            "description": "First video",
                            "position": 0
                        },
                        "contentDetails": { "videoId": "vid1" }
                    },
                    {
                        "kind": "youtube#playlistItem",
                        "etag": "d2",
                        "id": "item2",
                        "snippet": {
                            "title": "Video 2",
                            "description": "Second video",
                            "position": 1
                        },
                        "contentDetails": { "videoId": "vid2" }
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let result = client
            .list_playlist_items("PLtest", Some(5), None)
            .await
            .unwrap();
        assert_eq!(result.items.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_comments() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/commentThreads.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "youtube#commentThreadListResponse",
                "etag": "abc",
                "pageInfo": { "totalResults": 1, "resultsPerPage": 20 },
                "items": [{
                    "kind": "youtube#commentThread",
                    "etag": "def",
                    "id": "ct1",
                    "snippet": {
                        "videoId": "dQw4w9WgXcQ",
                        "topLevelComment": {
                            "id": "c1",
                            "snippet": {
                                "textDisplay": "Great video!",
                                "authorDisplayName": "TestUser",
                                "likeCount": 5
                            }
                        },
                        "totalReplyCount": 0
                    }
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let result = client.list_comments("dQw4w9WgXcQ", Some(20)).await.unwrap();
        assert_eq!(result.items.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_captions() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/captions.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "youtube#captionListResponse",
                "etag": "abc",
                "items": [{
                    "kind": "youtube#caption",
                    "etag": "def",
                    "id": "cap1",
                    "snippet": {
                        "videoId": "dQw4w9WgXcQ",
                        "language": "en",
                        "trackKind": "asr",
                        "name": "English (auto-generated)"
                    }
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let result = client.get_captions("dQw4w9WgXcQ").await.unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(
            result.items[0]
                .snippet
                .as_ref()
                .unwrap()
                .language
                .as_deref(),
            Some("en")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/videos.*"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "code": 401,
                    "message": "Invalid API key",
                    "errors": [{ "reason": "authError", "domain": "global" }]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("bad-key")
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.get_video("dQw4w9WgXcQ").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), YouTubeError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/channels.*"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": {
                    "code": 404,
                    "message": "Channel not found",
                    "errors": [{ "reason": "notFound", "domain": "youtube.channel" }]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.get_channel("UCnonexistent").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), YouTubeError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_quota_exceeded() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/search.*"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": {
                    "code": 403,
                    "message": "The request cannot be completed because you have exceeded your quota.",
                    "errors": [{ "reason": "quotaExceeded", "domain": "youtube.quota" }]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.search("test", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), YouTubeError::QuotaExceeded));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/videos.*"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": {
                    "code": 429,
                    "message": "Rate limit exceeded"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = YouTubeClient::new("test-key")
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.get_video("dQw4w9WgXcQ").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            YouTubeError::RateLimited { .. }
        ));
    }

    #[test]
    fn test_redact_key() {
        let url = "https://example.com/search?part=snippet&key=SECRET123&q=test";
        let redacted = redact_key(url);
        assert!(!redacted.contains("SECRET123"));
        assert!(redacted.contains("key=REDACTED"));
        assert!(redacted.contains("q=test"));
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("a+b"), "a%2Bb");
        assert_eq!(urlencoding::encode("simple"), "simple");
    }

    #[test]
    fn test_error_is_retryable() {
        let err = YouTubeError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = YouTubeError::Unauthorized;
        assert!(!err.is_retryable());

        let err = YouTubeError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = YouTubeError::QuotaExceeded;
        assert!(!err.is_retryable());
    }
}
