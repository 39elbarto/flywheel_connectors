//! `Reddit` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{RedditError, RedditResult},
    types::ApiErrorResponse,
};

/// Default `Reddit` OAuth API base URL.
pub const DEFAULT_BASE_URL: &str = "https://oauth.reddit.com";

/// Authentication mode for the `Reddit` API.
#[derive(Clone)]
pub enum RedditAuth {
    /// `OAuth2` Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl RedditAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for RedditAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Reddit` API client.
pub struct RedditClient {
    client: Client,
    auth: RedditAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for RedditClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedditClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl RedditClient {
    /// Create a new `Reddit` client.
    pub fn new(auth: RedditAuth, base_url: Option<&str>) -> RedditResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-reddit/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            RedditAuth::BearerToken(token) => req.bearer_auth(token),
            RedditAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> RedditResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> RedditResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(RedditError::Unauthorized),
            403 => Err(RedditError::Forbidden),
            404 => Err(RedditError::NotFound { resource: detail }),
            429 => Err(RedditError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(RedditError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> RedditResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let mut req = self.add_auth(self.client.get(&url));
        if let Some(q) = query {
            req = req.query(q);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post_form(
        &self,
        path: &str,
        body: &[(&str, &str)],
    ) -> RedditResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST form request");
        let encoded: String = body
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoded(k), urlencoded(v)))
            .collect::<Vec<_>>()
            .join("&");
        let req = self.add_auth(
            self.client
                .post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(encoded),
        );
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Search --

    /// Search posts.
    pub async fn search_posts(&self, params: &SearchParams<'_>) -> RedditResult<serde_json::Value> {
        let base = params
            .subreddit
            .map_or_else(|| "/search".to_string(), |sr| format!("/r/{sr}/search"));
        let mut q = vec![
            ("q".to_string(), params.query.to_string()),
            ("restrict_sr".to_string(), "on".to_string()),
        ];
        if let Some(s) = params.sort {
            q.push(("sort".to_string(), s.to_string()));
        }
        if let Some(t) = params.time_range {
            q.push(("t".to_string(), t.to_string()));
        }
        if let Some(l) = params.limit {
            q.push(("limit".to_string(), l.to_string()));
        }
        if let Some(a) = params.after {
            q.push(("after".to_string(), a.to_string()));
        }
        let q_refs: Vec<(&str, String)> = q.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        self.get(&base, Some(&q_refs)).await
    }

    // -- Subreddit new --

    /// List newest posts from a subreddit.
    pub async fn list_subreddit_new(
        &self,
        subreddit: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get(
            &format!("/r/{subreddit}/new"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- Post thread --

    /// Fetch a post and its comment tree.
    pub async fn get_post_thread(
        &self,
        post_fullname: &str,
        sort: Option<&str>,
        comment_limit: Option<i64>,
    ) -> RedditResult<serde_json::Value> {
        let post_id = post_fullname.strip_prefix("t3_").unwrap_or(post_fullname);
        let mut q = Vec::new();
        if let Some(s) = sort {
            q.push(("sort", s.to_string()));
        }
        if let Some(l) = comment_limit {
            q.push(("limit", l.to_string()));
        }
        self.get(
            &format!("/comments/{post_id}"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- Create post --

    /// Submit a new post.
    pub async fn create_post(
        &self,
        params: &CreatePostParams<'_>,
    ) -> RedditResult<serde_json::Value> {
        let mut form = vec![
            ("sr", params.subreddit),
            ("kind", params.kind),
            ("title", params.title),
            ("api_type", "json"),
        ];
        if let Some(t) = params.text {
            form.push(("text", t));
        }
        if let Some(u) = params.url {
            form.push(("url", u));
        }
        let nsfw_s = params.nsfw.to_string();
        let spoiler_s = params.spoiler.to_string();
        if params.nsfw {
            form.push(("nsfw", &nsfw_s));
        }
        if params.spoiler {
            form.push(("spoiler", &spoiler_s));
        }
        self.post_form("/api/submit", &form).await
    }

    // -- Create comment --

    /// Add a comment to a post or comment.
    pub async fn create_comment(
        &self,
        parent_fullname: &str,
        text: &str,
    ) -> RedditResult<serde_json::Value> {
        self.post_form(
            "/api/comment",
            &[
                ("thing_id", parent_fullname),
                ("text", text),
                ("api_type", "json"),
            ],
        )
        .await
    }

    // -- Send message --

    /// Send a private message.
    pub async fn send_message(
        &self,
        recipient: &str,
        subject: &str,
        message: &str,
    ) -> RedditResult<serde_json::Value> {
        self.post_form(
            "/api/compose",
            &[
                ("to", recipient),
                ("subject", subject),
                ("text", message),
                ("api_type", "json"),
            ],
        )
        .await
    }

    // -- Mod remove --

    /// Remove a post or comment via moderator action.
    pub async fn mod_remove(
        &self,
        thing_fullname: &str,
        spam: bool,
    ) -> RedditResult<serde_json::Value> {
        let spam_s = spam.to_string();
        self.post_form("/api/remove", &[("id", thing_fullname), ("spam", &spam_s)])
            .await
    }

    // -- Subreddit metadata --

    /// Get subreddit metadata (about page).
    pub async fn get_subreddit(&self, subreddit: &str) -> RedditResult<serde_json::Value> {
        self.get(&format!("/r/{subreddit}/about"), None).await
    }

    // -- Search subreddits --

    /// Search for subreddits by query.
    pub async fn search_subreddits(
        &self,
        query: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = vec![("q", query.to_string())];
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get("/subreddits/search", Some(&q)).await
    }

    // -- User posts --

    /// List a user's submitted post history.
    pub async fn get_user_posts(
        &self,
        username: &str,
        limit: Option<i64>,
        sort: Option<&str>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(s) = sort {
            q.push(("sort", s.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get(
            &format!("/user/{username}/submitted"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- User comments --

    /// List a user's comment history.
    pub async fn get_user_comments(
        &self,
        username: &str,
        limit: Option<i64>,
        sort: Option<&str>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(s) = sort {
            q.push(("sort", s.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get(
            &format!("/user/{username}/comments"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- Edit content --

    /// Edit the text of an existing post or comment.
    pub async fn edit_content(
        &self,
        thing_fullname: &str,
        text: &str,
    ) -> RedditResult<serde_json::Value> {
        self.post_form(
            "/api/editusertext",
            &[
                ("thing_id", thing_fullname),
                ("text", text),
                ("api_type", "json"),
            ],
        )
        .await
    }

    // -- Delete content --

    /// Delete an existing post or comment.
    pub async fn delete_content(&self, thing_fullname: &str) -> RedditResult<serde_json::Value> {
        self.post_form("/api/del", &[("id", thing_fullname)]).await
    }

    // -- Saved items --

    /// List saved items for a user.
    pub async fn get_saved(
        &self,
        username: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get(
            &format!("/user/{username}/saved"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    /// Save a post or comment.
    pub async fn save_thing(&self, thing_fullname: &str) -> RedditResult<serde_json::Value> {
        self.post_form("/api/save", &[("id", thing_fullname)]).await
    }

    /// Unsave a post or comment.
    pub async fn unsave_thing(&self, thing_fullname: &str) -> RedditResult<serde_json::Value> {
        self.post_form("/api/unsave", &[("id", thing_fullname)])
            .await
    }

    // -- Moderation queue --

    /// List the moderation queue for a subreddit.
    pub async fn get_mod_queue(
        &self,
        subreddit: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get(
            &format!("/r/{subreddit}/about/modqueue"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    /// Approve a flagged item via moderator action.
    pub async fn mod_approve(&self, thing_fullname: &str) -> RedditResult<serde_json::Value> {
        self.post_form("/api/approve", &[("id", thing_fullname)])
            .await
    }

    // -- Inbox --

    /// List inbox messages/mentions.
    pub async fn get_inbox(
        &self,
        category: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get(
            &format!("/message/{category}"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    /// Mark messages as read.
    pub async fn mark_messages_read(&self, fullnames: &[&str]) -> RedditResult<serde_json::Value> {
        let csv = fullnames.join(",");
        self.post_form("/api/read_message", &[("id", &csv)]).await
    }

    // -- Download media --

    /// Download media from an allowed `Reddit` media host.
    pub async fn download_media(
        &self,
        url: &str,
        max_bytes: Option<i64>,
    ) -> RedditResult<serde_json::Value> {
        let resp = self
            .client
            .get(url)
            .timeout(Duration::from_secs(90))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(RedditError::Api {
                status_code: status.as_u16(),
                message: format!("Media download failed: {status}"),
            });
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let body = resp.bytes().await?;
        let byte_count = i64::try_from(body.len()).unwrap_or(i64::MAX);

        if let Some(max) = max_bytes {
            if byte_count > max {
                return Err(RedditError::Api {
                    status_code: 413,
                    message: format!("Media exceeds max_bytes ({byte_count} > {max})"),
                });
            }
        }

        Ok(serde_json::json!({
            "content_type": content_type,
            "bytes": byte_count,
        }))
    }
}

/// Parameters for searching posts.
pub struct SearchParams<'a> {
    pub query: &'a str,
    pub subreddit: Option<&'a str>,
    pub sort: Option<&'a str>,
    pub time_range: Option<&'a str>,
    pub limit: Option<i64>,
    pub after: Option<&'a str>,
}

/// Parameters for creating a post.
pub struct CreatePostParams<'a> {
    pub subreddit: &'a str,
    pub kind: &'a str,
    pub title: &'a str,
    pub text: Option<&'a str>,
    pub url: Option<&'a str>,
    pub nsfw: bool,
    pub spoiler: bool,
}

/// Simple percent-encoding for query parameter values.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace('+', "%2B")
        .replace(' ', "+")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('#', "%23")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = RedditAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = RedditAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = RedditAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = RedditAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn urlencoded_basic() {
        assert_eq!(urlencoded("hello world"), "hello+world");
        assert_eq!(urlencoded("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn urlencoded_percent() {
        assert_eq!(urlencoded("100%"), "100%25");
    }

    #[test]
    fn urlencoded_plus() {
        assert_eq!(urlencoded("a+b"), "a%2Bb");
    }

    #[test]
    fn urlencoded_hash() {
        assert_eq!(urlencoded("test#anchor"), "test%23anchor");
    }

    #[test]
    fn urlencoded_empty() {
        assert_eq!(urlencoded(""), "");
    }

    #[test]
    fn urlencoded_no_special() {
        assert_eq!(urlencoded("simple"), "simple");
    }

    #[test]
    fn urlencoded_all_special() {
        let encoded = urlencoded("% + & = #");
        assert!(encoded.contains("%25"));
        assert!(encoded.contains("%2B"));
        assert!(encoded.contains("%26"));
        assert!(encoded.contains("%3D"));
        assert!(encoded.contains("%23"));
    }

    #[test]
    fn client_new_default_url() {
        let client = RedditClient::new(RedditAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = RedditClient::new(
            RedditAuth::BearerToken("tok".into()),
            Some("https://custom.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.example.com/api");
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = RedditClient::new(
            RedditAuth::BearerToken("tok".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn client_debug_redacts_bearer() {
        let client =
            RedditClient::new(RedditAuth::BearerToken("super-secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("RedditClient"));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = RedditClient::new(RedditAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn auth_debug_credential_id() {
        let id = CredentialId::new();
        let auth = RedditAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_credential_redacted_label() {
        let id = CredentialId::new();
        let auth = RedditAuth::CredentialId(id);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_clone() {
        let auth = RedditAuth::BearerToken("tok".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn search_params_struct_fields() {
        let params = SearchParams {
            query: "rust",
            subreddit: Some("programming"),
            sort: Some("new"),
            time_range: Some("week"),
            limit: Some(25),
            after: Some("t3_abc"),
        };
        assert_eq!(params.query, "rust");
        assert_eq!(params.subreddit, Some("programming"));
        assert_eq!(params.sort, Some("new"));
        assert_eq!(params.time_range, Some("week"));
        assert_eq!(params.limit, Some(25));
        assert_eq!(params.after, Some("t3_abc"));
    }

    #[test]
    fn search_params_minimal() {
        let params = SearchParams {
            query: "test",
            subreddit: None,
            sort: None,
            time_range: None,
            limit: None,
            after: None,
        };
        assert_eq!(params.query, "test");
        assert!(params.subreddit.is_none());
    }

    #[test]
    fn create_post_params_struct_fields() {
        let params = CreatePostParams {
            subreddit: "rust",
            kind: "self",
            title: "Hello",
            text: Some("Body text"),
            url: None,
            nsfw: false,
            spoiler: true,
        };
        assert_eq!(params.subreddit, "rust");
        assert_eq!(params.kind, "self");
        assert_eq!(params.title, "Hello");
        assert_eq!(params.text, Some("Body text"));
        assert!(params.url.is_none());
        assert!(!params.nsfw);
        assert!(params.spoiler);
    }

    #[test]
    fn create_post_params_link() {
        let params = CreatePostParams {
            subreddit: "pics",
            kind: "link",
            title: "Photo",
            text: None,
            url: Some("https://example.com/img.png"),
            nsfw: true,
            spoiler: false,
        };
        assert_eq!(params.url, Some("https://example.com/img.png"));
        assert!(params.nsfw);
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://oauth.reddit.com");
    }

    #[test]
    fn urlencoded_multiple_spaces() {
        assert_eq!(urlencoded("a b c d"), "a+b+c+d");
    }

    #[test]
    fn urlencoded_consecutive_specials() {
        let encoded = urlencoded("&&==");
        assert_eq!(encoded, "%26%26%3D%3D");
    }

    #[test]
    fn urlencoded_unicode_passthrough() {
        // Non-ASCII characters are not encoded by this simple encoder
        let encoded = urlencoded("hello\u{00e9}");
        assert!(encoded.contains('\u{00e9}'));
    }

    #[test]
    fn search_params_all_none_fields() {
        let params = SearchParams {
            query: "q",
            subreddit: None,
            sort: None,
            time_range: None,
            limit: None,
            after: None,
        };
        assert!(params.sort.is_none());
        assert!(params.time_range.is_none());
        assert!(params.limit.is_none());
        assert!(params.after.is_none());
    }

    #[test]
    fn create_post_params_both_text_and_url() {
        let params = CreatePostParams {
            subreddit: "test",
            kind: "self",
            title: "Both",
            text: Some("body text"),
            url: Some("https://example.com"),
            nsfw: false,
            spoiler: false,
        };
        assert!(params.text.is_some());
        assert!(params.url.is_some());
    }
}
