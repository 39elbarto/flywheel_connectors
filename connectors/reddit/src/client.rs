//! `Reddit` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
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
}

impl fmt::Debug for RedditClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedditClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
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
        })
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

    async fn handle_error(&self, status: StatusCode, resp: Response) -> RedditResult<serde_json::Value> {
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
            code => Err(RedditError::Api { status_code: code, message: detail }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> RedditResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post_form(&self, path: &str, body: &[(&str, &str)]) -> RedditResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST form request");
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
        let base = params.subreddit.map_or_else(
            || "/search".to_string(),
            |sr| format!("/r/{sr}/search"),
        );
        let mut qs = format!("?q={}&restrict_sr=on", urlencoded(params.query));
        if let Some(s) = params.sort {
            write_param(&mut qs, "sort", s);
        }
        if let Some(t) = params.time_range {
            write_param(&mut qs, "t", t);
        }
        if let Some(l) = params.limit {
            write_param(&mut qs, "limit", &l.to_string());
        }
        if let Some(a) = params.after {
            write_param(&mut qs, "after", a);
        }
        self.get(&format!("{base}{qs}")).await
    }

    // -- Subreddit new --

    /// List newest posts from a subreddit.
    pub async fn list_subreddit_new(
        &self,
        subreddit: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let qs = build_query(&[
            limit.map(|l| ("limit", l.to_string())),
            after.map(|a| ("after", a.to_string())),
        ]);
        self.get(&format!("/r/{subreddit}/new{qs}")).await
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
        let qs = build_query(&[
            sort.map(|s| ("sort", s.to_string())),
            comment_limit.map(|l| ("limit", l.to_string())),
        ]);
        self.get(&format!("/comments/{post_id}{qs}")).await
    }

    // -- Create post --

    /// Submit a new post.
    pub async fn create_post(&self, params: &CreatePostParams<'_>) -> RedditResult<serde_json::Value> {
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
        self.post_form("/api/comment", &[
            ("thing_id", parent_fullname),
            ("text", text),
            ("api_type", "json"),
        ]).await
    }

    // -- Send message --

    /// Send a private message.
    pub async fn send_message(
        &self,
        recipient: &str,
        subject: &str,
        message: &str,
    ) -> RedditResult<serde_json::Value> {
        self.post_form("/api/compose", &[
            ("to", recipient),
            ("subject", subject),
            ("text", message),
            ("api_type", "json"),
        ]).await
    }

    // -- Mod remove --

    /// Remove a post or comment via moderator action.
    pub async fn mod_remove(
        &self,
        thing_fullname: &str,
        spam: bool,
    ) -> RedditResult<serde_json::Value> {
        let spam_s = spam.to_string();
        self.post_form("/api/remove", &[
            ("id", thing_fullname),
            ("spam", &spam_s),
        ]).await
    }

    // -- Download media --

    /// Download media from an allowed `Reddit` media host.
    pub async fn download_media(
        &self,
        url: &str,
        max_bytes: Option<i64>,
    ) -> RedditResult<serde_json::Value> {
        let resp = self.client.get(url)
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

fn write_param(qs: &mut String, key: &str, value: &str) {
    qs.push('&');
    qs.push_str(key);
    qs.push('=');
    qs.push_str(value);
}

fn build_query(params: &[Option<(&str, String)>]) -> String {
    let mut qs = String::new();
    let mut sep = '?';
    for param in params.iter().flatten() {
        qs.push(sep);
        qs.push_str(param.0);
        qs.push('=');
        qs.push_str(&param.1);
        sep = '&';
    }
    qs
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
    fn build_query_empty() {
        assert_eq!(build_query(&[None, None]), "");
    }

    #[test]
    fn build_query_one() {
        assert_eq!(build_query(&[Some(("limit", "25".into()))]), "?limit=25");
    }

    #[test]
    fn build_query_two() {
        assert_eq!(
            build_query(&[Some(("limit", "25".into())), Some(("after", "t3_x".into()))]),
            "?limit=25&after=t3_x"
        );
    }
}
