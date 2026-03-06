use std::fmt;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{AnnasArchiveError, AnnasArchiveResult},
    types::ApiErrorResponse,
};

/// Default Anna's Archive API base URL.
pub const DEFAULT_BASE_URL: &str = "https://annas-archive.org";

/// Anna's Archive API client.
pub struct AnnasArchiveClient {
    client: Client,
    base_url: String,
}

impl fmt::Debug for AnnasArchiveClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnnasArchiveClient")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AnnasArchiveClient {
    /// Create a new Anna's Archive client.
    pub fn new(base_url: Option<&str>) -> AnnasArchiveResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-annas-archive/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    async fn handle_response(&self, resp: Response) -> AnnasArchiveResult<serde_json::Value> {
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
    ) -> AnnasArchiveResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.error).or(e.detail))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            404 => Err(AnnasArchiveError::NotFound { resource: detail }),
            429 => Err(AnnasArchiveError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            503 => Err(AnnasArchiveError::ServiceUnavailable),
            code => Err(AnnasArchiveError::Api {
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
    ) -> AnnasArchiveResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let mut req = self
            .client
            .get(&url)
            .header("Accept", "application/json");
        if let Some(q) = query {
            req = req.query(q);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Search for books and documents.
    pub async fn search(
        &self,
        query: &str,
        lang: Option<&str>,
        ext: Option<&str>,
        sort: Option<&str>,
    ) -> AnnasArchiveResult<serde_json::Value> {
        let mut q = vec![("q", query.to_string())];
        if let Some(l) = lang {
            q.push(("lang", l.to_string()));
        }
        if let Some(e) = ext {
            q.push(("ext", e.to_string()));
        }
        if let Some(s) = sort {
            q.push(("sort", s.to_string()));
        }
        self.get("/search", Some(&q)).await
    }

    /// Get book metadata by MD5 hash.
    pub async fn get_metadata(&self, md5: &str) -> AnnasArchiveResult<serde_json::Value> {
        self.get(&format!("/md5/{md5}"), None).await
    }

    /// Look up a book by ISBN.
    pub async fn lookup_isbn(&self, isbn: &str) -> AnnasArchiveResult<serde_json::Value> {
        self.get(&format!("/isbn/{isbn}"), None).await
    }

    /// Look up a book by MD5 hash.
    pub async fn lookup_md5(&self, md5: &str) -> AnnasArchiveResult<serde_json::Value> {
        self.get(&format!("/md5/{md5}"), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_base_url_correct() {
        assert_eq!(DEFAULT_BASE_URL, "https://annas-archive.org");
    }
}
