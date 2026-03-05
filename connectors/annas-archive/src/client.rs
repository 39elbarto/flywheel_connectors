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
    async fn get(&self, path: &str) -> AnnasArchiveResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .client
            .get(&url)
            .header("Accept", "application/json");
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
        let qs = build_query(&[
            Some(("q", query.to_string())),
            lang.map(|l| ("lang", l.to_string())),
            ext.map(|e| ("ext", e.to_string())),
            sort.map(|s| ("sort", s.to_string())),
        ]);
        self.get(&format!("/search{qs}")).await
    }

    /// Get book metadata by MD5 hash.
    pub async fn get_metadata(&self, md5: &str) -> AnnasArchiveResult<serde_json::Value> {
        self.get(&format!("/md5/{md5}")).await
    }

    /// Look up a book by ISBN.
    pub async fn lookup_isbn(&self, isbn: &str) -> AnnasArchiveResult<serde_json::Value> {
        self.get(&format!("/isbn/{isbn}")).await
    }

    /// Look up a book by MD5 hash.
    pub async fn lookup_md5(&self, md5: &str) -> AnnasArchiveResult<serde_json::Value> {
        self.get(&format!("/md5/{md5}")).await
    }
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
    fn default_base_url_correct() {
        assert_eq!(DEFAULT_BASE_URL, "https://annas-archive.org");
    }

    #[test]
    fn client_new_default_url() {
        let client = AnnasArchiveClient::new(None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = AnnasArchiveClient::new(Some("https://custom.example.com/")).unwrap();
        assert_eq!(client.base_url, "https://custom.example.com");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = AnnasArchiveClient::new(Some("https://example.com/")).unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_format() {
        let client = AnnasArchiveClient::new(None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("AnnasArchiveClient"));
        assert!(dbg.contains("annas-archive.org"));
    }

    #[test]
    fn build_query_empty() {
        assert_eq!(build_query(&[None, None]), "");
    }

    #[test]
    fn build_query_one() {
        assert_eq!(
            build_query(&[Some(("q", "test".into()))]),
            "?q=test"
        );
    }

    #[test]
    fn build_query_multiple() {
        assert_eq!(
            build_query(&[
                Some(("q", "ml".into())),
                Some(("lang", "en".into())),
                Some(("ext", "pdf".into())),
            ]),
            "?q=ml&lang=en&ext=pdf"
        );
    }

    #[test]
    fn build_query_with_none_gaps() {
        assert_eq!(
            build_query(&[Some(("q", "test".into())), None, Some(("ext", "epub".into()))]),
            "?q=test&ext=epub"
        );
    }

    #[test]
    fn build_query_all_none() {
        assert_eq!(build_query(&[None, None, None, None]), "");
    }
}
