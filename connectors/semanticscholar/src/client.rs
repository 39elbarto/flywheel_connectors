//! Semantic Scholar API client.

use std::fmt;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SemanticScholarError, SemanticScholarResult},
    types::ApiErrorResponse,
};

/// Default Semantic Scholar API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.semanticscholar.org/graph/v1";

/// Default fields for paper search results.
pub const DEFAULT_PAPER_SEARCH_FIELDS: &str = "paperId,title,abstract,year,citationCount,authors";

/// Default fields for paper detail.
pub const DEFAULT_PAPER_DETAIL_FIELDS: &str =
    "paperId,title,abstract,year,venue,citationCount,referenceCount,authors,isOpenAccess,externalIds,fieldsOfStudy";

/// Default fields for citations/references.
pub const DEFAULT_CITATION_FIELDS: &str = "paperId,title,year,citationCount,authors";

/// Default fields for author detail.
pub const DEFAULT_AUTHOR_FIELDS: &str = "authorId,name,hIndex,citationCount,paperCount,affiliations";

/// Default fields for author papers.
pub const DEFAULT_AUTHOR_PAPERS_FIELDS: &str = "paperId,title,year,citationCount";

/// Authentication mode for the Semantic Scholar API.
#[derive(Clone)]
pub enum SemanticScholarAuth {
    /// API key header authentication.
    ApiKey(String),
    /// No authentication (free tier).
    None,
}

impl SemanticScholarAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::None => "none".to_string(),
        }
    }

    #[must_use]
    pub const fn has_key(&self) -> bool {
        matches!(self, Self::ApiKey(_))
    }
}

impl fmt::Debug for SemanticScholarAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::None => f.write_str("None"),
        }
    }
}

/// Semantic Scholar API client.
pub struct SemanticScholarClient {
    client: Client,
    auth: SemanticScholarAuth,
    base_url: String,
}

impl fmt::Debug for SemanticScholarClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticScholarClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl SemanticScholarClient {
    /// Create a new Semantic Scholar client.
    pub fn new(
        auth: SemanticScholarAuth,
        base_url: Option<&str>,
    ) -> SemanticScholarResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-semanticscholar/0.1.0 (FCP connector)")
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
            SemanticScholarAuth::ApiKey(key) => req.header("x-api-key", key),
            SemanticScholarAuth::None => req,
        }
    }

    async fn handle_response(&self, resp: Response) -> SemanticScholarResult<serde_json::Value> {
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
    ) -> SemanticScholarResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.error))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(SemanticScholarError::Unauthorized),
            403 => Err(SemanticScholarError::Forbidden),
            404 => Err(SemanticScholarError::NotFound { resource: detail }),
            429 => Err(SemanticScholarError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SemanticScholarError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> SemanticScholarResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Papers --

    /// Search for papers by keyword.
    pub async fn search_papers(
        &self,
        query: &str,
        limit: Option<i64>,
        offset: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let f = fields.unwrap_or(DEFAULT_PAPER_SEARCH_FIELDS);
        let qs = build_query(&[
            Some(("query", query.to_string())),
            Some(("fields", f.to_string())),
            limit.map(|l| ("limit", l.to_string())),
            offset.map(|o| ("offset", o.to_string())),
        ]);
        self.get(&format!("/paper/search{qs}")).await
    }

    /// Get paper details by ID.
    pub async fn get_paper(
        &self,
        paper_id: &str,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let f = fields.unwrap_or(DEFAULT_PAPER_DETAIL_FIELDS);
        let qs = build_query(&[Some(("fields", f.to_string()))]);
        self.get(&format!("/paper/{paper_id}{qs}")).await
    }

    /// Get citations of a paper.
    pub async fn get_paper_citations(
        &self,
        paper_id: &str,
        limit: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let f = fields.unwrap_or(DEFAULT_CITATION_FIELDS);
        let qs = build_query(&[
            Some(("fields", f.to_string())),
            limit.map(|l| ("limit", l.to_string())),
        ]);
        self.get(&format!("/paper/{paper_id}/citations{qs}")).await
    }

    /// Get references of a paper.
    pub async fn get_paper_references(
        &self,
        paper_id: &str,
        limit: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let f = fields.unwrap_or(DEFAULT_CITATION_FIELDS);
        let qs = build_query(&[
            Some(("fields", f.to_string())),
            limit.map(|l| ("limit", l.to_string())),
        ]);
        self.get(&format!("/paper/{paper_id}/references{qs}"))
            .await
    }

    /// Get recommended papers based on a seed paper.
    pub async fn get_paper_recommendations(
        &self,
        paper_id: &str,
        limit: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let f = fields.unwrap_or(DEFAULT_CITATION_FIELDS);
        let qs = build_query(&[
            Some(("fields", f.to_string())),
            limit.map(|l| ("limit", l.to_string())),
        ]);
        self.get(&format!("/paper/{paper_id}/recommendations{qs}"))
            .await
    }

    // -- Authors --

    /// Get author details by ID.
    pub async fn get_author(
        &self,
        author_id: &str,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let f = fields.unwrap_or(DEFAULT_AUTHOR_FIELDS);
        let qs = build_query(&[Some(("fields", f.to_string()))]);
        self.get(&format!("/author/{author_id}{qs}")).await
    }

    /// Get papers by an author.
    pub async fn get_author_papers(
        &self,
        author_id: &str,
        limit: Option<i64>,
        fields: Option<&str>,
    ) -> SemanticScholarResult<serde_json::Value> {
        let f = fields.unwrap_or(DEFAULT_AUTHOR_PAPERS_FIELDS);
        let qs = build_query(&[
            Some(("fields", f.to_string())),
            limit.map(|l| ("limit", l.to_string())),
        ]);
        self.get(&format!("/author/{author_id}/papers{qs}")).await
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
    fn auth_debug_redacts_key() {
        let auth = SemanticScholarAuth::ApiKey("secret-key-123".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-key-123"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_none() {
        let auth = SemanticScholarAuth::None;
        let dbg = format!("{auth:?}");
        assert_eq!(dbg, "None");
    }

    #[test]
    fn auth_has_key_detection() {
        let key = SemanticScholarAuth::ApiKey("key".into());
        assert!(key.has_key());
        let none = SemanticScholarAuth::None;
        assert!(!none.has_key());
    }

    #[test]
    fn auth_redacted_label_api_key() {
        let auth = SemanticScholarAuth::ApiKey("key".into());
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_none() {
        let auth = SemanticScholarAuth::None;
        assert_eq!(auth.redacted_label(), "none");
    }

    #[test]
    fn build_query_empty() {
        assert_eq!(build_query(&[None, None]), "");
    }

    #[test]
    fn build_query_one() {
        assert_eq!(
            build_query(&[Some(("query", "test".into()))]),
            "?query=test"
        );
    }

    #[test]
    fn build_query_two() {
        assert_eq!(
            build_query(&[
                Some(("query", "test".into())),
                Some(("limit", "10".into()))
            ]),
            "?query=test&limit=10"
        );
    }

    #[test]
    fn build_query_with_none_gaps() {
        assert_eq!(
            build_query(&[Some(("query", "test".into())), None, Some(("limit", "5".into()))]),
            "?query=test&limit=5"
        );
    }

    #[test]
    fn build_query_all_none() {
        assert_eq!(build_query(&[None, None, None]), "");
    }

    #[test]
    fn build_query_three_params() {
        assert_eq!(
            build_query(&[
                Some(("query", "ml".into())),
                Some(("limit", "10".into())),
                Some(("offset", "0".into())),
            ]),
            "?query=ml&limit=10&offset=0"
        );
    }

    #[test]
    fn default_base_url_has_graph_v1() {
        assert!(DEFAULT_BASE_URL.contains("graph/v1"));
    }

    #[test]
    fn default_paper_search_fields_non_empty() {
        assert!(!DEFAULT_PAPER_SEARCH_FIELDS.is_empty());
        assert!(DEFAULT_PAPER_SEARCH_FIELDS.contains("title"));
    }

    #[test]
    fn default_paper_detail_fields_non_empty() {
        assert!(!DEFAULT_PAPER_DETAIL_FIELDS.is_empty());
        assert!(DEFAULT_PAPER_DETAIL_FIELDS.contains("paperId"));
    }

    #[test]
    fn default_citation_fields_non_empty() {
        assert!(!DEFAULT_CITATION_FIELDS.is_empty());
        assert!(DEFAULT_CITATION_FIELDS.contains("paperId"));
    }

    #[test]
    fn default_author_fields_non_empty() {
        assert!(!DEFAULT_AUTHOR_FIELDS.is_empty());
        assert!(DEFAULT_AUTHOR_FIELDS.contains("authorId"));
    }

    #[test]
    fn default_author_papers_fields_non_empty() {
        assert!(!DEFAULT_AUTHOR_PAPERS_FIELDS.is_empty());
        assert!(DEFAULT_AUTHOR_PAPERS_FIELDS.contains("paperId"));
    }

    #[test]
    fn client_new_default_url() {
        let client =
            SemanticScholarClient::new(SemanticScholarAuth::None, None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SemanticScholarClient::new(
            SemanticScholarAuth::None,
            Some("https://custom.api.com/v1/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.api.com/v1");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = SemanticScholarClient::new(
            SemanticScholarAuth::None,
            Some("https://example.com/"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_format() {
        let client =
            SemanticScholarClient::new(SemanticScholarAuth::ApiKey("secret".into()), None)
                .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("SemanticScholarClient"));
        assert!(!dbg.contains("secret"));
    }
}
