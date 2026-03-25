use serde::{Deserialize, Serialize};

// ── Scrape ──

/// Request body for POST /v1/scrape.
#[derive(Debug, Clone, Serialize)]
pub struct ScrapeRequest {
    pub url: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub formats: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_main_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

impl ScrapeRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            formats: vec!["markdown".into()],
            only_main_content: None,
            include_tags: None,
            exclude_tags: None,
            wait_for: None,
            timeout: None,
        }
    }
}

/// Response from POST /v1/scrape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScrapeResponse {
    pub success: bool,
    #[serde(default)]
    pub data: Option<ScrapeData>,
    #[serde(default)]
    pub error: Option<String>,
}

/// The data payload inside a successful scrape response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScrapeData {
    #[serde(default)]
    pub markdown: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub raw_html: Option<String>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<ScrapeMetadata>,
}

/// Metadata returned from a scrape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScrapeMetadata {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default, rename = "sourceURL")]
    pub source_url: Option<String>,
    #[serde(default, rename = "statusCode")]
    pub status_code: Option<u16>,
}

// ── Crawl ──

/// Request body for POST /v1/crawl.
#[derive(Debug, Clone, Serialize)]
pub struct CrawlRequest {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_paths: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub include_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_external_links: Option<bool>,
}

impl CrawlRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            limit: None,
            max_depth: None,
            exclude_paths: Vec::new(),
            include_paths: Vec::new(),
            allow_external_links: None,
        }
    }
}

/// Response from POST /v1/crawl (async job start).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrawlStartResponse {
    pub success: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Response from GET /v1/crawl/{id} (crawl status).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrawlStatusResponse {
    pub status: String,
    #[serde(default)]
    pub total: Option<u32>,
    #[serde(default)]
    pub completed: Option<u32>,
    #[serde(default, rename = "creditsUsed")]
    pub credits_used: Option<u32>,
    #[serde(default, rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub data: Option<Vec<CrawlPageData>>,
    #[serde(default)]
    pub error: Option<String>,
}

/// A single page result inside a crawl status response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrawlPageData {
    #[serde(default)]
    pub markdown: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<ScrapeMetadata>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrape_request_defaults() {
        let req = ScrapeRequest::new("https://example.com");
        assert_eq!(req.url, "https://example.com");
        assert_eq!(req.formats, vec!["markdown"]);
        assert!(req.only_main_content.is_none());
    }

    #[test]
    fn scrape_request_serializes() {
        let req = ScrapeRequest::new("https://example.com");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["url"], "https://example.com");
        assert_eq!(json["formats"][0], "markdown");
        // optional fields should be absent
        assert!(json.get("only_main_content").is_none());
    }

    #[test]
    fn scrape_response_deserializes() {
        let json = serde_json::json!({
            "success": true,
            "data": {
                "markdown": "# Hello",
                "metadata": {
                    "title": "Hello",
                    "statusCode": 200
                }
            }
        });
        let resp: ScrapeResponse = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        let data = resp.data.unwrap();
        assert_eq!(data.markdown.unwrap(), "# Hello");
        let meta = data.metadata.unwrap();
        assert_eq!(meta.title.unwrap(), "Hello");
        assert_eq!(meta.status_code.unwrap(), 200);
    }

    #[test]
    fn scrape_response_error_deserializes() {
        let json = serde_json::json!({
            "success": false,
            "error": "URL is not valid"
        });
        let resp: ScrapeResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.error.unwrap(), "URL is not valid");
    }

    #[test]
    fn crawl_request_defaults() {
        let req = CrawlRequest::new("https://example.com");
        assert_eq!(req.url, "https://example.com");
        assert!(req.limit.is_none());
        assert!(req.max_depth.is_none());
    }

    #[test]
    fn crawl_request_serializes_minimal() {
        let req = CrawlRequest::new("https://example.com");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["url"], "https://example.com");
        // empty vecs should not be present
        assert!(json.get("exclude_paths").is_none());
        assert!(json.get("include_paths").is_none());
    }

    #[test]
    fn crawl_start_response_deserializes() {
        let json = serde_json::json!({
            "success": true,
            "id": "crawl-abc-123",
            "url": "https://api.firecrawl.dev/v1/crawl/crawl-abc-123"
        });
        let resp: CrawlStartResponse = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.id.unwrap(), "crawl-abc-123");
    }

    #[test]
    fn crawl_status_response_completed() {
        let json = serde_json::json!({
            "status": "completed",
            "total": 5,
            "completed": 5,
            "creditsUsed": 5,
            "expiresAt": "2025-04-01T00:00:00Z",
            "data": [
                {
                    "markdown": "# Page 1",
                    "metadata": { "title": "Page 1", "sourceURL": "https://example.com/p1" }
                }
            ]
        });
        let resp: CrawlStatusResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status, "completed");
        assert_eq!(resp.total.unwrap(), 5);
        assert_eq!(resp.completed.unwrap(), 5);
        let pages = resp.data.unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].markdown.as_deref().unwrap(), "# Page 1");
    }

    #[test]
    fn crawl_status_response_scraping() {
        let json = serde_json::json!({
            "status": "scraping",
            "total": 10,
            "completed": 3
        });
        let resp: CrawlStatusResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status, "scraping");
        assert_eq!(resp.completed.unwrap(), 3);
        assert!(resp.data.is_none());
    }

    #[test]
    fn crawl_request_with_options() {
        let mut req = CrawlRequest::new("https://example.com");
        req.limit = Some(50);
        req.max_depth = Some(3);
        req.exclude_paths = vec!["/admin/*".into()];
        req.include_paths = vec!["/blog/*".into()];
        req.allow_external_links = Some(false);

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["limit"], 50);
        assert_eq!(json["max_depth"], 3);
        assert_eq!(json["exclude_paths"][0], "/admin/*");
        assert_eq!(json["include_paths"][0], "/blog/*");
        assert_eq!(json["allow_external_links"], false);
    }
}
