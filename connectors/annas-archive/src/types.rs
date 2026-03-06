use serde::{Deserialize, Serialize};

/// A search result item from Anna's Archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub md5: String,
    pub title: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub year: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub extension: String,
    #[serde(default)]
    pub filesize: u64,
    #[serde(default)]
    pub coverurl: String,
}

/// Detailed book metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookMetadata {
    pub md5: String,
    pub title: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub year: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub extension: String,
    #[serde(default)]
    pub filesize: u64,
    #[serde(default)]
    pub coverurl: String,
    #[serde(default)]
    pub isbn: String,
    #[serde(default)]
    pub doi: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub pages: String,
    #[serde(default)]
    pub source: String,
}

/// API error response from Anna's Archive.
#[derive(Debug, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_result_roundtrip() {
        let json = serde_json::json!({
            "md5": "abc123",
            "title": "Test Book",
            "author": "Author",
            "publisher": "Publisher",
            "year": "2023",
            "language": "en",
            "extension": "pdf",
            "filesize": 1000,
            "coverurl": "https://example.com/cover.jpg"
        });
        let result: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.md5, "abc123");
        assert_eq!(result.title, "Test Book");
        assert_eq!(result.author, "Author");
        assert_eq!(result.year, "2023");
        assert_eq!(result.extension, "pdf");
        assert_eq!(result.filesize, 1000);

        let roundtrip = serde_json::to_value(&result).unwrap();
        assert_eq!(roundtrip["md5"], "abc123");
        assert_eq!(roundtrip["title"], "Test Book");
    }

    #[test]
    fn search_result_defaults() {
        let json = serde_json::json!({
            "md5": "abc",
            "title": "Minimal"
        });
        let result: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.md5, "abc");
        assert_eq!(result.title, "Minimal");
        assert_eq!(result.author, "");
        assert_eq!(result.publisher, "");
        assert_eq!(result.year, "");
        assert_eq!(result.language, "");
        assert_eq!(result.extension, "");
        assert_eq!(result.filesize, 0);
        assert_eq!(result.coverurl, "");
    }

    #[test]
    fn book_metadata_roundtrip() {
        let json = serde_json::json!({
            "md5": "def456",
            "title": "Detailed Book",
            "author": "Jane Doe",
            "publisher": "O'Reilly",
            "year": "2024",
            "language": "en",
            "extension": "epub",
            "filesize": 5_000_000,
            "coverurl": "https://example.com/cover2.jpg",
            "isbn": "9780134685991",
            "doi": "10.1234/test",
            "description": "A great book about testing.",
            "pages": "450",
            "source": "libgen"
        });
        let meta: BookMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.md5, "def456");
        assert_eq!(meta.isbn, "9780134685991");
        assert_eq!(meta.doi, "10.1234/test");
        assert_eq!(meta.pages, "450");
        assert_eq!(meta.source, "libgen");
    }

    #[test]
    fn book_metadata_defaults() {
        let json = serde_json::json!({
            "md5": "ghi",
            "title": "Bare Minimum"
        });
        let meta: BookMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.isbn, "");
        assert_eq!(meta.doi, "");
        assert_eq!(meta.description, "");
        assert_eq!(meta.pages, "");
        assert_eq!(meta.source, "");
    }

    #[test]
    fn api_error_response_with_error() {
        let json = serde_json::json!({"error": "not found"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("not found"));
        assert!(err.message.is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let json = serde_json::json!({"message": "rate limited"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error.is_none());
        assert_eq!(err.message.as_deref(), Some("rate limited"));
    }

    #[test]
    fn api_error_response_with_detail() {
        let json = serde_json::json!({"detail": "bad request"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.detail.as_deref(), Some("bad request"));
    }

    #[test]
    fn api_error_response_empty() {
        let json = serde_json::json!({});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error.is_none());
        assert!(err.message.is_none());
        assert!(err.detail.is_none());
    }

    #[test]
    fn search_result_clone() {
        let result = SearchResult {
            md5: "abc".into(),
            title: "Test".into(),
            author: "Auth".into(),
            publisher: "Pub".into(),
            year: "2023".into(),
            language: "en".into(),
            extension: "pdf".into(),
            filesize: 100,
            coverurl: String::new(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.md5, result.md5);
        assert_eq!(cloned.title, result.title);
    }

    #[test]
    fn book_metadata_clone() {
        let meta = BookMetadata {
            md5: "abc".into(),
            title: "Test".into(),
            author: "Auth".into(),
            publisher: "Pub".into(),
            year: "2023".into(),
            language: "en".into(),
            extension: "pdf".into(),
            filesize: 100,
            coverurl: String::new(),
            isbn: "978".into(),
            doi: "10.1".into(),
            description: "desc".into(),
            pages: "100".into(),
            source: "libgen".into(),
        };
        let cloned = meta;
        assert_eq!(cloned.isbn, "978");
    }

    #[test]
    fn search_result_debug() {
        let result = SearchResult {
            md5: "abc".into(),
            title: "Test".into(),
            author: String::new(),
            publisher: String::new(),
            year: String::new(),
            language: String::new(),
            extension: String::new(),
            filesize: 0,
            coverurl: String::new(),
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("SearchResult"));
        assert!(dbg.contains("abc"));
    }
}
