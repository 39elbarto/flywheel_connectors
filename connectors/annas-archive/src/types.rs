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

    // ── SearchResult serde edge cases ───────────────────────────────

    #[test]
    fn search_result_extra_fields_ignored() {
        let json = serde_json::json!({
            "md5": "abc",
            "title": "Test",
            "extra_field": "should be ignored",
            "another": 42
        });
        let result: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.md5, "abc");
    }

    #[test]
    fn search_result_filesize_zero() {
        let json = serde_json::json!({"md5": "a", "title": "T", "filesize": 0});
        let r: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(r.filesize, 0);
    }

    #[test]
    fn search_result_filesize_large() {
        let json = serde_json::json!({"md5": "a", "title": "T", "filesize": 4_294_967_296_u64});
        let r: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(r.filesize, 4_294_967_296);
    }

    #[test]
    fn search_result_unicode_title() {
        let json = serde_json::json!({"md5": "x", "title": "\u{1F4DA} Books"});
        let r: SearchResult = serde_json::from_value(json).unwrap();
        assert!(r.title.contains('\u{1F4DA}'));
    }

    #[test]
    fn search_result_empty_md5() {
        let json = serde_json::json!({"md5": "", "title": "T"});
        let r: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(r.md5, "");
    }

    #[test]
    fn search_result_serialize_preserves_all_fields() {
        let result = SearchResult {
            md5: "abc123".into(),
            title: "My Book".into(),
            author: "Jane".into(),
            publisher: "Pub".into(),
            year: "2024".into(),
            language: "en".into(),
            extension: "pdf".into(),
            filesize: 999,
            coverurl: "https://cover.jpg".into(),
        };
        let v = serde_json::to_value(&result).unwrap();
        assert_eq!(v["md5"], "abc123");
        assert_eq!(v["title"], "My Book");
        assert_eq!(v["author"], "Jane");
        assert_eq!(v["publisher"], "Pub");
        assert_eq!(v["year"], "2024");
        assert_eq!(v["language"], "en");
        assert_eq!(v["extension"], "pdf");
        assert_eq!(v["filesize"], 999);
        assert_eq!(v["coverurl"], "https://cover.jpg");
    }

    #[test]
    fn search_result_roundtrip_json_string() {
        let original = SearchResult {
            md5: "test".into(),
            title: "Title".into(),
            author: "Auth".into(),
            publisher: String::new(),
            year: String::new(),
            language: String::new(),
            extension: String::new(),
            filesize: 0,
            coverurl: String::new(),
        };
        let json_str = serde_json::to_string(&original).unwrap();
        let deserialized: SearchResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.md5, original.md5);
        assert_eq!(deserialized.title, original.title);
        assert_eq!(deserialized.author, original.author);
    }

    // ── BookMetadata serde edge cases ───────────────────────────────

    #[test]
    fn book_metadata_extra_fields_ignored() {
        let json = serde_json::json!({
            "md5": "abc",
            "title": "Test",
            "unknown_field": true
        });
        let meta: BookMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.md5, "abc");
    }

    #[test]
    fn book_metadata_serialize_preserves_all_fields() {
        let meta = BookMetadata {
            md5: "abc".into(),
            title: "Test".into(),
            author: "Auth".into(),
            publisher: "Pub".into(),
            year: "2024".into(),
            language: "en".into(),
            extension: "epub".into(),
            filesize: 5000,
            coverurl: "https://c.jpg".into(),
            isbn: "978-0-13-468599-1".into(),
            doi: "10.1234/test".into(),
            description: "Desc".into(),
            pages: "300".into(),
            source: "libgen".into(),
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(v["md5"], "abc");
        assert_eq!(v["isbn"], "978-0-13-468599-1");
        assert_eq!(v["doi"], "10.1234/test");
        assert_eq!(v["description"], "Desc");
        assert_eq!(v["pages"], "300");
        assert_eq!(v["source"], "libgen");
        assert_eq!(v["filesize"], 5000);
    }

    #[test]
    fn book_metadata_roundtrip_json_string() {
        let original = BookMetadata {
            md5: "m".into(),
            title: "T".into(),
            author: "A".into(),
            publisher: String::new(),
            year: String::new(),
            language: String::new(),
            extension: String::new(),
            filesize: 0,
            coverurl: String::new(),
            isbn: "978".into(),
            doi: String::new(),
            description: String::new(),
            pages: String::new(),
            source: String::new(),
        };
        let json_str = serde_json::to_string(&original).unwrap();
        let deserialized: BookMetadata = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.md5, original.md5);
        assert_eq!(deserialized.isbn, original.isbn);
    }

    #[test]
    fn book_metadata_unicode_description() {
        let json = serde_json::json!({
            "md5": "x",
            "title": "T",
            "description": "Qu\u{00e9}bec \u{2764}"
        });
        let meta: BookMetadata = serde_json::from_value(json).unwrap();
        assert!(meta.description.contains('\u{00e9}'));
        assert!(meta.description.contains('\u{2764}'));
    }

    #[test]
    fn book_metadata_debug_trait() {
        let meta = BookMetadata {
            md5: "xyz".into(),
            title: "Debug Test".into(),
            author: String::new(),
            publisher: String::new(),
            year: String::new(),
            language: String::new(),
            extension: String::new(),
            filesize: 0,
            coverurl: String::new(),
            isbn: String::new(),
            doi: String::new(),
            description: String::new(),
            pages: String::new(),
            source: String::new(),
        };
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("BookMetadata"));
        assert!(dbg.contains("xyz"));
        assert!(dbg.contains("Debug Test"));
    }

    #[test]
    fn book_metadata_clone_is_deep() {
        let original = BookMetadata {
            md5: "orig".into(),
            title: "Original".into(),
            author: "Author".into(),
            publisher: "Pub".into(),
            year: "2025".into(),
            language: "fr".into(),
            extension: "pdf".into(),
            filesize: 42,
            coverurl: "url".into(),
            isbn: "isbn".into(),
            doi: "doi".into(),
            description: "desc".into(),
            pages: "10".into(),
            source: "src".into(),
        };
        #[allow(clippy::redundant_clone)]
        let cloned = original.clone();
        assert_eq!(cloned.md5, "orig");
        assert_eq!(cloned.title, "Original");
        assert_eq!(cloned.author, "Author");
        assert_eq!(cloned.publisher, "Pub");
        assert_eq!(cloned.year, "2025");
        assert_eq!(cloned.language, "fr");
        assert_eq!(cloned.extension, "pdf");
        assert_eq!(cloned.filesize, 42);
        assert_eq!(cloned.coverurl, "url");
        assert_eq!(cloned.isbn, "isbn");
        assert_eq!(cloned.doi, "doi");
        assert_eq!(cloned.description, "desc");
        assert_eq!(cloned.pages, "10");
        assert_eq!(cloned.source, "src");
    }

    #[test]
    fn search_result_clone_all_fields() {
        let result = SearchResult {
            md5: "m".into(),
            title: "t".into(),
            author: "a".into(),
            publisher: "p".into(),
            year: "y".into(),
            language: "l".into(),
            extension: "e".into(),
            filesize: 7,
            coverurl: "c".into(),
        };
        #[allow(clippy::redundant_clone)]
        let cloned = result.clone();
        assert_eq!(cloned.md5, "m");
        assert_eq!(cloned.title, "t");
        assert_eq!(cloned.author, "a");
        assert_eq!(cloned.publisher, "p");
        assert_eq!(cloned.year, "y");
        assert_eq!(cloned.language, "l");
        assert_eq!(cloned.extension, "e");
        assert_eq!(cloned.filesize, 7);
        assert_eq!(cloned.coverurl, "c");
    }

    // ── ApiErrorResponse edge cases ─────────────────────────────────

    #[test]
    fn api_error_response_all_fields() {
        let json = serde_json::json!({
            "error": "err",
            "message": "msg",
            "detail": "det"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("err"));
        assert_eq!(err.message.as_deref(), Some("msg"));
        assert_eq!(err.detail.as_deref(), Some("det"));
    }

    #[test]
    fn api_error_response_debug() {
        let json = serde_json::json!({"error": "test"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ApiErrorResponse"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn api_error_response_null_fields() {
        let json = serde_json::json!({"error": null, "message": null, "detail": null});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error.is_none());
        assert!(err.message.is_none());
        assert!(err.detail.is_none());
    }

    #[test]
    fn api_error_response_extra_fields_ignored() {
        let json = serde_json::json!({"error": "e", "unknown": "field"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("e"));
    }

    // ── Deserialize from strings ────────────────────────────────────

    #[test]
    fn search_result_from_json_string() {
        let json_str = r#"{"md5":"abc","title":"T"}"#;
        let r: SearchResult = serde_json::from_str(json_str).unwrap();
        assert_eq!(r.md5, "abc");
        assert_eq!(r.title, "T");
        assert_eq!(r.author, "");
    }

    #[test]
    fn book_metadata_from_json_string() {
        let json_str = r#"{"md5":"xyz","title":"B","isbn":"978"}"#;
        let m: BookMetadata = serde_json::from_str(json_str).unwrap();
        assert_eq!(m.md5, "xyz");
        assert_eq!(m.isbn, "978");
    }

    #[test]
    fn api_error_from_json_string() {
        let json_str = r#"{"message":"rate limited"}"#;
        let e: ApiErrorResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(e.message.as_deref(), Some("rate limited"));
    }

    // ── Missing required fields ─────────────────────────────────────

    #[test]
    fn search_result_missing_md5_fails() {
        let json = serde_json::json!({"title": "T"});
        assert!(serde_json::from_value::<SearchResult>(json).is_err());
    }

    #[test]
    fn search_result_missing_title_fails() {
        let json = serde_json::json!({"md5": "m"});
        assert!(serde_json::from_value::<SearchResult>(json).is_err());
    }

    #[test]
    fn book_metadata_missing_md5_fails() {
        let json = serde_json::json!({"title": "T"});
        assert!(serde_json::from_value::<BookMetadata>(json).is_err());
    }

    #[test]
    fn book_metadata_missing_title_fails() {
        let json = serde_json::json!({"md5": "m"});
        assert!(serde_json::from_value::<BookMetadata>(json).is_err());
    }

    // ── Filesize boundary ───────────────────────────────────────────

    #[test]
    fn search_result_filesize_max_u64() {
        let json = serde_json::json!({"md5": "a", "title": "T", "filesize": u64::MAX});
        let r: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(r.filesize, u64::MAX);
    }

    #[test]
    fn book_metadata_filesize_max_u64() {
        let json = serde_json::json!({"md5": "a", "title": "T", "filesize": u64::MAX});
        let m: BookMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(m.filesize, u64::MAX);
    }
}
