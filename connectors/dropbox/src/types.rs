//! Types for the Dropbox API.

#![allow(clippy::doc_markdown)]

//! Dropbox API types.

use serde::{Deserialize, Serialize};

/// Dropbox file metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    #[serde(rename = ".tag")]
    pub tag: Option<String>,
    pub name: String,
    pub path_lower: Option<String>,
    pub path_display: Option<String>,
    pub id: Option<String>,
    pub client_modified: Option<String>,
    pub server_modified: Option<String>,
    pub rev: Option<String>,
    pub size: Option<u64>,
    pub content_hash: Option<String>,
    pub is_downloadable: Option<bool>,
}

/// Dropbox folder metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderMetadata {
    #[serde(rename = ".tag")]
    pub tag: Option<String>,
    pub name: String,
    pub path_lower: Option<String>,
    pub path_display: Option<String>,
    pub id: Option<String>,
}

/// Result from list_folder API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListFolderResult {
    pub entries: Vec<serde_json::Value>,
    pub cursor: Option<String>,
    pub has_more: Option<bool>,
}

/// Deleted metadata (returned from delete_v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedMetadata {
    #[serde(rename = ".tag")]
    pub tag: Option<String>,
    pub name: String,
    pub path_lower: Option<String>,
    pub path_display: Option<String>,
}

/// Shared link metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedLinkMetadata {
    #[serde(rename = ".tag")]
    pub tag: Option<String>,
    pub url: String,
    pub name: Option<String>,
    pub path_lower: Option<String>,
    pub link_permissions: Option<serde_json::Value>,
}

/// Result from list_shared_links API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSharedLinksResult {
    pub links: Vec<serde_json::Value>,
    pub has_more: Option<bool>,
    pub cursor: Option<String>,
}

/// Dropbox API error response.
/// Format: `{"error_summary": "path/not_found/...", "error": {".tag": "path", "path": {".tag": "not_found"}}}`
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error_summary: Option<String>,
    pub error: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn file_metadata_roundtrip() {
        let f: FileMetadata = serde_json::from_value(json!({
            ".tag": "file",
            "name": "report.pdf",
            "path_lower": "/documents/report.pdf",
            "path_display": "/Documents/report.pdf",
            "id": "id:abc123",
            "client_modified": "2026-01-15T10:00:00Z",
            "server_modified": "2026-01-15T10:00:01Z",
            "rev": "015a06a2bc5d90000000001",
            "size": 2048,
            "content_hash": "e3b0c44298fc1c149afbf4c8996fb924",
            "is_downloadable": true,
        }))
        .unwrap();
        assert_eq!(f.name, "report.pdf");
        assert_eq!(f.tag, Some("file".into()));
        assert_eq!(f.size, Some(2048));
        assert_eq!(f.path_display, Some("/Documents/report.pdf".into()));
        let re = serde_json::to_value(&f).unwrap();
        assert_eq!(re["name"], "report.pdf");
    }

    #[test]
    fn file_metadata_minimal() {
        let f: FileMetadata = serde_json::from_value(json!({"name": "x.txt"})).unwrap();
        assert_eq!(f.name, "x.txt");
        assert!(f.tag.is_none());
        assert!(f.size.is_none());
        assert!(f.id.is_none());
        assert!(f.path_lower.is_none());
    }

    #[test]
    fn file_metadata_with_hash() {
        let f: FileMetadata = serde_json::from_value(json!({
            "name": "doc.txt",
            "content_hash": "abc123def456",
        }))
        .unwrap();
        assert_eq!(f.content_hash, Some("abc123def456".into()));
    }

    #[test]
    fn file_metadata_not_downloadable() {
        let f: FileMetadata = serde_json::from_value(json!({
            "name": "restricted.pdf",
            "is_downloadable": false,
        }))
        .unwrap();
        assert_eq!(f.is_downloadable, Some(false));
    }

    #[test]
    fn folder_metadata_roundtrip() {
        let f: FolderMetadata = serde_json::from_value(json!({
            ".tag": "folder",
            "name": "Documents",
            "path_lower": "/documents",
            "path_display": "/Documents",
            "id": "id:folder123",
        }))
        .unwrap();
        assert_eq!(f.name, "Documents");
        assert_eq!(f.tag, Some("folder".into()));
        assert_eq!(f.id, Some("id:folder123".into()));
        let re = serde_json::to_value(&f).unwrap();
        assert_eq!(re["name"], "Documents");
    }

    #[test]
    fn folder_metadata_minimal() {
        let f: FolderMetadata = serde_json::from_value(json!({"name": "My Folder"})).unwrap();
        assert_eq!(f.name, "My Folder");
        assert!(f.tag.is_none());
        assert!(f.path_lower.is_none());
    }

    #[test]
    fn list_folder_result_roundtrip() {
        let r: ListFolderResult = serde_json::from_value(json!({
            "entries": [
                {".tag": "file", "name": "a.txt", "path_display": "/a.txt"},
                {".tag": "folder", "name": "Docs", "path_display": "/Docs"},
            ],
            "cursor": "cursor123",
            "has_more": true,
        }))
        .unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.cursor, Some("cursor123".into()));
        assert_eq!(r.has_more, Some(true));
    }

    #[test]
    fn list_folder_result_empty() {
        let r: ListFolderResult = serde_json::from_value(json!({
            "entries": [],
            "has_more": false,
        }))
        .unwrap();
        assert!(r.entries.is_empty());
        assert_eq!(r.has_more, Some(false));
    }

    #[test]
    fn list_folder_result_no_cursor() {
        let r: ListFolderResult = serde_json::from_value(json!({
            "entries": [{"name": "x.txt"}],
        }))
        .unwrap();
        assert!(r.cursor.is_none());
        assert_eq!(r.entries.len(), 1);
    }

    #[test]
    fn deleted_metadata_roundtrip() {
        let d: DeletedMetadata = serde_json::from_value(json!({
            ".tag": "deleted",
            "name": "old_file.txt",
            "path_lower": "/old_file.txt",
            "path_display": "/old_file.txt",
        }))
        .unwrap();
        assert_eq!(d.name, "old_file.txt");
        assert_eq!(d.tag, Some("deleted".into()));
    }

    #[test]
    fn deleted_metadata_minimal() {
        let d: DeletedMetadata = serde_json::from_value(json!({"name": "gone.txt"})).unwrap();
        assert_eq!(d.name, "gone.txt");
        assert!(d.tag.is_none());
        assert!(d.path_lower.is_none());
    }

    #[test]
    fn shared_link_metadata_roundtrip() {
        let s: SharedLinkMetadata = serde_json::from_value(json!({
            ".tag": "file",
            "url": "https://www.dropbox.com/s/abc123/report.pdf?dl=0",
            "name": "report.pdf",
            "path_lower": "/documents/report.pdf",
            "link_permissions": {"resolved_visibility": {".tag": "public"}},
        }))
        .unwrap();
        assert_eq!(s.url, "https://www.dropbox.com/s/abc123/report.pdf?dl=0");
        assert_eq!(s.name, Some("report.pdf".into()));
        assert!(s.link_permissions.is_some());
    }

    #[test]
    fn shared_link_metadata_minimal() {
        let s: SharedLinkMetadata =
            serde_json::from_value(json!({"url": "https://example.com/link"})).unwrap();
        assert_eq!(s.url, "https://example.com/link");
        assert!(s.name.is_none());
        assert!(s.tag.is_none());
    }

    #[test]
    fn list_shared_links_result_roundtrip() {
        let r: ListSharedLinksResult = serde_json::from_value(json!({
            "links": [
                {"url": "https://www.dropbox.com/s/abc/file1.pdf?dl=0", ".tag": "file"},
                {"url": "https://www.dropbox.com/s/def/file2.pdf?dl=0", ".tag": "file"},
            ],
            "has_more": false,
            "cursor": "link_cursor_abc",
        }))
        .unwrap();
        assert_eq!(r.links.len(), 2);
        assert_eq!(r.has_more, Some(false));
        assert_eq!(r.cursor, Some("link_cursor_abc".into()));
    }

    #[test]
    fn list_shared_links_result_empty() {
        let r: ListSharedLinksResult = serde_json::from_value(json!({
            "links": [],
            "has_more": false,
        }))
        .unwrap();
        assert!(r.links.is_empty());
    }

    #[test]
    fn list_shared_links_result_no_cursor() {
        let r: ListSharedLinksResult = serde_json::from_value(json!({
            "links": [{"url": "https://example.com"}],
        }))
        .unwrap();
        assert!(r.cursor.is_none());
    }

    #[test]
    fn api_error_response_full() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error_summary": "path/not_found/.",
            "error": {
                ".tag": "path",
                "path": {".tag": "not_found"}
            }
        }))
        .unwrap();
        assert_eq!(e.error_summary, Some("path/not_found/.".into()));
        assert!(e.error.is_some());
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error_summary.is_none());
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_summary_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error_summary": "other/error"
        }))
        .unwrap();
        assert_eq!(e.error_summary, Some("other/error".into()));
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_with_nested_tag() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error_summary": "path/malformed_path/.",
            "error": {
                ".tag": "path",
                "path": {".tag": "malformed_path", "malformed_path": "/bad\\path"}
            }
        }))
        .unwrap();
        assert!(e.error_summary.unwrap().contains("malformed_path"));
    }

    #[test]
    fn file_metadata_serialize_preserves_tag_rename() {
        let f = FileMetadata {
            tag: Some("file".into()),
            name: "test.txt".into(),
            path_lower: None,
            path_display: None,
            id: None,
            client_modified: None,
            server_modified: None,
            rev: None,
            size: None,
            content_hash: None,
            is_downloadable: None,
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v[".tag"], "file");
        assert!(v.get("tag").is_none());
    }

    #[test]
    fn folder_metadata_serialize_preserves_tag_rename() {
        let f = FolderMetadata {
            tag: Some("folder".into()),
            name: "Test".into(),
            path_lower: None,
            path_display: None,
            id: None,
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v[".tag"], "folder");
        assert!(v.get("tag").is_none());
    }

    #[test]
    fn shared_link_serialize_preserves_tag() {
        let s = SharedLinkMetadata {
            tag: Some("file".into()),
            url: "https://example.com".into(),
            name: None,
            path_lower: None,
            link_permissions: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v[".tag"], "file");
    }

    #[test]
    fn file_metadata_with_rev() {
        let f: FileMetadata = serde_json::from_value(json!({
            "name": "doc.txt",
            "rev": "015a06a2bc5d90000000001",
        }))
        .unwrap();
        assert_eq!(f.rev, Some("015a06a2bc5d90000000001".into()));
    }

    #[test]
    fn list_folder_result_many_entries() {
        let entries: Vec<serde_json::Value> = (0..50)
            .map(|i| json!({".tag": "file", "name": format!("file_{i}.txt")}))
            .collect();
        let r: ListFolderResult = serde_json::from_value(json!({
            "entries": entries,
            "has_more": true,
            "cursor": "big_cursor",
        }))
        .unwrap();
        assert_eq!(r.entries.len(), 50);
        assert_eq!(r.has_more, Some(true));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn file_metadata_clone() {
        let f = FileMetadata {
            tag: Some("file".into()),
            name: "test.txt".into(),
            path_lower: None,
            path_display: None,
            id: None,
            client_modified: None,
            server_modified: None,
            rev: None,
            size: Some(42),
            content_hash: None,
            is_downloadable: None,
        };
        let f2 = f.clone();
        assert_eq!(f2.name, "test.txt");
        assert_eq!(f2.size, Some(42));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn folder_metadata_clone() {
        let f = FolderMetadata {
            tag: Some("folder".into()),
            name: "Test".into(),
            path_lower: None,
            path_display: None,
            id: None,
        };
        let f2 = f.clone();
        assert_eq!(f2.name, "Test");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn list_folder_result_clone() {
        let r = ListFolderResult {
            entries: vec![json!({"name": "a"})],
            cursor: Some("cur".into()),
            has_more: Some(false),
        };
        let r2 = r.clone();
        assert_eq!(r2.entries.len(), 1);
        assert_eq!(r2.cursor, Some("cur".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn deleted_metadata_clone() {
        let d = DeletedMetadata {
            tag: Some("deleted".into()),
            name: "gone.txt".into(),
            path_lower: None,
            path_display: None,
        };
        let d2 = d.clone();
        assert_eq!(d2.name, "gone.txt");
    }

    #[test]
    fn file_metadata_debug_format() {
        let f: FileMetadata = serde_json::from_value(json!({"name": "x.txt"})).unwrap();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("FileMetadata"));
        assert!(dbg.contains("x.txt"));
    }

    #[test]
    fn folder_metadata_debug_format() {
        let f: FolderMetadata = serde_json::from_value(json!({"name": "Docs"})).unwrap();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("FolderMetadata"));
    }

    #[test]
    fn shared_link_metadata_clone() {
        let s = SharedLinkMetadata {
            tag: None,
            url: "https://example.com".into(),
            name: Some("link".into()),
            path_lower: None,
            link_permissions: None,
        };
        #[allow(clippy::redundant_clone)]
        let s2 = s.clone();
        assert_eq!(s2.url, "https://example.com");
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error_summary": "path/not_found"
        }))
        .unwrap();
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.error_summary, Some("path/not_found".into()));
    }

    #[test]
    fn file_metadata_zero_size() {
        let f: FileMetadata = serde_json::from_value(json!({
            "name": "empty.txt",
            "size": 0
        }))
        .unwrap();
        assert_eq!(f.size, Some(0));
    }

    #[test]
    fn list_shared_links_result_clone() {
        let r = ListSharedLinksResult {
            links: vec![json!({"url": "https://example.com"})],
            has_more: Some(false),
            cursor: None,
        };
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.links.len(), 1);
    }
}
