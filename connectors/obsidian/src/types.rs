//! Obsidian vault types.

use serde::{Deserialize, Serialize};

/// A note in the Obsidian vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    /// Relative path within the vault (e.g., "folder/note.md").
    pub path: String,
    /// Note title (derived from filename without extension).
    pub title: String,
    /// Full markdown content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// File size in bytes.
    pub size: u64,
    /// Last modified time (ISO 8601).
    pub modified: String,
    /// Created time (ISO 8601).
    pub created: String,
    /// Tags extracted from frontmatter/inline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// A note listing entry (without content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteEntry {
    pub path: String,
    pub title: String,
    pub size: u64,
    pub modified: String,
    pub created: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Search result for vault-wide text search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub path: String,
    pub title: String,
    /// Matching line numbers and their content.
    pub matches: Vec<SearchMatch>,
}

/// A single search match within a note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMatch {
    pub line: usize,
    pub text: String,
}

/// Tag with usage count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagInfo {
    pub tag: String,
    pub count: usize,
}

/// Backlink: another note that references the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backlink {
    pub source_path: String,
    pub source_title: String,
    pub line: usize,
    pub context: String,
}

/// Vault health information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealth {
    pub vault_path: String,
    pub note_count: usize,
    pub total_size_bytes: u64,
    pub readable: bool,
    pub writable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_serialization() {
        let note = Note {
            path: "daily/2026-03-21.md".into(),
            title: "2026-03-21".into(),
            content: Some("# Daily Note\nContent here.".into()),
            size: 42,
            modified: "2026-03-21T10:00:00Z".into(),
            created: "2026-03-21T09:00:00Z".into(),
            tags: vec!["daily".into(), "journal".into()],
        };
        let json = serde_json::to_value(&note).unwrap();
        assert_eq!(json["path"], "daily/2026-03-21.md");
        assert_eq!(json["title"], "2026-03-21");
        assert_eq!(json["tags"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn note_entry_omits_content() {
        let entry = NoteEntry {
            path: "test.md".into(),
            title: "test".into(),
            size: 10,
            modified: "2026-01-01T00:00:00Z".into(),
            created: "2026-01-01T00:00:00Z".into(),
            tags: Vec::new(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert!(json.get("content").is_none());
        assert!(!json.to_string().contains("tags"));
    }

    #[test]
    fn search_result_serialization() {
        let result = SearchResult {
            path: "notes/rust.md".into(),
            title: "rust".into(),
            matches: vec![SearchMatch {
                line: 5,
                text: "Rust is a systems language".into(),
            }],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["matches"][0]["line"], 5);
    }

    #[test]
    fn tag_info_serialization() {
        let tag = TagInfo {
            tag: "rust".into(),
            count: 7,
        };
        let json = serde_json::to_value(&tag).unwrap();
        assert_eq!(json["count"], 7);
    }

    #[test]
    fn backlink_serialization() {
        let bl = Backlink {
            source_path: "index.md".into(),
            source_title: "index".into(),
            line: 3,
            context: "See [[rust]] for details".into(),
        };
        let json = serde_json::to_value(&bl).unwrap();
        assert!(json["context"].as_str().unwrap().contains("[[rust]]"));
    }

    #[test]
    fn vault_health_serialization() {
        let health = VaultHealth {
            vault_path: "/tmp/vault".into(),
            note_count: 100,
            total_size_bytes: 50_000,
            readable: true,
            writable: true,
        };
        let json = serde_json::to_value(&health).unwrap();
        assert_eq!(json["note_count"], 100);
        assert!(json["writable"].as_bool().unwrap());
    }

    #[test]
    fn note_without_optional_fields() {
        let note = Note {
            path: "bare.md".into(),
            title: "bare".into(),
            content: None,
            size: 0,
            modified: "2026-01-01T00:00:00Z".into(),
            created: "2026-01-01T00:00:00Z".into(),
            tags: Vec::new(),
        };
        let json = serde_json::to_value(&note).unwrap();
        assert!(json.get("content").is_none());
        assert!(json.get("tags").is_none());
    }

    #[test]
    fn note_deserialization() {
        let json = serde_json::json!({
            "path": "test.md",
            "title": "test",
            "size": 123,
            "modified": "2026-01-01T00:00:00Z",
            "created": "2026-01-01T00:00:00Z"
        });
        let note: Note = serde_json::from_value(json).unwrap();
        assert_eq!(note.path, "test.md");
        assert!(note.content.is_none());
        assert!(note.tags.is_empty());
    }
}
