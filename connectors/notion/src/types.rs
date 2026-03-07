//! Notion API types.

use serde::{Deserialize, Serialize};

// ── Page ────────────────────────────────────────────────────────

/// A Notion page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub id: String,
    pub object: String,
    #[serde(default)]
    pub archived: bool,
    pub url: Option<String>,
    pub created_time: Option<String>,
    pub last_edited_time: Option<String>,
    pub parent: Option<serde_json::Value>,
    pub properties: Option<serde_json::Value>,
}

// ── Database ────────────────────────────────────────────────────

/// A Notion database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub id: String,
    pub object: String,
    pub title: Option<Vec<RichText>>,
    pub url: Option<String>,
    pub created_time: Option<String>,
    pub last_edited_time: Option<String>,
    pub properties: Option<serde_json::Value>,
}

// ── Block ───────────────────────────────────────────────────────

/// A Notion block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub id: String,
    pub object: String,
    #[serde(rename = "type")]
    pub block_type: Option<String>,
    pub has_children: Option<bool>,
    pub archived: Option<bool>,
    pub created_time: Option<String>,
    pub last_edited_time: Option<String>,
    // Block content is dynamic per type; store as raw value.
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

// ── Comment ─────────────────────────────────────────────────────

/// A Notion comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub id: String,
    pub object: String,
    pub parent: Option<serde_json::Value>,
    pub discussion_id: Option<String>,
    pub rich_text: Option<Vec<RichText>>,
    pub created_time: Option<String>,
}

// ── Rich text ───────────────────────────────────────────────────

/// Rich text object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichText {
    #[serde(rename = "type")]
    pub text_type: Option<String>,
    pub text: Option<TextContent>,
    pub plain_text: Option<String>,
    pub annotations: Option<serde_json::Value>,
}

/// Text content inside a rich text object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextContent {
    pub content: String,
    pub link: Option<serde_json::Value>,
}

// ── Paginated responses ─────────────────────────────────────────

/// Paginated list response from Notion API.
#[derive(Debug, Clone, Deserialize)]
pub struct PaginatedResponse {
    pub object: String,
    pub results: Vec<serde_json::Value>,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

// ── Error response ──────────────────────────────────────────────

/// Notion API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub status: Option<u16>,
    pub code: Option<String>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ═══════════════════════════════════════════════════════════════════
    //  Page
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn page_serde_roundtrip() {
        let page = Page {
            id: "page-1".into(),
            object: "page".into(),
            archived: false,
            url: Some("https://notion.so/page-1".into()),
            created_time: Some("2026-03-01T00:00:00Z".into()),
            last_edited_time: None,
            parent: Some(json!({"database_id": "db-1"})),
            properties: Some(json!({"Name": {"title": []}})),
        };
        let json_str = serde_json::to_string(&page).unwrap();
        let back: Page = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, "page-1");
        assert_eq!(back.object, "page");
        assert!(!back.archived);
        assert_eq!(back.url.as_deref(), Some("https://notion.so/page-1"));
        assert_eq!(back.created_time.as_deref(), Some("2026-03-01T00:00:00Z"));
        assert!(back.last_edited_time.is_none());
        assert!(back.parent.is_some());
        assert!(back.properties.is_some());
    }

    #[test]
    fn page_defaults() {
        let json = json!({"id": "p1", "object": "page"});
        let page: Page = serde_json::from_value(json).unwrap();
        assert!(!page.archived, "archived should default to false");
        assert!(page.url.is_none());
        assert!(page.created_time.is_none());
        assert!(page.last_edited_time.is_none());
        assert!(page.parent.is_none());
        assert!(page.properties.is_none());
    }

    #[test]
    fn page_archived_true() {
        let json = json!({"id": "p1", "object": "page", "archived": true});
        let page: Page = serde_json::from_value(json).unwrap();
        assert!(page.archived);
    }

    #[test]
    fn page_clone() {
        let page = Page {
            id: "page-c".into(),
            object: "page".into(),
            archived: true,
            url: Some("https://example.com".into()),
            created_time: None,
            last_edited_time: None,
            parent: None,
            properties: Some(json!({"key": "value"})),
        };
        let cloned = page.clone();
        assert_eq!(cloned.id, page.id);
        assert_eq!(cloned.archived, page.archived);
        assert_eq!(cloned.url, page.url);
        assert_eq!(cloned.properties, page.properties);
    }

    #[test]
    fn page_debug() {
        let page = Page {
            id: "dbg".into(),
            object: "page".into(),
            archived: false,
            url: None,
            created_time: None,
            last_edited_time: None,
            parent: None,
            properties: None,
        };
        let dbg = format!("{page:?}");
        assert!(dbg.contains("Page"));
        assert!(dbg.contains("dbg"));
    }

    #[test]
    fn page_all_optional_fields_present() {
        let json = json!({
            "id": "p-full",
            "object": "page",
            "archived": true,
            "url": "https://notion.so/p-full",
            "created_time": "2026-01-01T00:00:00Z",
            "last_edited_time": "2026-03-05T12:00:00Z",
            "parent": {"workspace": true},
            "properties": {"Status": {"select": {"name": "Done"}}}
        });
        let page: Page = serde_json::from_value(json).unwrap();
        assert!(page.archived);
        assert_eq!(page.url.as_deref(), Some("https://notion.so/p-full"));
        assert!(page.created_time.is_some());
        assert!(page.last_edited_time.is_some());
        assert!(page.parent.is_some());
        assert!(page.properties.is_some());
    }

    #[test]
    fn page_roundtrip_preserves_null_optional_fields() {
        let page = Page {
            id: "p-null".into(),
            object: "page".into(),
            archived: false,
            url: None,
            created_time: None,
            last_edited_time: None,
            parent: None,
            properties: None,
        };
        let json_str = serde_json::to_string(&page).unwrap();
        let back: Page = serde_json::from_str(&json_str).unwrap();
        assert!(back.url.is_none());
        assert!(back.created_time.is_none());
        assert!(back.last_edited_time.is_none());
        assert!(back.parent.is_none());
        assert!(back.properties.is_none());
    }

    #[test]
    fn page_with_complex_properties() {
        let json = json!({
            "id": "p-cp",
            "object": "page",
            "properties": {
                "Name": {
                    "type": "title",
                    "title": [{"plain_text": "My Page", "type": "text"}]
                },
                "Tags": {
                    "type": "multi_select",
                    "multi_select": [{"name": "tag1"}, {"name": "tag2"}]
                },
                "Due": {
                    "type": "date",
                    "date": {"start": "2026-04-01"}
                }
            }
        });
        let page: Page = serde_json::from_value(json).unwrap();
        let props = page.properties.unwrap();
        assert!(props.get("Name").is_some());
        assert!(props.get("Tags").is_some());
        assert!(props.get("Due").is_some());
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Database
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn database_serde() {
        let json = json!({
            "id": "db-1",
            "object": "database",
            "title": [{"type": "text", "plain_text": "Tasks"}],
            "url": "https://notion.so/db-1"
        });
        let db: Database = serde_json::from_value(json).unwrap();
        assert_eq!(db.id, "db-1");
        let titles = db.title.unwrap();
        assert_eq!(titles[0].plain_text.as_deref(), Some("Tasks"));
    }

    #[test]
    fn database_minimal() {
        let json = json!({"id": "db-min", "object": "database"});
        let db: Database = serde_json::from_value(json).unwrap();
        assert_eq!(db.id, "db-min");
        assert!(db.title.is_none());
        assert!(db.url.is_none());
        assert!(db.created_time.is_none());
        assert!(db.last_edited_time.is_none());
        assert!(db.properties.is_none());
    }

    #[test]
    fn database_roundtrip() {
        let db = Database {
            id: "db-rt".into(),
            object: "database".into(),
            title: Some(vec![RichText {
                text_type: Some("text".into()),
                text: Some(TextContent {
                    content: "My DB".into(),
                    link: None,
                }),
                plain_text: Some("My DB".into()),
                annotations: None,
            }]),
            url: Some("https://notion.so/db-rt".into()),
            created_time: Some("2026-01-01T00:00:00Z".into()),
            last_edited_time: Some("2026-03-05T00:00:00Z".into()),
            properties: Some(json!({"Name": {"title": {}}})),
        };
        let json_str = serde_json::to_string(&db).unwrap();
        let back: Database = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, "db-rt");
        assert_eq!(back.title.unwrap().len(), 1);
        assert!(back.url.is_some());
        assert!(back.properties.is_some());
    }

    #[test]
    fn database_clone() {
        let db = Database {
            id: "db-c".into(),
            object: "database".into(),
            title: None,
            url: None,
            created_time: None,
            last_edited_time: None,
            properties: None,
        };
        let cloned = db.clone();
        assert_eq!(cloned.id, db.id);
        assert_eq!(cloned.object, db.object);
    }

    #[test]
    fn database_debug() {
        let db = Database {
            id: "db-dbg".into(),
            object: "database".into(),
            title: None,
            url: None,
            created_time: None,
            last_edited_time: None,
            properties: None,
        };
        let dbg = format!("{db:?}");
        assert!(dbg.contains("Database"));
        assert!(dbg.contains("db-dbg"));
    }

    #[test]
    fn database_empty_title_vec() {
        let json = json!({
            "id": "db-et",
            "object": "database",
            "title": []
        });
        let db: Database = serde_json::from_value(json).unwrap();
        assert_eq!(db.title.unwrap().len(), 0);
    }

    #[test]
    fn database_multiple_title_segments() {
        let json = json!({
            "id": "db-mt",
            "object": "database",
            "title": [
                {"type": "text", "plain_text": "Part 1"},
                {"type": "text", "plain_text": " Part 2"}
            ]
        });
        let db: Database = serde_json::from_value(json).unwrap();
        let titles = db.title.unwrap();
        assert_eq!(titles.len(), 2);
        assert_eq!(titles[0].plain_text.as_deref(), Some("Part 1"));
        assert_eq!(titles[1].plain_text.as_deref(), Some(" Part 2"));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Block
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn block_serde_with_flatten() {
        let json = json!({
            "id": "blk-1",
            "object": "block",
            "type": "paragraph",
            "has_children": false,
            "paragraph": {"rich_text": []}
        });
        let block: Block = serde_json::from_value(json).unwrap();
        assert_eq!(block.block_type.as_deref(), Some("paragraph"));
        assert!(block.extra.get("paragraph").is_some());
    }

    #[test]
    fn block_minimal() {
        let json = json!({"id": "blk-min", "object": "block"});
        let block: Block = serde_json::from_value(json).unwrap();
        assert_eq!(block.id, "blk-min");
        assert!(block.block_type.is_none());
        assert!(block.has_children.is_none());
        assert!(block.archived.is_none());
        assert!(block.created_time.is_none());
        assert!(block.last_edited_time.is_none());
    }

    #[test]
    fn block_roundtrip() {
        let json = json!({
            "id": "blk-rt",
            "object": "block",
            "type": "heading_1",
            "has_children": true,
            "archived": false,
            "created_time": "2026-01-01T00:00:00Z",
            "last_edited_time": "2026-03-05T00:00:00Z",
            "heading_1": {"rich_text": [{"plain_text": "Title"}]}
        });
        let block: Block = serde_json::from_value(json).unwrap();
        let json_str = serde_json::to_string(&block).unwrap();
        let back: Block = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, "blk-rt");
        assert_eq!(back.block_type.as_deref(), Some("heading_1"));
        assert_eq!(back.has_children, Some(true));
        assert_eq!(back.archived, Some(false));
        assert!(back.extra.get("heading_1").is_some());
    }

    #[test]
    fn block_clone() {
        let json = json!({
            "id": "blk-c",
            "object": "block",
            "type": "to_do",
            "to_do": {"checked": false}
        });
        let block: Block = serde_json::from_value(json).unwrap();
        let cloned = block.clone();
        assert_eq!(cloned.id, block.id);
        assert_eq!(cloned.block_type, block.block_type);
        assert_eq!(cloned.extra, block.extra);
    }

    #[test]
    fn block_debug() {
        let json = json!({"id": "blk-dbg", "object": "block"});
        let block: Block = serde_json::from_value(json).unwrap();
        let dbg = format!("{block:?}");
        assert!(dbg.contains("Block"));
        assert!(dbg.contains("blk-dbg"));
    }

    #[test]
    fn block_different_types() {
        let types = vec![
            ("paragraph", json!({"rich_text": []})),
            ("heading_1", json!({"rich_text": []})),
            ("heading_2", json!({"rich_text": []})),
            ("heading_3", json!({"rich_text": []})),
            ("bulleted_list_item", json!({"rich_text": []})),
            ("numbered_list_item", json!({"rich_text": []})),
            ("to_do", json!({"rich_text": [], "checked": false})),
            ("code", json!({"rich_text": [], "language": "rust"})),
            (
                "image",
                json!({"type": "external", "external": {"url": "https://example.com/img.png"}}),
            ),
        ];
        for (block_type, content) in types {
            let mut json_val = json!({
                "id": format!("blk-{block_type}"),
                "object": "block",
                "type": block_type,
            });
            json_val[block_type] = content;
            let block: Block = serde_json::from_value(json_val).unwrap();
            assert_eq!(block.block_type.as_deref(), Some(block_type));
            assert!(block.extra.get(block_type).is_some());
        }
    }

    #[test]
    fn block_flatten_captures_unknown_fields() {
        let json = json!({
            "id": "blk-unk",
            "object": "block",
            "type": "paragraph",
            "paragraph": {"rich_text": []},
            "custom_field": "custom_value"
        });
        let block: Block = serde_json::from_value(json).unwrap();
        assert_eq!(
            block.extra.get("custom_field").and_then(|v| v.as_str()),
            Some("custom_value")
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Comment
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn comment_serde() {
        let json = json!({
            "id": "cmt-1",
            "object": "comment",
            "discussion_id": "disc-1",
            "rich_text": [{"type": "text", "plain_text": "Hello"}]
        });
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.id, "cmt-1");
        assert_eq!(comment.rich_text.unwrap().len(), 1);
    }

    #[test]
    fn comment_minimal() {
        let json = json!({"id": "cmt-min", "object": "comment"});
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.id, "cmt-min");
        assert!(comment.parent.is_none());
        assert!(comment.discussion_id.is_none());
        assert!(comment.rich_text.is_none());
        assert!(comment.created_time.is_none());
    }

    #[test]
    fn comment_roundtrip() {
        let comment = Comment {
            id: "cmt-rt".into(),
            object: "comment".into(),
            parent: Some(json!({"page_id": "page-1"})),
            discussion_id: Some("disc-1".into()),
            rich_text: Some(vec![RichText {
                text_type: Some("text".into()),
                text: Some(TextContent {
                    content: "Roundtrip".into(),
                    link: None,
                }),
                plain_text: Some("Roundtrip".into()),
                annotations: None,
            }]),
            created_time: Some("2026-03-05T10:00:00Z".into()),
        };
        let json_str = serde_json::to_string(&comment).unwrap();
        let back: Comment = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, "cmt-rt");
        assert_eq!(back.discussion_id.as_deref(), Some("disc-1"));
        assert_eq!(back.rich_text.unwrap().len(), 1);
        assert!(back.parent.is_some());
        assert!(back.created_time.is_some());
    }

    #[test]
    fn comment_clone() {
        let comment = Comment {
            id: "cmt-c".into(),
            object: "comment".into(),
            parent: None,
            discussion_id: None,
            rich_text: None,
            created_time: None,
        };
        let cloned = comment.clone();
        assert_eq!(cloned.id, comment.id);
    }

    #[test]
    fn comment_debug() {
        let comment = Comment {
            id: "cmt-dbg".into(),
            object: "comment".into(),
            parent: None,
            discussion_id: None,
            rich_text: None,
            created_time: None,
        };
        let dbg = format!("{comment:?}");
        assert!(dbg.contains("Comment"));
        assert!(dbg.contains("cmt-dbg"));
    }

    #[test]
    fn comment_with_empty_rich_text() {
        let json = json!({
            "id": "cmt-empty-rt",
            "object": "comment",
            "rich_text": []
        });
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.rich_text.unwrap().len(), 0);
    }

    #[test]
    fn comment_with_multiple_rich_text() {
        let json = json!({
            "id": "cmt-multi-rt",
            "object": "comment",
            "rich_text": [
                {"type": "text", "plain_text": "Hello "},
                {"type": "text", "plain_text": "world!"}
            ]
        });
        let comment: Comment = serde_json::from_value(json).unwrap();
        let rt = comment.rich_text.unwrap();
        assert_eq!(rt.len(), 2);
        assert_eq!(rt[0].plain_text.as_deref(), Some("Hello "));
        assert_eq!(rt[1].plain_text.as_deref(), Some("world!"));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  RichText
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn rich_text_serde() {
        let rt = RichText {
            text_type: Some("text".into()),
            text: Some(TextContent {
                content: "Hello".into(),
                link: None,
            }),
            plain_text: Some("Hello".into()),
            annotations: None,
        };
        let json_str = serde_json::to_string(&rt).unwrap();
        assert!(json_str.contains("\"type\":\"text\""));
        let back: RichText = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.text.unwrap().content, "Hello");
    }

    #[test]
    fn rich_text_minimal() {
        let json = json!({});
        let rt: RichText = serde_json::from_value(json).unwrap();
        assert!(rt.text_type.is_none());
        assert!(rt.text.is_none());
        assert!(rt.plain_text.is_none());
        assert!(rt.annotations.is_none());
    }

    #[test]
    fn rich_text_with_link() {
        let json = json!({
            "type": "text",
            "text": {
                "content": "Click here",
                "link": {"url": "https://example.com"}
            },
            "plain_text": "Click here"
        });
        let rt: RichText = serde_json::from_value(json).unwrap();
        let text = rt.text.unwrap();
        assert_eq!(text.content, "Click here");
        assert!(text.link.is_some());
        assert_eq!(
            text.link.unwrap().get("url").and_then(|v| v.as_str()),
            Some("https://example.com")
        );
    }

    #[test]
    fn rich_text_with_annotations() {
        let json = json!({
            "type": "text",
            "plain_text": "bold text",
            "annotations": {
                "bold": true,
                "italic": false,
                "strikethrough": false,
                "underline": false,
                "code": false,
                "color": "red"
            }
        });
        let rt: RichText = serde_json::from_value(json).unwrap();
        let annot = rt.annotations.unwrap();
        assert_eq!(annot["bold"], true);
        assert_eq!(annot["color"], "red");
    }

    #[test]
    fn rich_text_clone() {
        let rt = RichText {
            text_type: Some("text".into()),
            text: Some(TextContent {
                content: "Clone me".into(),
                link: None,
            }),
            plain_text: Some("Clone me".into()),
            annotations: Some(json!({"bold": true})),
        };
        let cloned = rt.clone();
        assert_eq!(cloned.text_type, rt.text_type);
        assert_eq!(cloned.plain_text, rt.plain_text);
        assert_eq!(cloned.annotations, rt.annotations);
        assert_eq!(cloned.text.unwrap().content, "Clone me");
    }

    #[test]
    fn rich_text_debug() {
        let rt = RichText {
            text_type: Some("equation".into()),
            text: None,
            plain_text: Some("E=mc^2".into()),
            annotations: None,
        };
        let dbg = format!("{rt:?}");
        assert!(dbg.contains("RichText"));
        assert!(dbg.contains("equation"));
    }

    #[test]
    fn rich_text_type_rename_in_json() {
        // Verify that #[serde(rename = "type")] works correctly
        let rt = RichText {
            text_type: Some("mention".into()),
            text: None,
            plain_text: Some("@user".into()),
            annotations: None,
        };
        let json_val = serde_json::to_value(&rt).unwrap();
        // Should serialize as "type", not "text_type"
        assert!(json_val.get("type").is_some());
        assert!(json_val.get("text_type").is_none());
    }

    // ═══════════════════════════════════════════════════════════════════
    //  TextContent
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn text_content_roundtrip() {
        let tc = TextContent {
            content: "Hello world".into(),
            link: Some(json!({"url": "https://example.com"})),
        };
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: TextContent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.content, "Hello world");
        assert!(back.link.is_some());
    }

    #[test]
    fn text_content_no_link() {
        let tc = TextContent {
            content: "No link".into(),
            link: None,
        };
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: TextContent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.content, "No link");
        assert!(back.link.is_none());
    }

    #[test]
    fn text_content_empty_string() {
        let tc = TextContent {
            content: String::new(),
            link: None,
        };
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: TextContent = serde_json::from_str(&json_str).unwrap();
        assert!(back.content.is_empty());
    }

    #[test]
    fn text_content_clone() {
        let tc = TextContent {
            content: "clone test".into(),
            link: Some(json!({"url": "https://example.com"})),
        };
        let cloned = tc.clone();
        assert_eq!(cloned.content, tc.content);
        assert_eq!(cloned.link, tc.link);
    }

    #[test]
    fn text_content_debug() {
        let tc = TextContent {
            content: "debug".into(),
            link: None,
        };
        let dbg = format!("{tc:?}");
        assert!(dbg.contains("TextContent"));
        assert!(dbg.contains("debug"));
    }

    #[test]
    fn text_content_unicode() {
        let tc = TextContent {
            content: "こんにちは 🌍 café".into(),
            link: None,
        };
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: TextContent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.content, "こんにちは 🌍 café");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PaginatedResponse
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn paginated_response_serde() {
        let json = json!({
            "object": "list",
            "results": [{"id": "item-1"}],
            "has_more": true,
            "next_cursor": "cursor-abc"
        });
        let resp: PaginatedResponse = serde_json::from_value(json).unwrap();
        assert!(resp.has_more);
        assert_eq!(resp.next_cursor.as_deref(), Some("cursor-abc"));
        assert_eq!(resp.results.len(), 1);
    }

    #[test]
    fn paginated_response_no_more() {
        let json = json!({
            "object": "list",
            "results": [],
            "has_more": false,
            "next_cursor": null
        });
        let resp: PaginatedResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.has_more);
        assert!(resp.next_cursor.is_none());
        assert!(resp.results.is_empty());
    }

    #[test]
    fn paginated_response_multiple_results() {
        let json = json!({
            "object": "list",
            "results": [
                {"id": "r1", "object": "page"},
                {"id": "r2", "object": "page"},
                {"id": "r3", "object": "database"}
            ],
            "has_more": true,
            "next_cursor": "cursor-xyz"
        });
        let resp: PaginatedResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.results.len(), 3);
        assert_eq!(resp.results[0]["id"], "r1");
        assert_eq!(resp.results[2]["object"], "database");
    }

    #[test]
    fn paginated_response_clone() {
        let json = json!({
            "object": "list",
            "results": [{"id": "c1"}],
            "has_more": false,
            "next_cursor": null
        });
        let resp: PaginatedResponse = serde_json::from_value(json).unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.object, resp.object);
        assert_eq!(cloned.results.len(), resp.results.len());
        assert_eq!(cloned.has_more, resp.has_more);
    }

    #[test]
    fn paginated_response_debug() {
        let json = json!({
            "object": "list",
            "results": [],
            "has_more": false,
            "next_cursor": null
        });
        let resp: PaginatedResponse = serde_json::from_value(json).unwrap();
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("PaginatedResponse"));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  ApiErrorResponse
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn api_error_response_serde() {
        let json = json!({
            "status": 404,
            "code": "object_not_found",
            "message": "Could not find page"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.status, Some(404));
        assert_eq!(err.code.as_deref(), Some("object_not_found"));
        assert_eq!(err.message.as_deref(), Some("Could not find page"));
    }

    #[test]
    fn api_error_response_minimal() {
        let json = json!({});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.status.is_none());
        assert!(err.code.is_none());
        assert!(err.message.is_none());
    }

    #[test]
    fn api_error_response_partial_fields() {
        let json = json!({"status": 429});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.status, Some(429));
        assert!(err.code.is_none());
        assert!(err.message.is_none());
    }

    #[test]
    fn api_error_response_clone() {
        let json = json!({
            "status": 500,
            "code": "internal_server_error",
            "message": "Internal server error"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let cloned = err.clone();
        assert_eq!(cloned.status, err.status);
        assert_eq!(cloned.code, err.code);
        assert_eq!(cloned.message, err.message);
    }

    #[test]
    fn api_error_response_debug() {
        let json = json!({"status": 401, "code": "unauthorized"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ApiErrorResponse"));
        assert!(dbg.contains("401"));
    }

    #[test]
    fn api_error_response_all_codes() {
        for code_str in &[
            "object_not_found",
            "unauthorized",
            "restricted_resource",
            "validation_error",
            "conflict_error",
            "rate_limited",
            "internal_server_error",
            "service_unavailable",
        ] {
            let json = json!({"code": code_str});
            let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
            assert_eq!(err.code.as_deref(), Some(*code_str));
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Cross-type edge cases
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn page_with_null_values_in_json() {
        let json = json!({
            "id": "p-null",
            "object": "page",
            "url": null,
            "created_time": null,
            "last_edited_time": null,
            "parent": null,
            "properties": null
        });
        let page: Page = serde_json::from_value(json).unwrap();
        assert!(page.url.is_none());
        assert!(page.created_time.is_none());
        assert!(page.parent.is_none());
        assert!(page.properties.is_none());
    }

    #[test]
    fn database_with_null_values() {
        let json = json!({
            "id": "db-null",
            "object": "database",
            "title": null,
            "url": null,
            "created_time": null,
            "last_edited_time": null,
            "properties": null
        });
        let db: Database = serde_json::from_value(json).unwrap();
        assert!(db.title.is_none());
        assert!(db.url.is_none());
    }

    #[test]
    fn comment_with_null_values() {
        let json = json!({
            "id": "cmt-null",
            "object": "comment",
            "parent": null,
            "discussion_id": null,
            "rich_text": null,
            "created_time": null
        });
        let cmt: Comment = serde_json::from_value(json).unwrap();
        assert!(cmt.parent.is_none());
        assert!(cmt.discussion_id.is_none());
        assert!(cmt.rich_text.is_none());
        assert!(cmt.created_time.is_none());
    }

    #[test]
    fn rich_text_with_null_values() {
        let json = json!({
            "type": null,
            "text": null,
            "plain_text": null,
            "annotations": null
        });
        let rt: RichText = serde_json::from_value(json).unwrap();
        assert!(rt.text_type.is_none());
        assert!(rt.text.is_none());
        assert!(rt.plain_text.is_none());
        assert!(rt.annotations.is_none());
    }

    #[test]
    fn text_content_with_null_link() {
        let json = json!({"content": "test", "link": null});
        let tc: TextContent = serde_json::from_value(json).unwrap();
        assert_eq!(tc.content, "test");
        assert!(tc.link.is_none());
    }

    #[test]
    fn page_extra_fields_ignored() {
        // Serde should silently ignore fields not in the struct
        let json = json!({
            "id": "p-extra",
            "object": "page",
            "icon": {"type": "emoji", "emoji": "🔥"},
            "cover": null,
            "public_url": "https://notion.so/public/p-extra"
        });
        let page: Page = serde_json::from_value(json).unwrap();
        assert_eq!(page.id, "p-extra");
    }

    #[test]
    fn database_extra_fields_ignored() {
        let json = json!({
            "id": "db-extra",
            "object": "database",
            "icon": {"type": "emoji", "emoji": "📊"},
            "is_inline": true,
            "description": [{"plain_text": "A description"}]
        });
        let db: Database = serde_json::from_value(json).unwrap();
        assert_eq!(db.id, "db-extra");
    }

    #[test]
    fn paginated_response_with_mixed_result_types() {
        let json = json!({
            "object": "list",
            "results": [
                {"id": "p1", "object": "page", "url": "https://notion.so/p1"},
                {"id": "db1", "object": "database", "title": []},
                {"id": "blk1", "object": "block", "type": "paragraph"}
            ],
            "has_more": false,
            "next_cursor": null
        });
        let resp: PaginatedResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.results.len(), 3);
        assert_eq!(resp.results[0]["object"], "page");
        assert_eq!(resp.results[1]["object"], "database");
        assert_eq!(resp.results[2]["object"], "block");
    }

    #[test]
    fn block_archived_true() {
        let json = json!({
            "id": "blk-arch",
            "object": "block",
            "type": "paragraph",
            "archived": true
        });
        let block: Block = serde_json::from_value(json).unwrap();
        assert_eq!(block.archived, Some(true));
    }

    #[test]
    fn page_serialize_skips_none_optional_fields() {
        // Verify that serializing a Page with None values still works
        // and produces valid JSON that can be deserialized back
        let page = Page {
            id: "p-skip".into(),
            object: "page".into(),
            archived: false,
            url: None,
            created_time: None,
            last_edited_time: None,
            parent: None,
            properties: None,
        };
        let val = serde_json::to_value(&page).unwrap();
        // url should be present as null (Option serializes to null)
        assert!(val.get("id").is_some());
        assert!(val.get("object").is_some());
        // Roundtrip should succeed
        let back: Page = serde_json::from_value(val).unwrap();
        assert_eq!(back.id, "p-skip");
    }

    #[test]
    fn empty_string_fields() {
        let json = json!({
            "id": "",
            "object": "",
            "url": "",
            "created_time": ""
        });
        let page: Page = serde_json::from_value(json).unwrap();
        assert!(page.id.is_empty());
        assert!(page.object.is_empty());
        assert_eq!(page.url.as_deref(), Some(""));
        assert_eq!(page.created_time.as_deref(), Some(""));
    }

    // ── Page missing required fields ──────────────────────────────

    #[test]
    fn page_missing_id_fails() {
        let json = json!({"object": "page"});
        assert!(serde_json::from_value::<Page>(json).is_err());
    }

    #[test]
    fn page_missing_object_fails() {
        let json = json!({"id": "p1"});
        assert!(serde_json::from_value::<Page>(json).is_err());
    }

    // ── Database missing fields ───────────────────────────────────

    #[test]
    fn database_missing_id_fails() {
        let json = json!({"object": "database"});
        assert!(serde_json::from_value::<Database>(json).is_err());
    }

    // ── Block missing fields ──────────────────────────────────────

    #[test]
    fn block_missing_id_fails() {
        let json = json!({"object": "block"});
        assert!(serde_json::from_value::<Block>(json).is_err());
    }

    // ── Comment missing fields ────────────────────────────────────

    #[test]
    fn comment_missing_id_fails() {
        let json = json!({"object": "comment"});
        assert!(serde_json::from_value::<Comment>(json).is_err());
    }

    // ── Page clone and debug ──────────────────────────────────────

    #[test]
    #[allow(clippy::redundant_clone)]
    fn page_clone_deep() {
        let page = Page {
            id: "p-clone".into(),
            object: "page".into(),
            archived: true,
            url: Some("https://notion.so/test".into()),
            created_time: Some("2026-01-01".into()),
            last_edited_time: Some("2026-01-02".into()),
            parent: Some(json!({"type": "workspace"})),
            properties: Some(json!({"Name": "Test"})),
        };
        let cloned = page.clone();
        assert_eq!(cloned.id, "p-clone");
        assert!(cloned.archived);
        assert_eq!(cloned.url.as_deref(), Some("https://notion.so/test"));
    }

    #[test]
    fn page_debug_with_all_none_fields() {
        let page = Page {
            id: "p-dbg".into(),
            object: "page".into(),
            archived: false,
            url: None,
            created_time: None,
            last_edited_time: None,
            parent: None,
            properties: None,
        };
        let dbg = format!("{page:?}");
        assert!(dbg.contains("p-dbg"));
        assert!(dbg.contains("Page"));
    }

    // ── Database clone and debug ──────────────────────────────────

    #[test]
    #[allow(clippy::redundant_clone)]
    fn database_clone_deep() {
        let db = Database {
            id: "db-clone".into(),
            object: "database".into(),
            title: Some(vec![]),
            url: Some("https://notion.so/db".into()),
            created_time: None,
            last_edited_time: None,
            properties: None,
        };
        let cloned = db.clone();
        assert_eq!(cloned.id, "db-clone");
    }

    #[test]
    fn database_debug_with_all_none_fields() {
        let db = Database {
            id: "db-dbg".into(),
            object: "database".into(),
            title: None,
            url: None,
            created_time: None,
            last_edited_time: None,
            properties: None,
        };
        let dbg = format!("{db:?}");
        assert!(dbg.contains("db-dbg"));
    }

    // ── Block clone and debug ─────────────────────────────────────

    #[test]
    #[allow(clippy::redundant_clone)]
    fn block_clone_deep() {
        let block = Block {
            id: "blk-clone".into(),
            object: "block".into(),
            block_type: Some("heading_1".into()),
            has_children: Some(false),
            archived: Some(false),
            created_time: None,
            last_edited_time: None,
            extra: json!({}),
        };
        let cloned = block.clone();
        assert_eq!(cloned.id, "blk-clone");
        assert_eq!(cloned.block_type.as_deref(), Some("heading_1"));
    }

    // ── Comment clone and debug ───────────────────────────────────

    #[test]
    #[allow(clippy::redundant_clone)]
    fn comment_clone_deep() {
        let cmt = Comment {
            id: "cmt-clone".into(),
            object: "comment".into(),
            parent: Some(json!({"page_id": "p1"})),
            discussion_id: Some("disc1".into()),
            rich_text: Some(vec![]),
            created_time: Some("2026-01-01".into()),
        };
        let cloned = cmt.clone();
        assert_eq!(cloned.id, "cmt-clone");
        assert_eq!(cloned.discussion_id.as_deref(), Some("disc1"));
    }

    // ── PaginatedResponse additional ──────────────────────────────

    #[test]
    fn paginated_response_empty_results() {
        let json = json!({
            "object": "list",
            "results": [],
            "has_more": false,
            "next_cursor": null
        });
        let resp: PaginatedResponse = serde_json::from_value(json).unwrap();
        assert!(resp.results.is_empty());
        assert!(!resp.has_more);
        assert!(resp.next_cursor.is_none());
    }

    #[test]
    fn paginated_response_with_cursor() {
        let json = json!({
            "object": "list",
            "results": [{"id": "r1"}],
            "has_more": true,
            "next_cursor": "cursor_abc_123"
        });
        let resp: PaginatedResponse = serde_json::from_value(json).unwrap();
        assert!(resp.has_more);
        assert_eq!(resp.next_cursor.as_deref(), Some("cursor_abc_123"));
    }

    // ── RichText additional ───────────────────────────────────────

    #[test]
    fn rich_text_full_roundtrip() {
        let rt = RichText {
            text_type: Some("text".into()),
            text: Some(TextContent {
                content: "Hello world".into(),
                link: Some(json!({"url": "https://example.com"})),
            }),
            plain_text: Some("Hello world".into()),
            annotations: Some(json!({"bold": true, "italic": false})),
        };
        let json = serde_json::to_value(&rt).unwrap();
        let back: RichText = serde_json::from_value(json).unwrap();
        assert_eq!(back.plain_text.as_deref(), Some("Hello world"));
        assert!(back.annotations.is_some());
    }

    // ── RichText minimal / edge cases ────────────────────────────

    #[test]
    fn rich_text_all_none_fields() {
        let rt = RichText {
            text_type: None,
            text: None,
            plain_text: None,
            annotations: None,
        };
        let json = serde_json::to_value(&rt).unwrap();
        let back: RichText = serde_json::from_value(json).unwrap();
        assert!(back.text_type.is_none());
        assert!(back.text.is_none());
        assert!(back.plain_text.is_none());
        assert!(back.annotations.is_none());
    }

    #[test]
    fn api_error_response_roundtrip() {
        let err = ApiErrorResponse {
            status: Some(400),
            code: Some("validation_error".into()),
            message: Some("Invalid page ID".into()),
        };
        let json = serde_json::to_value(&err).unwrap();
        let back: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.status, Some(400));
        assert_eq!(back.code.as_deref(), Some("validation_error"));
        assert_eq!(back.message.as_deref(), Some("Invalid page ID"));
    }
}
