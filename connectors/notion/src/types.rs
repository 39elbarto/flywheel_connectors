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
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub status: Option<u16>,
    pub code: Option<String>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        assert!(!back.archived);
    }

    #[test]
    fn page_defaults() {
        let json = json!({"id": "p1", "object": "page"});
        let page: Page = serde_json::from_value(json).unwrap();
        assert!(!page.archived);
        assert!(page.url.is_none());
    }

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
    fn api_error_response_serde() {
        let json = json!({
            "status": 404,
            "code": "object_not_found",
            "message": "Could not find page"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.status, Some(404));
        assert_eq!(err.code.as_deref(), Some("object_not_found"));
    }
}
