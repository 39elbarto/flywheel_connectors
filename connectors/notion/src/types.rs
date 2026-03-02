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
