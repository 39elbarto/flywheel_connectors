//! Figma API types.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Figma API response envelope
// ---------------------------------------------------------------------------

/// Standard Figma API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct FigmaErrorResponse {
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default, alias = "err")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Files & Nodes
// ---------------------------------------------------------------------------

/// Response from `GET /v1/files/:file_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileResponse {
    pub name: String,
    pub document: serde_json::Value,
    pub last_modified: String,
    pub version: String,
    #[serde(default)]
    pub components: Option<serde_json::Value>,
    #[serde(default)]
    pub styles: Option<serde_json::Value>,
}

/// Response from `GET /v1/files/:file_key/nodes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNodesResponse {
    pub nodes: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Components & Styles
// ---------------------------------------------------------------------------

/// Response from `GET /v1/files/:file_key/components`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentsResponse {
    pub meta: serde_json::Value,
}

/// Response from `GET /v1/files/:file_key/styles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StylesResponse {
    pub meta: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Image Export
// ---------------------------------------------------------------------------

/// Response from `GET /v1/images/:file_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportImagesResponse {
    pub images: serde_json::Value,
    #[serde(default)]
    pub err: Option<String>,
}

// ---------------------------------------------------------------------------
// Version History
// ---------------------------------------------------------------------------

/// Response from `GET /v1/files/:file_key/versions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionsResponse {
    pub versions: Vec<FileVersion>,
    #[serde(default)]
    pub pagination: Option<serde_json::Value>,
}

/// A single file version entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVersion {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub user: Option<FigmaUser>,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Comments
// ---------------------------------------------------------------------------

/// Response from `GET /v1/files/:file_key/comments`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentsResponse {
    pub comments: Vec<Comment>,
}

/// A Figma comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub id: String,
    pub message: String,
    pub created_at: String,
    #[serde(default)]
    pub resolved_at: Option<String>,
    #[serde(default)]
    pub user: Option<FigmaUser>,
    #[serde(default)]
    pub client_meta: Option<serde_json::Value>,
    #[serde(default)]
    pub order_id: Option<String>,
    #[serde(default)]
    pub parent_id: Option<String>,
}

/// Figma user info (shared across multiple response types).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FigmaUser {
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub img_url: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

/// Request body for `POST /v1/files/:file_key/comments`.
#[derive(Debug, Clone, Serialize)]
pub struct PostCommentRequest {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_meta: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

/// Response from `GET /v2/webhooks/:team_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhooksListResponse {
    pub webhooks: Vec<Webhook>,
}

/// A Figma webhook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub team_id: String,
    pub event_type: String,
    pub endpoint: String,
    pub status: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub passcode: Option<String>,
}

/// Request body for POST /v2/webhooks.
#[derive(Debug, Clone, Serialize)]
pub struct CreateWebhookRequest {
    pub team_id: String,
    pub event_type: String,
    pub endpoint: String,
    pub passcode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
