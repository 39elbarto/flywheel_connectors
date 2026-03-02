//! Gmail API types.

use serde::{Deserialize, Serialize};

/// Gmail message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailMessage {
    pub id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub label_ids: Vec<String>,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub history_id: Option<String>,
    #[serde(default)]
    pub internal_date: Option<String>,
    #[serde(default)]
    pub size_estimate: u64,
    #[serde(default)]
    pub payload: Option<MessagePart>,
}

/// Gmail message part (MIME structure).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePart {
    #[serde(default)]
    pub part_id: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: Option<MessagePartBody>,
    #[serde(default)]
    pub parts: Option<Vec<Self>>,
}

/// Gmail message part body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePartBody {
    #[serde(default)]
    pub attachment_id: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub data: Option<String>,
}

/// Gmail header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Gmail thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailThread {
    pub id: String,
    #[serde(default)]
    pub history_id: Option<String>,
    #[serde(default)]
    pub messages: Vec<GmailMessage>,
    #[serde(default)]
    pub snippet: String,
}

/// Gmail label.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailLabel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub message_list_visibility: Option<String>,
    #[serde(default)]
    pub label_list_visibility: Option<String>,
    #[serde(default, rename = "type")]
    pub label_type: Option<String>,
    #[serde(default)]
    pub messages_total: u32,
    #[serde(default)]
    pub messages_unread: u32,
    #[serde(default)]
    pub threads_total: u32,
    #[serde(default)]
    pub threads_unread: u32,
}

/// Gmail draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmailDraft {
    pub id: String,
    #[serde(default)]
    pub message: Option<GmailMessage>,
}

/// Messages list response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesListResponse {
    #[serde(default)]
    pub messages: Vec<MessageRef>,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub result_size_estimate: u32,
}

/// Minimal message reference (from list endpoints).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRef {
    pub id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
}

/// Labels list response.
#[derive(Debug, Clone, Deserialize)]
pub struct LabelsListResponse {
    #[serde(default)]
    pub labels: Vec<GmailLabel>,
}

/// Threads list response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadsListResponse {
    #[serde(default)]
    pub threads: Vec<ThreadRef>,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub result_size_estimate: u32,
}

/// Minimal thread reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadRef {
    pub id: String,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub history_id: Option<String>,
}

/// History list response for incremental sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryListResponse {
    #[serde(default)]
    pub history: Vec<serde_json::Value>,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub history_id: Option<String>,
}

/// Gmail API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct GmailApiError {
    pub error: GmailErrorDetail,
}

/// Gmail API error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct GmailErrorDetail {
    pub code: u32,
    pub message: String,
    #[serde(default)]
    pub errors: Vec<GmailErrorItem>,
}

/// Individual error item.
#[derive(Debug, Clone, Deserialize)]
pub struct GmailErrorItem {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
}
