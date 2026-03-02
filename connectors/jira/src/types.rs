//! Jira REST API types.

use serde::{Deserialize, Serialize};

// ── Issue ───────────────────────────────────────────────────────

/// Jira issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraIssue {
    pub id: String,
    pub key: String,
    #[serde(rename = "self")]
    pub self_url: Option<String>,
    pub fields: Option<serde_json::Value>,
    pub changelog: Option<serde_json::Value>,
}

/// Response from creating an issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIssueResponse {
    pub id: String,
    pub key: String,
    #[serde(rename = "self")]
    pub self_url: String,
}

// ── Project ─────────────────────────────────────────────────────

/// Jira project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraProject {
    pub id: Option<String>,
    pub key: String,
    pub name: Option<String>,
}

// ── Transition ──────────────────────────────────────────────────

/// Jira workflow transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraTransition {
    pub id: String,
    pub name: String,
    pub to: Option<TransitionStatus>,
}

/// Status that a transition leads to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionStatus {
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "statusCategory")]
    pub status_category: Option<serde_json::Value>,
}

/// Response from listing transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionsResponse {
    pub transitions: Vec<JiraTransition>,
}

// ── Comment ─────────────────────────────────────────────────────

/// Jira comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraComment {
    pub id: Option<String>,
    pub body: Option<serde_json::Value>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub author: Option<serde_json::Value>,
    pub visibility: Option<serde_json::Value>,
}

/// Paginated comment list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentListResponse {
    pub comments: Vec<JiraComment>,
    pub total: u64,
    pub start_at: Option<u64>,
    pub max_results: Option<u64>,
}

// ── Sprint ──────────────────────────────────────────────────────

/// Jira sprint (from Agile API).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraSprint {
    pub id: u64,
    pub name: String,
    pub state: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub complete_date: Option<String>,
    pub origin_board_id: Option<u64>,
    pub goal: Option<String>,
}

/// Paginated sprint list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SprintListResponse {
    pub values: Vec<JiraSprint>,
    pub is_last: Option<bool>,
    pub max_results: Option<u64>,
    pub start_at: Option<u64>,
}

// ── Search ──────────────────────────────────────────────────────

/// JQL search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub issues: Vec<JiraIssue>,
    pub total: u64,
    pub max_results: u64,
    pub start_at: u64,
}

// ── Attachment ──────────────────────────────────────────────────

/// Jira attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraAttachment {
    pub id: Option<String>,
    pub filename: Option<String>,
    pub size: Option<u64>,
    pub mime_type: Option<String>,
    pub content: Option<String>,
    pub created: Option<String>,
    pub author: Option<serde_json::Value>,
}

// ── API Error ───────────────────────────────────────────────────

/// Jira REST API error response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    pub error_messages: Option<Vec<String>>,
    pub errors: Option<serde_json::Value>,
}
