//! Linear GraphQL API types.

use serde::{Deserialize, Serialize};

// ── GraphQL request/response ────────────────────────────────────

/// GraphQL request body.
#[derive(Debug, Serialize)]
pub struct GraphQLRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<serde_json::Value>,
}

/// GraphQL response wrapper.
#[derive(Debug, Deserialize)]
pub struct GraphQLResponse {
    pub data: Option<serde_json::Value>,
    pub errors: Option<Vec<GraphQLError>>,
}

/// GraphQL error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    pub message: String,
    pub path: Option<Vec<serde_json::Value>>,
    pub extensions: Option<serde_json::Value>,
}

// ── Issue ───────────────────────────────────────────────────────

/// Linear issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub id: String,
    pub identifier: String,
    pub title: String,
    pub description: Option<String>,
    pub priority: Option<f64>,
    pub priority_label: Option<String>,
    pub state: Option<IssueState>,
    pub assignee: Option<User>,
    pub team: Option<TeamRef>,
    pub labels: Option<LabelConnection>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub url: Option<String>,
}

/// Issue state (workflow state).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueState {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    #[serde(rename = "type")]
    pub state_type: Option<String>,
}

/// Label connection (paginated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelConnection {
    pub nodes: Vec<Label>,
}

/// Issue label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}

// ── Team ────────────────────────────────────────────────────────

/// Linear team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub key: String,
    pub description: Option<String>,
}

/// Lightweight team reference in issue responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamRef {
    pub id: String,
    pub name: Option<String>,
    pub key: Option<String>,
}

// ── User ────────────────────────────────────────────────────────

/// Linear user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
}

// ── Cycle ───────────────────────────────────────────────────────

/// Linear cycle (sprint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cycle {
    pub id: String,
    pub number: u32,
    pub name: Option<String>,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
    pub completed_at: Option<String>,
}

// ── Project ─────────────────────────────────────────────────────

/// Linear project.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub state: Option<String>,
    pub progress: Option<f64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub url: Option<String>,
}

// ── Comment ─────────────────────────────────────────────────────

/// Linear comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueComment {
    pub id: String,
    pub body: String,
    pub user: Option<User>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

// ── Mutation results ────────────────────────────────────────────

/// Result from creating an issue.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCreatePayload {
    pub success: bool,
    pub issue: Option<Issue>,
}

/// Result from updating an issue.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueUpdatePayload {
    pub success: bool,
    pub issue: Option<Issue>,
}

/// Result from creating a comment.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentCreatePayload {
    pub success: bool,
    pub comment: Option<IssueComment>,
}
