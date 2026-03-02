//! Zendesk API types.

use serde::{Deserialize, Serialize};

/// A Zendesk support ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub id: Option<i64>,
    pub url: Option<String>,
    pub subject: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    #[serde(rename = "type")]
    pub ticket_type: Option<String>,
    pub requester_id: Option<i64>,
    pub assignee_id: Option<i64>,
    pub group_id: Option<i64>,
    pub tags: Option<Vec<String>>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub custom_fields: Option<Vec<serde_json::Value>>,
}

/// A Zendesk ticket comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub id: Option<i64>,
    pub body: Option<String>,
    pub html_body: Option<String>,
    pub author_id: Option<i64>,
    pub public: Option<bool>,
    pub created_at: Option<String>,
}

/// A Zendesk Help Center article.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Article {
    pub id: Option<i64>,
    pub url: Option<String>,
    pub html_url: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub locale: Option<String>,
    pub section_id: Option<i64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub draft: Option<bool>,
}

/// A Zendesk user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<i64>,
    pub url: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub role: Option<String>,
    pub active: Option<bool>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Zendesk API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
    pub description: Option<String>,
}
