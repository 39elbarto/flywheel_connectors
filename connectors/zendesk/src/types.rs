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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ticket_serde_roundtrip() {
        let ticket = Ticket {
            id: Some(123),
            url: Some("https://example.zendesk.com/api/v2/tickets/123.json".into()),
            subject: Some("Help needed".into()),
            description: Some("I need help".into()),
            status: Some("open".into()),
            priority: Some("high".into()),
            ticket_type: Some("problem".into()),
            requester_id: Some(456),
            assignee_id: Some(789),
            group_id: Some(10),
            tags: Some(vec!["urgent".into(), "billing".into()]),
            created_at: Some("2026-03-01T00:00:00Z".into()),
            updated_at: None,
            custom_fields: None,
        };
        let json_str = serde_json::to_string(&ticket).unwrap();
        assert!(json_str.contains("\"type\":\"problem\""));
        let back: Ticket = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, Some(123));
        assert_eq!(back.ticket_type.as_deref(), Some("problem"));
    }

    #[test]
    fn ticket_all_optional() {
        let json = json!({"id": null});
        let ticket: Ticket = serde_json::from_value(json).unwrap();
        assert!(ticket.id.is_none());
        assert!(ticket.subject.is_none());
        assert!(ticket.tags.is_none());
    }

    #[test]
    fn comment_serde() {
        let comment = Comment {
            id: Some(100),
            body: Some("Thanks for the help".into()),
            html_body: Some("<p>Thanks</p>".into()),
            author_id: Some(456),
            public: Some(true),
            created_at: Some("2026-03-01T12:00:00Z".into()),
        };
        let json_str = serde_json::to_string(&comment).unwrap();
        let back: Comment = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, Some(100));
        assert_eq!(back.public, Some(true));
    }

    #[test]
    fn article_serde() {
        let json = json!({
            "id": 200,
            "title": "Getting Started",
            "body": "<h1>Welcome</h1>",
            "locale": "en-us",
            "section_id": 50,
            "draft": false
        });
        let article: Article = serde_json::from_value(json).unwrap();
        assert_eq!(article.id, Some(200));
        assert_eq!(article.title.as_deref(), Some("Getting Started"));
        assert_eq!(article.draft, Some(false));
    }

    #[test]
    fn user_serde() {
        let user = User {
            id: Some(300),
            url: None,
            name: Some("Alice".into()),
            email: Some("alice@example.com".into()),
            role: Some("admin".into()),
            active: Some(true),
            created_at: None,
            updated_at: None,
        };
        let json_str = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name.as_deref(), Some("Alice"));
        assert_eq!(back.active, Some(true));
    }

    #[test]
    fn api_error_response_serde() {
        let json = json!({
            "error": "RecordNotFound",
            "message": "Not Found",
            "description": "Ticket not found"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("RecordNotFound"));
        assert_eq!(err.description.as_deref(), Some("Ticket not found"));
    }
}
