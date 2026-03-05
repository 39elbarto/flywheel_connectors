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

    // ── Ticket ────────────────────────────────────────────────────────

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
    fn ticket_empty_object() {
        let ticket: Ticket = serde_json::from_value(json!({})).unwrap();
        assert!(ticket.id.is_none());
        assert!(ticket.url.is_none());
        assert!(ticket.subject.is_none());
        assert!(ticket.description.is_none());
        assert!(ticket.status.is_none());
        assert!(ticket.priority.is_none());
        assert!(ticket.ticket_type.is_none());
        assert!(ticket.requester_id.is_none());
        assert!(ticket.assignee_id.is_none());
        assert!(ticket.group_id.is_none());
        assert!(ticket.tags.is_none());
        assert!(ticket.created_at.is_none());
        assert!(ticket.updated_at.is_none());
        assert!(ticket.custom_fields.is_none());
    }

    #[test]
    fn ticket_type_rename_serialization() {
        // Verify `ticket_type` serializes as `type` (serde rename)
        let ticket = Ticket {
            id: None,
            url: None,
            subject: None,
            description: None,
            status: None,
            priority: None,
            ticket_type: Some("incident".into()),
            requester_id: None,
            assignee_id: None,
            group_id: None,
            tags: None,
            created_at: None,
            updated_at: None,
            custom_fields: None,
        };
        let val: serde_json::Value = serde_json::to_value(&ticket).unwrap();
        assert_eq!(val["type"], "incident");
        // Ensure there is no `ticket_type` key in serialized output
        assert!(val.get("ticket_type").is_none());
    }

    #[test]
    fn ticket_type_rename_deserialization() {
        // Verify `type` in JSON maps to `ticket_type` field
        let json = json!({"type": "question"});
        let ticket: Ticket = serde_json::from_value(json).unwrap();
        assert_eq!(ticket.ticket_type.as_deref(), Some("question"));
    }

    #[test]
    fn ticket_tags_empty_vec() {
        let json = json!({"tags": []});
        let ticket: Ticket = serde_json::from_value(json).unwrap();
        assert_eq!(ticket.tags, Some(vec![]));
    }

    #[test]
    fn ticket_tags_roundtrip() {
        let json = json!({"tags": ["vip", "billing", "escalated"]});
        let ticket: Ticket = serde_json::from_value(json).unwrap();
        let tags = ticket.tags.as_ref().unwrap();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0], "vip");
        assert_eq!(tags[2], "escalated");

        // Roundtrip
        let val = serde_json::to_value(&ticket).unwrap();
        let back: Ticket = serde_json::from_value(val).unwrap();
        assert_eq!(back.tags.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn ticket_custom_fields_with_values() {
        let json = json!({
            "custom_fields": [
                {"id": 1001, "value": "important"},
                {"id": 1002, "value": null},
                {"id": 1003, "value": 42}
            ]
        });
        let ticket: Ticket = serde_json::from_value(json).unwrap();
        let fields = ticket.custom_fields.as_ref().unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0]["id"], 1001);
        assert_eq!(fields[0]["value"], "important");
        assert!(fields[1]["value"].is_null());
        assert_eq!(fields[2]["value"], 42);
    }

    #[test]
    fn ticket_clone() {
        let ticket = Ticket {
            id: Some(1),
            url: Some("https://test.zendesk.com/api/v2/tickets/1.json".into()),
            subject: Some("Clone test".into()),
            description: None,
            status: Some("new".into()),
            priority: None,
            ticket_type: None,
            requester_id: Some(100),
            assignee_id: None,
            group_id: None,
            tags: Some(vec!["test".into()]),
            created_at: None,
            updated_at: None,
            custom_fields: None,
        };
        let cloned = ticket.clone();
        assert_eq!(cloned.id, ticket.id);
        assert_eq!(cloned.subject, ticket.subject);
        assert_eq!(cloned.tags, ticket.tags);
        assert_eq!(cloned.requester_id, ticket.requester_id);
    }

    #[test]
    fn ticket_debug() {
        let ticket = Ticket {
            id: Some(42),
            url: None,
            subject: Some("Debug test".into()),
            description: None,
            status: None,
            priority: None,
            ticket_type: None,
            requester_id: None,
            assignee_id: None,
            group_id: None,
            tags: None,
            created_at: None,
            updated_at: None,
            custom_fields: None,
        };
        let dbg = format!("{ticket:?}");
        assert!(dbg.contains("Ticket"), "got: {dbg}");
        assert!(dbg.contains("42"), "got: {dbg}");
        assert!(dbg.contains("Debug test"), "got: {dbg}");
    }

    #[test]
    fn ticket_null_serialization_includes_null_fields() {
        // Verify that None fields serialize as null (no skip_serializing_if)
        let ticket = Ticket {
            id: None,
            url: None,
            subject: None,
            description: None,
            status: None,
            priority: None,
            ticket_type: None,
            requester_id: None,
            assignee_id: None,
            group_id: None,
            tags: None,
            created_at: None,
            updated_at: None,
            custom_fields: None,
        };
        let val: serde_json::Value = serde_json::to_value(&ticket).unwrap();
        // All fields should be present as null
        assert!(val["id"].is_null());
        assert!(val["url"].is_null());
        assert!(val["subject"].is_null());
        assert!(val["description"].is_null());
        assert!(val["status"].is_null());
        assert!(val["priority"].is_null());
        assert!(val["type"].is_null());
        assert!(val["requester_id"].is_null());
        assert!(val["assignee_id"].is_null());
        assert!(val["group_id"].is_null());
        assert!(val["tags"].is_null());
        assert!(val["created_at"].is_null());
        assert!(val["updated_at"].is_null());
        assert!(val["custom_fields"].is_null());
    }

    #[test]
    fn ticket_from_full_api_response() {
        let json = json!({
            "id": 9999,
            "url": "https://acme.zendesk.com/api/v2/tickets/9999.json",
            "subject": "Full API response",
            "description": "Detailed description here",
            "status": "pending",
            "priority": "urgent",
            "type": "task",
            "requester_id": 111,
            "assignee_id": 222,
            "group_id": 333,
            "tags": ["a", "b"],
            "created_at": "2026-01-15T10:30:00Z",
            "updated_at": "2026-03-05T14:00:00Z",
            "custom_fields": [{"id": 5, "value": "yes"}]
        });
        let ticket: Ticket = serde_json::from_value(json).unwrap();
        assert_eq!(ticket.id, Some(9999));
        assert_eq!(ticket.status.as_deref(), Some("pending"));
        assert_eq!(ticket.priority.as_deref(), Some("urgent"));
        assert_eq!(ticket.ticket_type.as_deref(), Some("task"));
        assert_eq!(ticket.requester_id, Some(111));
        assert_eq!(ticket.assignee_id, Some(222));
        assert_eq!(ticket.group_id, Some(333));
        assert!(ticket.updated_at.is_some());
        assert_eq!(ticket.custom_fields.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn ticket_ignores_extra_fields() {
        let json = json!({
            "id": 1,
            "subject": "test",
            "extra_unknown_field": "should be ignored",
            "another_field": 42
        });
        let ticket: Ticket = serde_json::from_value(json).unwrap();
        assert_eq!(ticket.id, Some(1));
        assert_eq!(ticket.subject.as_deref(), Some("test"));
    }

    // ── Comment ───────────────────────────────────────────────────────

    #[test]
    fn comment_serde_roundtrip() {
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
        assert_eq!(back.body.as_deref(), Some("Thanks for the help"));
        assert_eq!(back.html_body.as_deref(), Some("<p>Thanks</p>"));
        assert_eq!(back.author_id, Some(456));
        assert_eq!(back.public, Some(true));
        assert_eq!(back.created_at.as_deref(), Some("2026-03-01T12:00:00Z"));
    }

    #[test]
    fn comment_empty_object() {
        let comment: Comment = serde_json::from_value(json!({})).unwrap();
        assert!(comment.id.is_none());
        assert!(comment.body.is_none());
        assert!(comment.html_body.is_none());
        assert!(comment.author_id.is_none());
        assert!(comment.public.is_none());
        assert!(comment.created_at.is_none());
    }

    #[test]
    fn comment_private() {
        let json = json!({"public": false, "body": "Internal note"});
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.public, Some(false));
        assert_eq!(comment.body.as_deref(), Some("Internal note"));
    }

    #[test]
    fn comment_clone() {
        let comment = Comment {
            id: Some(1),
            body: Some("test".into()),
            html_body: None,
            author_id: Some(99),
            public: Some(true),
            created_at: None,
        };
        let cloned = comment.clone();
        assert_eq!(cloned.id, comment.id);
        assert_eq!(cloned.body, comment.body);
        assert_eq!(cloned.author_id, comment.author_id);
        assert_eq!(cloned.public, comment.public);
    }

    #[test]
    fn comment_debug() {
        let comment = Comment {
            id: Some(77),
            body: Some("debug test".into()),
            html_body: None,
            author_id: None,
            public: None,
            created_at: None,
        };
        let dbg = format!("{comment:?}");
        assert!(dbg.contains("Comment"), "got: {dbg}");
        assert!(dbg.contains("77"), "got: {dbg}");
    }

    #[test]
    fn comment_null_fields_serialize() {
        let comment = Comment {
            id: None,
            body: None,
            html_body: None,
            author_id: None,
            public: None,
            created_at: None,
        };
        let val: serde_json::Value = serde_json::to_value(&comment).unwrap();
        assert!(val["id"].is_null());
        assert!(val["body"].is_null());
        assert!(val["html_body"].is_null());
        assert!(val["author_id"].is_null());
        assert!(val["public"].is_null());
        assert!(val["created_at"].is_null());
    }

    // ── Article ───────────────────────────────────────────────────────

    #[test]
    fn article_serde_roundtrip() {
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

        // Roundtrip
        let val = serde_json::to_value(&article).unwrap();
        let back: Article = serde_json::from_value(val).unwrap();
        assert_eq!(back.id, Some(200));
        assert_eq!(back.locale.as_deref(), Some("en-us"));
        assert_eq!(back.section_id, Some(50));
    }

    #[test]
    fn article_empty_object() {
        let article: Article = serde_json::from_value(json!({})).unwrap();
        assert!(article.id.is_none());
        assert!(article.url.is_none());
        assert!(article.html_url.is_none());
        assert!(article.title.is_none());
        assert!(article.body.is_none());
        assert!(article.locale.is_none());
        assert!(article.section_id.is_none());
        assert!(article.created_at.is_none());
        assert!(article.updated_at.is_none());
        assert!(article.draft.is_none());
    }

    #[test]
    fn article_draft_true() {
        let json = json!({"draft": true, "title": "WIP article"});
        let article: Article = serde_json::from_value(json).unwrap();
        assert_eq!(article.draft, Some(true));
        assert_eq!(article.title.as_deref(), Some("WIP article"));
    }

    #[test]
    fn article_full_fields() {
        let json = json!({
            "id": 500,
            "url": "https://acme.zendesk.com/api/v2/help_center/articles/500.json",
            "html_url": "https://acme.zendesk.com/hc/en-us/articles/500",
            "title": "Full article",
            "body": "<p>Content</p>",
            "locale": "fr",
            "section_id": 88,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-02-01T00:00:00Z",
            "draft": false
        });
        let article: Article = serde_json::from_value(json).unwrap();
        assert_eq!(article.id, Some(500));
        assert!(article.url.is_some());
        assert!(article.html_url.is_some());
        assert_eq!(article.locale.as_deref(), Some("fr"));
        assert_eq!(article.section_id, Some(88));
        assert!(article.created_at.is_some());
        assert!(article.updated_at.is_some());
    }

    #[test]
    fn article_clone() {
        let article = Article {
            id: Some(10),
            url: None,
            html_url: None,
            title: Some("Cloned".into()),
            body: Some("<p>body</p>".into()),
            locale: Some("de".into()),
            section_id: None,
            created_at: None,
            updated_at: None,
            draft: Some(true),
        };
        let cloned = article.clone();
        assert_eq!(cloned.id, article.id);
        assert_eq!(cloned.title, article.title);
        assert_eq!(cloned.draft, article.draft);
        assert_eq!(cloned.locale, article.locale);
    }

    #[test]
    fn article_debug() {
        let article = Article {
            id: Some(303),
            url: None,
            html_url: None,
            title: Some("Debug article".into()),
            body: None,
            locale: None,
            section_id: None,
            created_at: None,
            updated_at: None,
            draft: None,
        };
        let dbg = format!("{article:?}");
        assert!(dbg.contains("Article"), "got: {dbg}");
        assert!(dbg.contains("303"), "got: {dbg}");
    }

    #[test]
    fn article_null_fields_serialize() {
        let article = Article {
            id: None,
            url: None,
            html_url: None,
            title: None,
            body: None,
            locale: None,
            section_id: None,
            created_at: None,
            updated_at: None,
            draft: None,
        };
        let val: serde_json::Value = serde_json::to_value(&article).unwrap();
        assert!(val["id"].is_null());
        assert!(val["url"].is_null());
        assert!(val["html_url"].is_null());
        assert!(val["title"].is_null());
        assert!(val["body"].is_null());
        assert!(val["locale"].is_null());
        assert!(val["section_id"].is_null());
        assert!(val["created_at"].is_null());
        assert!(val["updated_at"].is_null());
        assert!(val["draft"].is_null());
    }

    // ── User ──────────────────────────────────────────────────────────

    #[test]
    fn user_serde_roundtrip() {
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
        assert_eq!(back.id, Some(300));
        assert_eq!(back.name.as_deref(), Some("Alice"));
        assert_eq!(back.email.as_deref(), Some("alice@example.com"));
        assert_eq!(back.role.as_deref(), Some("admin"));
        assert_eq!(back.active, Some(true));
    }

    #[test]
    fn user_empty_object() {
        let user: User = serde_json::from_value(json!({})).unwrap();
        assert!(user.id.is_none());
        assert!(user.url.is_none());
        assert!(user.name.is_none());
        assert!(user.email.is_none());
        assert!(user.role.is_none());
        assert!(user.active.is_none());
        assert!(user.created_at.is_none());
        assert!(user.updated_at.is_none());
    }

    #[test]
    fn user_inactive() {
        let json = json!({"active": false, "name": "Inactive User"});
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.active, Some(false));
    }

    #[test]
    fn user_full_fields() {
        let json = json!({
            "id": 777,
            "url": "https://acme.zendesk.com/api/v2/users/777.json",
            "name": "Bob Smith",
            "email": "bob@acme.com",
            "role": "agent",
            "active": true,
            "created_at": "2025-06-01T00:00:00Z",
            "updated_at": "2026-03-05T12:00:00Z"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, Some(777));
        assert!(user.url.is_some());
        assert_eq!(user.role.as_deref(), Some("agent"));
        assert!(user.created_at.is_some());
        assert!(user.updated_at.is_some());
    }

    #[test]
    fn user_clone() {
        let user = User {
            id: Some(42),
            url: None,
            name: Some("Clone".into()),
            email: Some("clone@test.com".into()),
            role: None,
            active: Some(true),
            created_at: None,
            updated_at: None,
        };
        let cloned = user.clone();
        assert_eq!(cloned.id, user.id);
        assert_eq!(cloned.name, user.name);
        assert_eq!(cloned.email, user.email);
        assert_eq!(cloned.active, user.active);
    }

    #[test]
    fn user_debug() {
        let user = User {
            id: Some(55),
            url: None,
            name: Some("Debug user".into()),
            email: None,
            role: None,
            active: None,
            created_at: None,
            updated_at: None,
        };
        let dbg = format!("{user:?}");
        assert!(dbg.contains("User"), "got: {dbg}");
        assert!(dbg.contains("55"), "got: {dbg}");
    }

    #[test]
    fn user_null_fields_serialize() {
        let user = User {
            id: None,
            url: None,
            name: None,
            email: None,
            role: None,
            active: None,
            created_at: None,
            updated_at: None,
        };
        let val: serde_json::Value = serde_json::to_value(&user).unwrap();
        assert!(val["id"].is_null());
        assert!(val["url"].is_null());
        assert!(val["name"].is_null());
        assert!(val["email"].is_null());
        assert!(val["role"].is_null());
        assert!(val["active"].is_null());
        assert!(val["created_at"].is_null());
        assert!(val["updated_at"].is_null());
    }

    #[test]
    fn user_various_roles() {
        for role in ["admin", "agent", "end-user"] {
            let json = json!({"role": role});
            let user: User = serde_json::from_value(json).unwrap();
            assert_eq!(user.role.as_deref(), Some(role));
        }
    }

    // ── ApiErrorResponse ──────────────────────────────────────────────

    #[test]
    fn api_error_response_full() {
        let json = json!({
            "error": "RecordNotFound",
            "message": "Not Found",
            "description": "Ticket not found"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("RecordNotFound"));
        assert_eq!(err.message.as_deref(), Some("Not Found"));
        assert_eq!(err.description.as_deref(), Some("Ticket not found"));
    }

    #[test]
    fn api_error_response_empty_object() {
        let err: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(err.error.is_none());
        assert!(err.message.is_none());
        assert!(err.description.is_none());
    }

    #[test]
    fn api_error_response_only_error() {
        let json = json!({"error": "InvalidCredentials"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("InvalidCredentials"));
        assert!(err.message.is_none());
        assert!(err.description.is_none());
    }

    #[test]
    fn api_error_response_only_message() {
        let json = json!({"message": "Something went wrong"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error.is_none());
        assert_eq!(err.message.as_deref(), Some("Something went wrong"));
    }

    #[test]
    fn api_error_response_only_description() {
        let json = json!({"description": "Detailed error info"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error.is_none());
        assert!(err.message.is_none());
        assert_eq!(err.description.as_deref(), Some("Detailed error info"));
    }

    #[test]
    fn api_error_response_clone() {
        let err = ApiErrorResponse {
            error: Some("TestError".into()),
            message: Some("test msg".into()),
            description: None,
        };
        let cloned = err.clone();
        assert_eq!(cloned.error, err.error);
        assert_eq!(cloned.message, err.message);
        assert_eq!(cloned.description, err.description);
    }

    #[test]
    fn api_error_response_debug() {
        let err = ApiErrorResponse {
            error: Some("Debug".into()),
            message: None,
            description: None,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ApiErrorResponse"), "got: {dbg}");
        assert!(dbg.contains("Debug"), "got: {dbg}");
    }

    // ── Cross-type tests ──────────────────────────────────────────────

    #[test]
    fn ticket_skips_unknown_fields() {
        let json = json!({
            "id": 1,
            "subject": "test",
            "extra_unknown_field": "should be ignored",
            "another_field": 42
        });
        let ticket: Ticket = serde_json::from_value(json).unwrap();
        assert_eq!(ticket.id, Some(1));
        assert_eq!(ticket.subject.as_deref(), Some("test"));
    }

    #[test]
    fn comment_ignores_extra_fields() {
        let json = json!({
            "id": 1,
            "body": "test",
            "attachments": [{"file": "a.png"}]
        });
        let comment: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.id, Some(1));
    }

    #[test]
    fn article_ignores_extra_fields() {
        let json = json!({
            "id": 1,
            "title": "test",
            "author_id": 99,
            "vote_count": 5
        });
        let article: Article = serde_json::from_value(json).unwrap();
        assert_eq!(article.id, Some(1));
    }

    #[test]
    fn user_ignores_extra_fields() {
        let json = json!({
            "id": 1,
            "name": "test",
            "organization_id": 77,
            "phone": "+1234567890"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, Some(1));
    }

    #[test]
    fn api_error_response_ignores_extra_fields() {
        let json = json!({
            "error": "test",
            "message": "msg",
            "details": {"field": "value"}
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("test"));
    }

    // ── Value roundtrip via JSON string ───────────────────────────────

    #[test]
    fn ticket_json_string_roundtrip() {
        let ticket = Ticket {
            id: Some(555),
            url: None,
            subject: Some("roundtrip".into()),
            description: None,
            status: Some("solved".into()),
            priority: Some("low".into()),
            ticket_type: None,
            requester_id: None,
            assignee_id: None,
            group_id: None,
            tags: Some(vec!["a".into()]),
            created_at: None,
            updated_at: None,
            custom_fields: None,
        };
        let s = serde_json::to_string(&ticket).unwrap();
        let back: Ticket = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(555));
        assert_eq!(back.status.as_deref(), Some("solved"));
        assert_eq!(back.priority.as_deref(), Some("low"));
        assert_eq!(back.tags.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn comment_json_string_roundtrip() {
        let comment = Comment {
            id: Some(888),
            body: Some("roundtrip body".into()),
            html_body: Some("<b>bold</b>".into()),
            author_id: Some(11),
            public: Some(false),
            created_at: Some("2026-03-05T00:00:00Z".into()),
        };
        let s = serde_json::to_string(&comment).unwrap();
        let back: Comment = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(888));
        assert_eq!(back.public, Some(false));
        assert_eq!(back.html_body.as_deref(), Some("<b>bold</b>"));
    }

    #[test]
    fn article_json_string_roundtrip() {
        let article = Article {
            id: Some(444),
            url: Some("https://test.zendesk.com/api/v2/help_center/articles/444.json".into()),
            html_url: Some("https://test.zendesk.com/hc/en-us/articles/444".into()),
            title: Some("Roundtrip article".into()),
            body: Some("<p>content</p>".into()),
            locale: Some("en-us".into()),
            section_id: Some(12),
            created_at: Some("2026-01-01T00:00:00Z".into()),
            updated_at: Some("2026-03-01T00:00:00Z".into()),
            draft: Some(false),
        };
        let s = serde_json::to_string(&article).unwrap();
        let back: Article = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(444));
        assert_eq!(back.locale.as_deref(), Some("en-us"));
        assert_eq!(back.draft, Some(false));
    }

    #[test]
    fn user_json_string_roundtrip() {
        let user = User {
            id: Some(999),
            url: Some("https://test.zendesk.com/api/v2/users/999.json".into()),
            name: Some("Roundtrip User".into()),
            email: Some("rt@example.com".into()),
            role: Some("end-user".into()),
            active: Some(true),
            created_at: Some("2025-01-01T00:00:00Z".into()),
            updated_at: Some("2026-03-05T00:00:00Z".into()),
        };
        let s = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(999));
        assert_eq!(back.role.as_deref(), Some("end-user"));
        assert_eq!(back.active, Some(true));
    }
}
