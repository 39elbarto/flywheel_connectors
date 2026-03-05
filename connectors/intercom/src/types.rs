//! `Intercom` API types.

use serde::{Deserialize, Serialize};

/// An `Intercom` contact (user or lead).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    #[serde(rename = "type")]
    pub contact_type: Option<String>,
    pub role: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
    pub external_id: Option<String>,
}

/// Paginated list of contacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactList {
    #[serde(rename = "type")]
    pub list_type: Option<String>,
    pub data: Vec<serde_json::Value>,
    pub total_count: Option<i64>,
    pub pages: Option<Pages>,
}

/// An `Intercom` conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    #[serde(rename = "type")]
    pub conversation_type: Option<String>,
    pub title: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
    pub state: Option<String>,
    pub open: Option<bool>,
    pub read: Option<bool>,
    pub source: Option<serde_json::Value>,
    pub contacts: Option<serde_json::Value>,
    pub assignee: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
    pub statistics: Option<serde_json::Value>,
}

/// Paginated list of conversations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationList {
    #[serde(rename = "type")]
    pub list_type: Option<String>,
    pub conversations: Vec<serde_json::Value>,
    pub total_count: Option<i64>,
    pub pages: Option<Pages>,
}

/// A conversation reply response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationReply {
    pub id: String,
    #[serde(rename = "type")]
    pub reply_type: Option<String>,
    pub body: Option<String>,
    pub created_at: Option<i64>,
}

/// An `Intercom` tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    #[serde(rename = "type")]
    pub tag_type: Option<String>,
    pub name: String,
}

/// Tag list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagList {
    #[serde(rename = "type")]
    pub list_type: Option<String>,
    pub data: Vec<serde_json::Value>,
}

/// Pagination info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pages {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub total_pages: Option<i64>,
    pub next: Option<NextPage>,
}

/// Next page cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextPage {
    pub page: Option<i64>,
    pub starting_after: Option<String>,
}

/// `Intercom` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub message: Option<String>,
    pub request_id: Option<String>,
    pub errors: Option<Vec<ApiError>>,
}

/// Individual error in an `Intercom` error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    pub code: Option<String>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn contact_roundtrip() {
        let c: Contact = serde_json::from_value(json!({
            "id": "abc123",
            "type": "contact",
            "role": "user",
            "email": "alice@example.com",
            "name": "Alice",
            "created_at": 1_709_251_200,
        }))
        .unwrap();
        assert_eq!(c.id, "abc123");
        assert_eq!(c.role, Some("user".into()));
        assert_eq!(c.email, Some("alice@example.com".into()));
        let re = serde_json::to_value(&c).unwrap();
        assert_eq!(re["name"], "Alice");
    }

    #[test]
    fn contact_minimal() {
        let c: Contact = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(c.id, "x");
        assert!(c.email.is_none());
        assert!(c.role.is_none());
    }

    #[test]
    fn contact_list_roundtrip() {
        let cl: ContactList = serde_json::from_value(json!({
            "type": "list",
            "data": [{"id": "c1", "role": "user"}],
            "total_count": 1,
            "pages": {"page": 1, "per_page": 50, "total_pages": 1}
        }))
        .unwrap();
        assert_eq!(cl.data.len(), 1);
        assert_eq!(cl.total_count, Some(1));
    }

    #[test]
    fn conversation_roundtrip() {
        let c: Conversation = serde_json::from_value(json!({
            "id": "conv1",
            "type": "conversation",
            "title": "Help request",
            "created_at": 1_709_251_200,
            "state": "open",
            "open": true,
            "read": false,
        }))
        .unwrap();
        assert_eq!(c.id, "conv1");
        assert_eq!(c.state, Some("open".into()));
        assert_eq!(c.open, Some(true));
    }

    #[test]
    fn conversation_list_roundtrip() {
        let cl: ConversationList = serde_json::from_value(json!({
            "type": "conversation.list",
            "conversations": [{"id": "c1"}, {"id": "c2"}],
            "total_count": 2,
            "pages": {"page": 1, "per_page": 20, "total_pages": 1}
        }))
        .unwrap();
        assert_eq!(cl.conversations.len(), 2);
        assert_eq!(cl.total_count, Some(2));
    }

    #[test]
    fn conversation_reply_roundtrip() {
        let r: ConversationReply = serde_json::from_value(json!({
            "id": "reply1",
            "type": "conversation_part",
            "body": "Thanks!",
            "created_at": 1_709_251_200,
        }))
        .unwrap();
        assert_eq!(r.id, "reply1");
        assert_eq!(r.body, Some("Thanks!".into()));
    }

    #[test]
    fn tag_roundtrip() {
        let t: Tag = serde_json::from_value(json!({
            "id": "tag1",
            "type": "tag",
            "name": "VIP",
        }))
        .unwrap();
        assert_eq!(t.name, "VIP");
        let re = serde_json::to_value(&t).unwrap();
        assert_eq!(re["id"], "tag1");
    }

    #[test]
    fn tag_list_roundtrip() {
        let tl: TagList = serde_json::from_value(json!({
            "type": "list",
            "data": [{"id": "t1", "name": "Urgent"}]
        }))
        .unwrap();
        assert_eq!(tl.data.len(), 1);
    }

    #[test]
    fn pages_roundtrip() {
        let p: Pages = serde_json::from_value(json!({
            "page": 2,
            "per_page": 50,
            "total_pages": 5,
            "next": {"page": 3, "starting_after": "abc"}
        }))
        .unwrap();
        assert_eq!(p.page, Some(2));
        assert_eq!(p.next.unwrap().starting_after, Some("abc".into()));
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "error.list",
            "message": "Not found",
            "request_id": "req-123",
            "errors": [{"code": "not_found", "message": "Contact not found"}]
        }))
        .unwrap();
        assert_eq!(e.message, Some("Not found".into()));
        assert_eq!(e.errors.unwrap()[0].code, Some("not_found".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.errors.is_none());
    }
}
