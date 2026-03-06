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

    // ── Contact extended tests ──────────────────────────────────────

    #[test]
    fn contact_clone() {
        let c: Contact = serde_json::from_value(json!({"id": "c1", "name": "Bob"})).unwrap();
        let c2 = c.clone();
        assert_eq!(c.id, "c1");
        assert_eq!(c2.name, Some("Bob".into()));
    }

    #[test]
    fn contact_debug() {
        let c: Contact = serde_json::from_value(json!({"id": "d1"})).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("d1"));
    }

    #[test]
    fn contact_all_fields() {
        let c: Contact = serde_json::from_value(json!({
            "id": "full",
            "type": "contact",
            "role": "lead",
            "email": "bob@example.com",
            "name": "Bob",
            "phone": "+15551234567",
            "created_at": 1_700_000_000,
            "updated_at": 1_700_001_000,
            "external_id": "ext-999"
        }))
        .unwrap();
        assert_eq!(c.contact_type, Some("contact".into()));
        assert_eq!(c.phone, Some("+15551234567".into()));
        assert_eq!(c.external_id, Some("ext-999".into()));
        assert_eq!(c.created_at, Some(1_700_000_000));
        assert_eq!(c.updated_at, Some(1_700_001_000));
    }

    #[test]
    fn contact_serialize_preserves_type_rename() {
        let c: Contact = serde_json::from_value(json!({
            "id": "r1",
            "type": "contact"
        }))
        .unwrap();
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["type"], "contact");
        assert!(v.get("contact_type").is_none());
    }

    #[test]
    fn contact_empty_string_fields() {
        let c: Contact = serde_json::from_value(json!({
            "id": "",
            "email": "",
            "name": ""
        }))
        .unwrap();
        assert_eq!(c.id, "");
        assert_eq!(c.email, Some(String::new()));
        assert_eq!(c.name, Some(String::new()));
    }

    // ── ContactList extended tests ──────────────────────────────────

    #[test]
    fn contact_list_empty_data() {
        let cl: ContactList = serde_json::from_value(json!({
            "type": "list",
            "data": [],
            "total_count": 0
        }))
        .unwrap();
        assert!(cl.data.is_empty());
        assert_eq!(cl.total_count, Some(0));
    }

    #[test]
    fn contact_list_clone() {
        let cl: ContactList = serde_json::from_value(json!({
            "type": "list",
            "data": [{"id": "c1"}]
        }))
        .unwrap();
        let cl2 = cl.clone();
        assert_eq!(cl.data.len(), 1);
        assert_eq!(cl2.list_type, Some("list".into()));
    }

    #[test]
    fn contact_list_debug() {
        let cl: ContactList = serde_json::from_value(json!({
            "data": []
        }))
        .unwrap();
        let dbg = format!("{cl:?}");
        assert!(dbg.contains("ContactList"));
    }

    #[test]
    fn contact_list_without_pages() {
        let cl: ContactList = serde_json::from_value(json!({
            "data": [{"id": "x"}]
        }))
        .unwrap();
        assert!(cl.pages.is_none());
        assert!(cl.list_type.is_none());
    }

    // ── Conversation extended tests ─────────────────────────────────

    #[test]
    fn conversation_all_fields() {
        let c: Conversation = serde_json::from_value(json!({
            "id": "conv-full",
            "type": "conversation",
            "title": "Full conversation",
            "created_at": 1_700_000_000,
            "updated_at": 1_700_001_000,
            "state": "closed",
            "open": false,
            "read": true,
            "source": {"type": "email"},
            "contacts": {"contacts": [{"id": "c1"}]},
            "assignee": {"type": "admin", "id": "admin-1"},
            "tags": {"tags": [{"id": "t1", "name": "vip"}]},
            "statistics": {"time_to_assignment": 60}
        }))
        .unwrap();
        assert_eq!(c.conversation_type, Some("conversation".into()));
        assert_eq!(c.title, Some("Full conversation".into()));
        assert_eq!(c.state, Some("closed".into()));
        assert_eq!(c.open, Some(false));
        assert_eq!(c.read, Some(true));
        assert!(c.source.is_some());
        assert!(c.contacts.is_some());
        assert!(c.assignee.is_some());
        assert!(c.tags.is_some());
        assert!(c.statistics.is_some());
    }

    #[test]
    fn conversation_minimal() {
        let c: Conversation = serde_json::from_value(json!({"id": "min"})).unwrap();
        assert_eq!(c.id, "min");
        assert!(c.title.is_none());
        assert!(c.state.is_none());
        assert!(c.open.is_none());
        assert!(c.source.is_none());
    }

    #[test]
    fn conversation_clone() {
        let c: Conversation = serde_json::from_value(json!({"id": "cc1", "title": "Hi"})).unwrap();
        let c2 = c.clone();
        assert_eq!(c.id, "cc1");
        assert_eq!(c2.title, Some("Hi".into()));
    }

    #[test]
    fn conversation_debug() {
        let c: Conversation = serde_json::from_value(json!({"id": "dbg"})).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Conversation"));
    }

    // ── ConversationList extended tests ─────────────────────────────

    #[test]
    fn conversation_list_empty() {
        let cl: ConversationList = serde_json::from_value(json!({
            "conversations": [],
            "total_count": 0
        }))
        .unwrap();
        assert!(cl.conversations.is_empty());
    }

    #[test]
    fn conversation_list_clone() {
        let cl: ConversationList = serde_json::from_value(json!({
            "conversations": [{"id": "c1"}]
        }))
        .unwrap();
        let cl2 = cl.clone();
        assert_eq!(cl.conversations.len(), 1);
        assert!(cl2.list_type.is_none());
    }

    // ── ConversationReply extended tests ────────────────────────────

    #[test]
    fn conversation_reply_minimal() {
        let r: ConversationReply = serde_json::from_value(json!({"id": "r-min"})).unwrap();
        assert_eq!(r.id, "r-min");
        assert!(r.reply_type.is_none());
        assert!(r.body.is_none());
        assert!(r.created_at.is_none());
    }

    #[test]
    fn conversation_reply_clone() {
        let r: ConversationReply = serde_json::from_value(json!({"id": "rc", "body": "hi"})).unwrap();
        let r2 = r.clone();
        assert_eq!(r.id, "rc");
        assert_eq!(r2.body, Some("hi".into()));
    }

    #[test]
    fn conversation_reply_serialize_type_rename() {
        let r: ConversationReply = serde_json::from_value(json!({
            "id": "r1",
            "type": "note"
        }))
        .unwrap();
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["type"], "note");
        assert!(v.get("reply_type").is_none());
    }

    // ── Tag extended tests ──────────────────────────────────────────

    #[test]
    fn tag_minimal() {
        let t: Tag = serde_json::from_value(json!({"id": "t1", "name": "Basic"})).unwrap();
        assert_eq!(t.id, "t1");
        assert_eq!(t.name, "Basic");
        assert!(t.tag_type.is_none());
    }

    #[test]
    fn tag_clone() {
        let t: Tag = serde_json::from_value(json!({"id": "tc", "name": "X"})).unwrap();
        let t2 = t.clone();
        assert_eq!(t.id, "tc");
        assert_eq!(t2.name, "X");
    }

    #[test]
    fn tag_debug() {
        let t: Tag = serde_json::from_value(json!({"id": "td", "name": "Debug"})).unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Tag"));
        assert!(dbg.contains("Debug"));
    }

    #[test]
    fn tag_serialize_type_rename() {
        let t: Tag = serde_json::from_value(json!({"id": "t1", "type": "tag", "name": "VIP"})).unwrap();
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["type"], "tag");
        assert!(v.get("tag_type").is_none());
    }

    // ── TagList extended tests ──────────────────────────────────────

    #[test]
    fn tag_list_empty() {
        let tl: TagList = serde_json::from_value(json!({
            "type": "list",
            "data": []
        }))
        .unwrap();
        assert!(tl.data.is_empty());
    }

    #[test]
    fn tag_list_clone() {
        let tl: TagList = serde_json::from_value(json!({"data": []})).unwrap();
        let tl2 = tl.clone();
        assert!(tl.data.is_empty());
        assert!(tl2.list_type.is_none());
    }

    #[test]
    fn tag_list_debug() {
        let tl: TagList = serde_json::from_value(json!({"data": []})).unwrap();
        let dbg = format!("{tl:?}");
        assert!(dbg.contains("TagList"));
    }

    // ── Pages extended tests ────────────────────────────────────────

    #[test]
    fn pages_minimal() {
        let p: Pages = serde_json::from_value(json!({})).unwrap();
        assert!(p.page.is_none());
        assert!(p.per_page.is_none());
        assert!(p.total_pages.is_none());
        assert!(p.next.is_none());
    }

    #[test]
    fn pages_clone() {
        let p: Pages = serde_json::from_value(json!({"page": 1})).unwrap();
        let p2 = p.clone();
        assert_eq!(p.page, Some(1));
        assert!(p2.next.is_none());
    }

    #[test]
    fn pages_debug() {
        let p: Pages = serde_json::from_value(json!({"page": 5})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Pages"));
        assert!(dbg.contains('5'));
    }

    #[test]
    fn pages_serialize_roundtrip() {
        let p: Pages = serde_json::from_value(json!({
            "page": 3,
            "per_page": 25,
            "total_pages": 10,
            "next": {"page": 4, "starting_after": "cursor123"}
        }))
        .unwrap();
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["page"], 3);
        assert_eq!(v["per_page"], 25);
        assert_eq!(v["total_pages"], 10);
        assert_eq!(v["next"]["starting_after"], "cursor123");
    }

    // ── NextPage extended tests ─────────────────────────────────────

    #[test]
    fn next_page_minimal() {
        let np: NextPage = serde_json::from_value(json!({})).unwrap();
        assert!(np.page.is_none());
        assert!(np.starting_after.is_none());
    }

    #[test]
    fn next_page_clone() {
        let np: NextPage = serde_json::from_value(json!({"starting_after": "abc"})).unwrap();
        let np2 = np.clone();
        assert_eq!(np.starting_after, Some("abc".into()));
        assert!(np2.page.is_none());
    }

    #[test]
    fn next_page_debug() {
        let np: NextPage = serde_json::from_value(json!({"page": 7})).unwrap();
        let dbg = format!("{np:?}");
        assert!(dbg.contains("NextPage"));
    }

    #[test]
    fn next_page_serialize_roundtrip() {
        let np: NextPage = serde_json::from_value(json!({"page": 2, "starting_after": "xyz"})).unwrap();
        let v = serde_json::to_value(&np).unwrap();
        assert_eq!(v["page"], 2);
        assert_eq!(v["starting_after"], "xyz");
    }

    // ── ApiErrorResponse extended tests ─────────────────────────────

    #[test]
    fn api_error_response_no_errors_list() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "error.list",
            "message": "Something went wrong"
        }))
        .unwrap();
        assert_eq!(e.message, Some("Something went wrong".into()));
        assert!(e.errors.is_none());
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "error.list",
            "message": "Error",
            "request_id": "req-abc"
        }))
        .unwrap();
        let e2 = e.clone();
        assert_eq!(e.message, Some("Error".into()));
        assert_eq!(e2.request_id, Some("req-abc".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_response_multiple_errors() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errors": [
                {"code": "err1", "message": "first error"},
                {"code": "err2", "message": "second error"}
            ]
        }))
        .unwrap();
        let errs = e.errors.unwrap();
        assert_eq!(errs.len(), 2);
        assert_eq!(errs[0].code, Some("err1".into()));
        assert_eq!(errs[1].message, Some("second error".into()));
    }

    // ── ApiError extended tests ─────────────────────────────────────

    #[test]
    fn api_error_minimal() {
        let e: ApiError = serde_json::from_value(json!({})).unwrap();
        assert!(e.code.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_clone() {
        let e: ApiError = serde_json::from_value(json!({"code": "not_found", "message": "missing"})).unwrap();
        let e2 = e.clone();
        assert_eq!(e.code, Some("not_found".into()));
        assert_eq!(e2.message, Some("missing".into()));
    }

    #[test]
    fn api_error_debug() {
        let e: ApiError = serde_json::from_value(json!({"code": "rate_limit"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiError"));
    }
}
