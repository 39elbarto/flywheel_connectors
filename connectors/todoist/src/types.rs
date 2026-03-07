//! `Todoist` API types.

use serde::{Deserialize, Serialize};

/// A `Todoist` project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: Option<String>,
    pub color: Option<String>,
    pub comment_count: Option<u64>,
    pub is_shared: Option<bool>,
    pub is_favorite: Option<bool>,
    pub order: Option<i64>,
    pub url: Option<String>,
    pub view_style: Option<String>,
}

/// A `Todoist` task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub content: Option<String>,
    pub description: Option<String>,
    pub project_id: Option<String>,
    pub is_completed: Option<bool>,
    pub priority: Option<u8>,
    pub due: Option<Due>,
    pub url: Option<String>,
    pub comment_count: Option<u64>,
    pub order: Option<i64>,
}

/// Due date information for a `Todoist` task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Due {
    pub date: Option<String>,
    pub string: Option<String>,
    pub datetime: Option<String>,
    pub timezone: Option<String>,
    pub is_recurring: Option<bool>,
}

/// `Todoist` API error response body.
///
/// `Todoist` returns plain text or empty body on errors, so fields are optional.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(rename = "error")]
    pub error_message: Option<String>,
    pub error_code: Option<u16>,
    pub http_code: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn project_roundtrip() {
        let p: Project = serde_json::from_value(json!({
            "id": "proj_abc123",
            "name": "Work",
            "color": "blue",
            "comment_count": 5,
            "is_shared": false,
            "is_favorite": true,
            "order": 1,
            "url": "https://todoist.com/showProject?id=proj_abc123",
            "view_style": "list",
        }))
        .unwrap();
        assert_eq!(p.id, "proj_abc123");
        assert_eq!(p.name, Some("Work".into()));
        assert_eq!(p.color, Some("blue".into()));
        assert_eq!(p.comment_count, Some(5));
        assert_eq!(p.is_shared, Some(false));
        assert_eq!(p.is_favorite, Some(true));
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["name"], "Work");
    }

    #[test]
    fn project_minimal() {
        let p: Project = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(p.id, "x");
        assert!(p.name.is_none());
        assert!(p.color.is_none());
    }

    #[test]
    fn task_roundtrip() {
        let t: Task = serde_json::from_value(json!({
            "id": "task_abc123",
            "content": "Review PR #42",
            "description": "Important PR review",
            "project_id": "proj_abc",
            "is_completed": false,
            "priority": 4,
            "due": {
                "date": "2026-03-10",
                "string": "tomorrow",
                "is_recurring": false,
            },
            "url": "https://todoist.com/showTask?id=task_abc123",
            "comment_count": 3,
            "order": 2,
        }))
        .unwrap();
        assert_eq!(t.id, "task_abc123");
        assert_eq!(t.content, Some("Review PR #42".into()));
        assert_eq!(t.project_id, Some("proj_abc".into()));
        assert_eq!(t.is_completed, Some(false));
        assert_eq!(t.priority, Some(4));
        assert!(t.due.is_some());
        let due = t.due.unwrap();
        assert_eq!(due.date, Some("2026-03-10".into()));
        assert_eq!(due.string, Some("tomorrow".into()));
        assert_eq!(due.is_recurring, Some(false));
    }

    #[test]
    fn task_minimal() {
        let t: Task = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(t.id, "x");
        assert!(t.content.is_none());
        assert!(t.due.is_none());
    }

    #[test]
    fn task_serialize_roundtrip() {
        let t = Task {
            id: "t1".into(),
            content: Some("Do thing".into()),
            description: None,
            project_id: Some("p1".into()),
            is_completed: Some(false),
            priority: Some(1),
            due: None,
            url: None,
            comment_count: None,
            order: None,
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["id"], "t1");
        assert_eq!(v["content"], "Do thing");
        assert_eq!(v["project_id"], "p1");
    }

    #[test]
    fn due_roundtrip() {
        let d: Due = serde_json::from_value(json!({
            "date": "2026-03-15",
            "string": "next Monday",
            "datetime": "2026-03-15T09:00:00Z",
            "timezone": "America/New_York",
            "is_recurring": true,
        }))
        .unwrap();
        assert_eq!(d.date, Some("2026-03-15".into()));
        assert_eq!(d.string, Some("next Monday".into()));
        assert_eq!(d.datetime, Some("2026-03-15T09:00:00Z".into()));
        assert_eq!(d.timezone, Some("America/New_York".into()));
        assert_eq!(d.is_recurring, Some(true));
    }

    #[test]
    fn due_minimal() {
        let d: Due = serde_json::from_value(json!({})).unwrap();
        assert!(d.date.is_none());
        assert!(d.string.is_none());
        assert!(d.is_recurring.is_none());
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Invalid token",
            "error_code": 401,
            "http_code": 401,
        }))
        .unwrap();
        assert_eq!(e.error_message, Some("Invalid token".into()));
        assert_eq!(e.error_code, Some(401));
        assert_eq!(e.http_code, Some(401));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error_message.is_none());
        assert!(e.error_code.is_none());
        assert!(e.http_code.is_none());
    }

    #[test]
    fn project_extra_fields_ignored() {
        let p: Project = serde_json::from_value(json!({
            "id": "p1",
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(p.id, "p1");
        assert_eq!(p.name, Some("Test".into()));
    }

    #[test]
    fn task_extra_fields_ignored() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "content": "Test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(t.id, "t1");
        assert_eq!(t.content, Some("Test".into()));
    }

    // ── Project additional tests ────────────────────────────────────

    #[test]
    fn project_clone() {
        let p: Project = serde_json::from_value(json!({"id": "p1", "name": "Clone Test"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let p2 = p.clone();
        assert_eq!(p2.id, "p1");
        assert_eq!(p2.name, Some("Clone Test".into()));
    }

    #[test]
    fn project_debug() {
        let p: Project = serde_json::from_value(json!({"id": "dbg_proj"})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("dbg_proj"));
    }

    #[test]
    fn project_all_none_optionals() {
        let p: Project = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert!(p.name.is_none());
        assert!(p.color.is_none());
        assert!(p.comment_count.is_none());
        assert!(p.is_shared.is_none());
        assert!(p.is_favorite.is_none());
        assert!(p.order.is_none());
        assert!(p.url.is_none());
        assert!(p.view_style.is_none());
    }

    #[test]
    fn project_serialize_includes_all_set_fields() {
        let p = Project {
            id: "p1".into(),
            name: Some("Test".into()),
            color: Some("red".into()),
            comment_count: Some(0),
            is_shared: Some(true),
            is_favorite: Some(false),
            order: Some(99),
            url: Some("https://todoist.com/p1".into()),
            view_style: Some("board".into()),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["color"], "red");
        assert_eq!(v["order"], 99);
        assert_eq!(v["view_style"], "board");
    }

    // ── Task additional tests ───────────────────────────────────────

    #[test]
    fn task_clone() {
        let t: Task = serde_json::from_value(json!({"id": "t1", "content": "Clone"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let t2 = t.clone();
        assert_eq!(t2.id, "t1");
        assert_eq!(t2.content, Some("Clone".into()));
    }

    #[test]
    fn task_debug() {
        let t: Task = serde_json::from_value(json!({"id": "dbg_task"})).unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("dbg_task"));
    }

    #[test]
    fn task_all_none_optionals() {
        let t: Task = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert!(t.content.is_none());
        assert!(t.description.is_none());
        assert!(t.project_id.is_none());
        assert!(t.is_completed.is_none());
        assert!(t.priority.is_none());
        assert!(t.due.is_none());
        assert!(t.url.is_none());
        assert!(t.comment_count.is_none());
        assert!(t.order.is_none());
    }

    #[test]
    fn task_completed_true() {
        let t: Task = serde_json::from_value(json!({"id": "t1", "is_completed": true})).unwrap();
        assert_eq!(t.is_completed, Some(true));
    }

    #[test]
    fn task_priority_boundary_values() {
        // Todoist priority: 1 (normal) to 4 (urgent)
        let t1: Task = serde_json::from_value(json!({"id": "t1", "priority": 1})).unwrap();
        assert_eq!(t1.priority, Some(1));
        let t4: Task = serde_json::from_value(json!({"id": "t2", "priority": 4})).unwrap();
        assert_eq!(t4.priority, Some(4));
    }

    #[test]
    fn task_with_description() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "content": "Buy milk",
            "description": "From the organic store"
        }))
        .unwrap();
        assert_eq!(t.description, Some("From the organic store".into()));
    }

    // ── Due additional tests ────────────────────────────────────────

    #[test]
    fn due_clone() {
        let d: Due = serde_json::from_value(json!({"date": "2026-03-15"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let d2 = d.clone();
        assert_eq!(d2.date, Some("2026-03-15".into()));
    }

    #[test]
    fn due_debug() {
        let d: Due = serde_json::from_value(json!({"date": "2026-03-15"})).unwrap();
        let dbg = format!("{d:?}");
        assert!(dbg.contains("2026-03-15"));
    }

    #[test]
    fn due_serialize_roundtrip() {
        let d = Due {
            date: Some("2026-04-01".into()),
            string: Some("April 1st".into()),
            datetime: Some("2026-04-01T10:00:00Z".into()),
            timezone: Some("UTC".into()),
            is_recurring: Some(false),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["timezone"], "UTC");
        let d2: Due = serde_json::from_value(v).unwrap();
        assert_eq!(d2.timezone, Some("UTC".into()));
    }

    #[test]
    fn due_recurring_true() {
        let d: Due =
            serde_json::from_value(json!({"is_recurring": true, "string": "every day"})).unwrap();
        assert_eq!(d.is_recurring, Some(true));
        assert_eq!(d.string, Some("every day".into()));
    }

    // ── ApiErrorResponse additional tests ───────────────────────────

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"error": "test"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.error_message, Some("test".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"error": "debug_err"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("debug_err"));
    }

    #[test]
    fn api_error_response_all_none() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error_message.is_none());
        assert!(e.error_code.is_none());
        assert!(e.http_code.is_none());
    }

    #[test]
    fn api_error_response_different_codes() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Forbidden",
            "error_code": 403,
            "http_code": 403
        }))
        .unwrap();
        assert_eq!(e.error_code, Some(403));
        assert_eq!(e.http_code, Some(403));
    }

    // ── Additional type coverage tests ────────────────────────────

    #[test]
    fn project_serialize_roundtrip() {
        let p: Project = serde_json::from_value(json!({
            "id": "p1",
            "name": "Work",
            "color": "blue",
            "is_shared": false,
            "is_favorite": true
        }))
        .unwrap();
        let v = serde_json::to_value(&p).unwrap();
        let p2: Project = serde_json::from_value(v).unwrap();
        assert_eq!(p2.id, "p1");
        assert_eq!(p2.name, Some("Work".into()));
        assert_eq!(p2.color, Some("blue".into()));
    }

    #[test]
    fn project_empty_string_name() {
        let p: Project = serde_json::from_value(json!({
            "id": "p1",
            "name": ""
        }))
        .unwrap();
        assert_eq!(p.name, Some(String::new()));
    }

    #[test]
    fn task_serialize_with_due() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "content": "Test",
            "due": {
                "date": "2026-04-01",
                "string": "April 1",
                "is_recurring": false
            }
        }))
        .unwrap();
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["due"]["date"], "2026-04-01");
        assert_eq!(v["due"]["string"], "April 1");
    }

    #[test]
    fn task_high_priority() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "priority": 255
        }))
        .unwrap();
        assert_eq!(t.priority, Some(255));
    }

    #[test]
    fn task_zero_comment_count() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "comment_count": 0
        }))
        .unwrap();
        assert_eq!(t.comment_count, Some(0));
    }

    #[test]
    fn task_negative_order() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "order": -5
        }))
        .unwrap();
        assert_eq!(t.order, Some(-5));
    }

    #[test]
    fn due_all_none_optionals() {
        let d: Due = serde_json::from_value(json!({})).unwrap();
        assert!(d.date.is_none());
        assert!(d.string.is_none());
        assert!(d.datetime.is_none());
        assert!(d.timezone.is_none());
        assert!(d.is_recurring.is_none());
    }

    #[test]
    fn due_with_datetime_only() {
        let d: Due = serde_json::from_value(json!({
            "datetime": "2026-05-01T14:30:00Z"
        }))
        .unwrap();
        assert!(d.date.is_none());
        assert_eq!(d.datetime, Some("2026-05-01T14:30:00Z".into()));
    }

    #[test]
    fn due_empty_string_fields() {
        let d: Due = serde_json::from_value(json!({
            "date": "",
            "string": "",
            "timezone": ""
        }))
        .unwrap();
        assert_eq!(d.date, Some(String::new()));
        assert_eq!(d.string, Some(String::new()));
        assert_eq!(d.timezone, Some(String::new()));
    }

    #[test]
    fn project_view_style_board() {
        let p: Project = serde_json::from_value(json!({
            "id": "p1",
            "view_style": "board"
        }))
        .unwrap();
        assert_eq!(p.view_style, Some("board".into()));
    }

    #[test]
    fn project_large_comment_count() {
        let p: Project = serde_json::from_value(json!({
            "id": "p1",
            "comment_count": 999_999
        }))
        .unwrap();
        assert_eq!(p.comment_count, Some(999_999));
    }

    #[test]
    fn api_error_response_error_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Resource not found"
        }))
        .unwrap();
        assert_eq!(e.error_message, Some("Resource not found".into()));
        assert!(e.error_code.is_none());
        assert!(e.http_code.is_none());
    }

    #[test]
    fn api_error_response_extra_fields_ignored() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Bad request",
            "extra_field": "should be ignored"
        }))
        .unwrap();
        assert_eq!(e.error_message, Some("Bad request".into()));
    }

    #[test]
    fn task_url_value() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "url": "https://todoist.com/showTask?id=t1"
        }))
        .unwrap();
        assert_eq!(t.url, Some("https://todoist.com/showTask?id=t1".into()));
    }

    #[test]
    fn project_url_value() {
        let p: Project = serde_json::from_value(json!({
            "id": "p1",
            "url": "https://todoist.com/showProject?id=p1"
        }))
        .unwrap();
        assert_eq!(p.url, Some("https://todoist.com/showProject?id=p1".into()));
    }

    #[test]
    fn project_negative_order() {
        let p: Project = serde_json::from_value(json!({
            "id": "p1",
            "order": -10
        }))
        .unwrap();
        assert_eq!(p.order, Some(-10));
    }

    #[test]
    fn due_serialize_preserves_recurring() {
        let d = Due {
            date: None,
            string: Some("every week".into()),
            datetime: None,
            timezone: None,
            is_recurring: Some(true),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["is_recurring"], true);
        assert_eq!(v["string"], "every week");
    }
}
