//! `ClickUp` API types.

use serde::{Deserialize, Serialize};

/// A `ClickUp` space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Space {
    pub id: String,
    pub name: Option<String>,
    pub private: Option<bool>,
    pub color: Option<String>,
}

/// A `ClickUp` list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct List {
    pub id: String,
    pub name: Option<String>,
    pub content: Option<String>,
    pub task_count: Option<u64>,
    pub archived: Option<bool>,
}

/// A `ClickUp` task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<TaskStatus>,
    pub priority: Option<TaskPriority>,
    pub url: Option<String>,
    pub list: Option<TaskList>,
}

/// Task status info returned by the `ClickUp` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatus {
    pub status: Option<String>,
    pub color: Option<String>,
    #[serde(rename = "type")]
    pub status_type: Option<String>,
}

/// Task priority info returned by the `ClickUp` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPriority {
    pub id: Option<String>,
    pub priority: Option<String>,
    pub color: Option<String>,
}

/// Embedded list reference within a `ClickUp` task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskList {
    pub id: Option<String>,
    pub name: Option<String>,
}

/// `ClickUp` API error response body.
///
/// `ClickUp` returns `{"err": "message", "ECODE": "CODE"}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from `ClickUp`.
    pub err: Option<String>,
    /// The error code (e.g., `"ITEM_NOT_FOUND"`).
    #[serde(rename = "ECODE")]
    pub ecode: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn space_roundtrip() {
        let s: Space = serde_json::from_value(json!({
            "id": "space_abc123",
            "name": "Engineering",
            "private": false,
            "color": "#7B68EE",
        }))
        .unwrap();
        assert_eq!(s.id, "space_abc123");
        assert_eq!(s.name, Some("Engineering".into()));
        assert_eq!(s.private, Some(false));
        assert_eq!(s.color, Some("#7B68EE".into()));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["name"], "Engineering");
    }

    #[test]
    fn space_minimal() {
        let s: Space = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(s.id, "x");
        assert!(s.name.is_none());
        assert!(s.private.is_none());
        assert!(s.color.is_none());
    }

    #[test]
    fn list_roundtrip() {
        let l: List = serde_json::from_value(json!({
            "id": "list_abc123",
            "name": "Sprint Backlog",
            "content": "Current sprint items",
            "task_count": 15,
            "archived": false,
        }))
        .unwrap();
        assert_eq!(l.id, "list_abc123");
        assert_eq!(l.name, Some("Sprint Backlog".into()));
        assert_eq!(l.content, Some("Current sprint items".into()));
        assert_eq!(l.task_count, Some(15));
        assert_eq!(l.archived, Some(false));
        let re = serde_json::to_value(&l).unwrap();
        assert_eq!(re["name"], "Sprint Backlog");
    }

    #[test]
    fn list_minimal() {
        let l: List = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(l.id, "x");
        assert!(l.name.is_none());
        assert!(l.content.is_none());
        assert!(l.task_count.is_none());
    }

    #[test]
    fn task_roundtrip() {
        let t: Task = serde_json::from_value(json!({
            "id": "task_abc123",
            "name": "Implement login page",
            "description": "Build the login form",
            "status": {
                "status": "in progress",
                "color": "#4194f6",
                "type": "custom",
            },
            "priority": {
                "id": "1",
                "priority": "urgent",
                "color": "#f50000",
            },
            "url": "https://app.clickup.com/t/task_abc123",
            "list": {
                "id": "list_1",
                "name": "Sprint 1",
            },
        }))
        .unwrap();
        assert_eq!(t.id, "task_abc123");
        assert_eq!(t.name, Some("Implement login page".into()));
        assert_eq!(t.description, Some("Build the login form".into()));
        assert!(t.status.is_some());
        let status = t.status.unwrap();
        assert_eq!(status.status, Some("in progress".into()));
        assert_eq!(status.status_type, Some("custom".into()));
        assert!(t.priority.is_some());
        let priority = t.priority.unwrap();
        assert_eq!(priority.priority, Some("urgent".into()));
        assert!(t.list.is_some());
        let list = t.list.unwrap();
        assert_eq!(list.id, Some("list_1".into()));
    }

    #[test]
    fn task_minimal() {
        let t: Task = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(t.id, "x");
        assert!(t.name.is_none());
        assert!(t.status.is_none());
        assert!(t.priority.is_none());
        assert!(t.list.is_none());
    }

    #[test]
    fn task_serialize_roundtrip() {
        let t = Task {
            id: "t1".into(),
            name: Some("Do thing".into()),
            description: None,
            status: None,
            priority: None,
            url: None,
            list: Some(TaskList {
                id: Some("l1".into()),
                name: Some("List A".into()),
            }),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["id"], "t1");
        assert_eq!(v["name"], "Do thing");
        assert_eq!(v["list"]["id"], "l1");
    }

    #[test]
    fn task_status_roundtrip() {
        let s: TaskStatus = serde_json::from_value(json!({
            "status": "open",
            "color": "#d3d3d3",
            "type": "open",
        }))
        .unwrap();
        assert_eq!(s.status, Some("open".into()));
        assert_eq!(s.color, Some("#d3d3d3".into()));
        assert_eq!(s.status_type, Some("open".into()));
    }

    #[test]
    fn task_priority_roundtrip() {
        let p: TaskPriority = serde_json::from_value(json!({
            "id": "2",
            "priority": "high",
            "color": "#ffcc00",
        }))
        .unwrap();
        assert_eq!(p.id, Some("2".into()));
        assert_eq!(p.priority, Some("high".into()));
        assert_eq!(p.color, Some("#ffcc00".into()));
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "err": "Team not found",
            "ECODE": "ITEM_NOT_FOUND",
        }))
        .unwrap();
        assert_eq!(e.err, Some("Team not found".into()));
        assert_eq!(e.ecode, Some("ITEM_NOT_FOUND".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.err.is_none());
        assert!(e.ecode.is_none());
    }

    #[test]
    fn api_error_response_err_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "err": "Rate limit exceeded",
        }))
        .unwrap();
        assert_eq!(e.err, Some("Rate limit exceeded".into()));
        assert!(e.ecode.is_none());
    }

    #[test]
    fn space_extra_fields_ignored() {
        let s: Space = serde_json::from_value(json!({
            "id": "s1",
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(s.id, "s1");
        assert_eq!(s.name, Some("Test".into()));
    }

    #[test]
    fn list_extra_fields_ignored() {
        let l: List = serde_json::from_value(json!({
            "id": "l1",
            "name": "Test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(l.id, "l1");
        assert_eq!(l.name, Some("Test".into()));
    }

    #[test]
    fn task_extra_fields_ignored() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "name": "Test",
            "unknown_field": true,
        }))
        .unwrap();
        assert_eq!(t.id, "t1");
        assert_eq!(t.name, Some("Test".into()));
    }

    // ── Clone / Debug trait tests ─────────────────────────────────

    #[test]
    fn space_clone() {
        let s = Space {
            id: "s1".into(),
            name: Some("eng".into()),
            private: Some(true),
            color: None,
        };
        let cloned = s.clone();
        assert_eq!(s.id, "s1");
        assert_eq!(cloned.id, "s1");
        assert_eq!(cloned.private, Some(true));
    }

    #[test]
    fn space_debug() {
        let s: Space = serde_json::from_value(json!({"id": "s1", "name": "Dev"})).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Space"));
        assert!(dbg.contains("Dev"));
    }

    #[test]
    fn list_clone_and_debug() {
        let l = List {
            id: "l1".into(),
            name: Some("Backlog".into()),
            content: None,
            task_count: Some(42),
            archived: Some(false),
        };
        let cloned = l.clone();
        assert_eq!(l.id, "l1");
        assert_eq!(cloned.task_count, Some(42));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("List"));
        assert!(dbg.contains("Backlog"));
    }

    #[test]
    fn task_clone_and_debug() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "name": "Test Task",
        }))
        .unwrap();
        let cloned = t.clone();
        assert_eq!(t.id, "t1");
        assert_eq!(cloned.name.as_deref(), Some("Test Task"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("Task"));
    }

    #[test]
    fn task_status_clone_and_debug() {
        let s = TaskStatus {
            status: Some("done".into()),
            color: Some("#000".into()),
            status_type: Some("closed".into()),
        };
        let cloned = s.clone();
        assert_eq!(s.color.as_deref(), Some("#000"));
        assert_eq!(cloned.status.as_deref(), Some("done"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("TaskStatus"));
    }

    #[test]
    fn task_priority_clone_and_debug() {
        let p = TaskPriority {
            id: Some("3".into()),
            priority: Some("normal".into()),
            color: Some("#6fddff".into()),
        };
        let cloned = p.clone();
        assert_eq!(p.id.as_deref(), Some("3"));
        assert_eq!(cloned.priority.as_deref(), Some("normal"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("TaskPriority"));
    }

    #[test]
    fn task_list_clone_and_debug() {
        let l = TaskList {
            id: Some("l1".into()),
            name: Some("Sprint".into()),
        };
        let cloned = l.clone();
        assert_eq!(l.id.as_deref(), Some("l1"));
        assert_eq!(cloned.name.as_deref(), Some("Sprint"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("TaskList"));
    }

    // ── Null field handling ───────────────────────────────────────

    #[test]
    fn space_with_null_fields() {
        let s: Space = serde_json::from_value(json!({
            "id": "s1",
            "name": null,
            "private": null,
            "color": null,
        }))
        .unwrap();
        assert!(s.name.is_none());
        assert!(s.private.is_none());
        assert!(s.color.is_none());
    }

    #[test]
    fn list_with_null_fields() {
        let l: List = serde_json::from_value(json!({
            "id": "l1",
            "name": null,
            "content": null,
            "task_count": null,
            "archived": null,
        }))
        .unwrap();
        assert!(l.name.is_none());
        assert!(l.task_count.is_none());
        assert!(l.archived.is_none());
    }

    #[test]
    fn task_with_null_nested() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "status": null,
            "priority": null,
            "list": null,
        }))
        .unwrap();
        assert!(t.status.is_none());
        assert!(t.priority.is_none());
        assert!(t.list.is_none());
    }

    // ── Serialize roundtrips ──────────────────────────────────────

    #[test]
    fn space_serialize_roundtrip() {
        let s = Space {
            id: "s1".into(),
            name: Some("Test".into()),
            private: Some(true),
            color: Some("#ff0000".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        let back: Space = serde_json::from_value(v).unwrap();
        assert_eq!(back.id, "s1");
        assert_eq!(back.private, Some(true));
    }

    #[test]
    fn list_serialize_roundtrip() {
        let l = List {
            id: "l1".into(),
            name: Some("Sprint 3".into()),
            content: Some("desc".into()),
            task_count: Some(10),
            archived: Some(false),
        };
        let v = serde_json::to_value(&l).unwrap();
        let back: List = serde_json::from_value(v).unwrap();
        assert_eq!(back.task_count, Some(10));
    }

    #[test]
    fn task_status_type_rename() {
        let s: TaskStatus = serde_json::from_value(json!({
            "type": "custom"
        }))
        .unwrap();
        assert_eq!(s.status_type.as_deref(), Some("custom"));
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["type"], "custom");
        // Ensure the Rust field name is not in the output
        assert!(v.get("status_type").is_none());
    }

    #[test]
    fn task_status_minimal() {
        let s: TaskStatus = serde_json::from_value(json!({})).unwrap();
        assert!(s.status.is_none());
        assert!(s.color.is_none());
        assert!(s.status_type.is_none());
    }

    #[test]
    fn task_priority_minimal() {
        let p: TaskPriority = serde_json::from_value(json!({})).unwrap();
        assert!(p.id.is_none());
        assert!(p.priority.is_none());
        assert!(p.color.is_none());
    }

    #[test]
    fn task_list_minimal() {
        let l: TaskList = serde_json::from_value(json!({})).unwrap();
        assert!(l.id.is_none());
        assert!(l.name.is_none());
    }

    // ── ApiErrorResponse edge cases ───────────────────────────────

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            err: Some("error".into()),
            ecode: Some("ITEM_NOT_FOUND".into()),
        };
        let cloned = e.clone();
        assert_eq!(e.ecode.as_deref(), Some("ITEM_NOT_FOUND"));
        assert_eq!(cloned.err.as_deref(), Some("error"));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"err": "test"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn api_error_response_ecode_rename() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "ECODE": "OAUTH_017"
        }))
        .unwrap();
        assert_eq!(e.ecode.as_deref(), Some("OAUTH_017"));
    }

    // ── Large task count ──────────────────────────────────────────

    #[test]
    fn list_large_task_count() {
        let l: List = serde_json::from_value(json!({
            "id": "l1",
            "task_count": 999999,
        }))
        .unwrap();
        assert_eq!(l.task_count, Some(999_999));
    }

    #[test]
    fn task_with_url() {
        let t: Task = serde_json::from_value(json!({
            "id": "t1",
            "url": "https://app.clickup.com/t/task_abc123",
        }))
        .unwrap();
        assert_eq!(
            t.url.as_deref(),
            Some("https://app.clickup.com/t/task_abc123")
        );
    }
}
