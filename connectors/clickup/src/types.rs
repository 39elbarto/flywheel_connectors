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
            list: Some(TaskList { id: Some("l1".into()), name: Some("List A".into()) }),
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
}
