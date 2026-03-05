//! Asana API types.

use serde::{Deserialize, Serialize};

/// A compact reference to an Asana resource (used in nested fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRef {
    pub gid: String,
    pub name: Option<String>,
}

/// An Asana workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub gid: String,
    pub name: Option<String>,
    pub is_organization: Option<bool>,
}

/// An Asana project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub gid: String,
    pub name: Option<String>,
    pub notes: Option<String>,
    pub color: Option<String>,
    pub archived: Option<bool>,
    pub workspace: Option<ResourceRef>,
}

/// An Asana task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub gid: String,
    pub name: Option<String>,
    pub notes: Option<String>,
    pub completed: Option<bool>,
    pub assignee: Option<ResourceRef>,
    pub projects: Option<Vec<ResourceRef>>,
    pub due_on: Option<String>,
}

/// An Asana section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub gid: String,
    pub name: Option<String>,
}

/// Asana API error response body.
///
/// Asana returns `{"errors": [{"message": "...", "help": "..."}]}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub errors: Option<Vec<ApiError>>,
}

/// Individual error from Asana API response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    pub message: Option<String>,
    pub help: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- ResourceRef --

    #[test]
    fn resource_ref_roundtrip() {
        let r: ResourceRef = serde_json::from_value(json!({
            "gid": "12345",
            "name": "Test Resource",
        }))
        .unwrap();
        assert_eq!(r.gid, "12345");
        assert_eq!(r.name, Some("Test Resource".into()));
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["gid"], "12345");
        assert_eq!(re["name"], "Test Resource");
    }

    #[test]
    fn resource_ref_minimal() {
        let r: ResourceRef = serde_json::from_value(json!({"gid": "99"})).unwrap();
        assert_eq!(r.gid, "99");
        assert!(r.name.is_none());
    }

    #[test]
    fn resource_ref_extra_fields_ignored() {
        let r: ResourceRef = serde_json::from_value(json!({
            "gid": "1",
            "name": "A",
            "resource_type": "user",
        }))
        .unwrap();
        assert_eq!(r.gid, "1");
        assert_eq!(r.name, Some("A".into()));
    }

    // -- Workspace --

    #[test]
    fn workspace_roundtrip() {
        let w: Workspace = serde_json::from_value(json!({
            "gid": "ws_123",
            "name": "My Workspace",
            "is_organization": true,
        }))
        .unwrap();
        assert_eq!(w.gid, "ws_123");
        assert_eq!(w.name, Some("My Workspace".into()));
        assert_eq!(w.is_organization, Some(true));
        let re = serde_json::to_value(&w).unwrap();
        assert_eq!(re["name"], "My Workspace");
    }

    #[test]
    fn workspace_minimal() {
        let w: Workspace = serde_json::from_value(json!({"gid": "x"})).unwrap();
        assert_eq!(w.gid, "x");
        assert!(w.name.is_none());
        assert!(w.is_organization.is_none());
    }

    #[test]
    fn workspace_extra_fields_ignored() {
        let w: Workspace = serde_json::from_value(json!({
            "gid": "w1",
            "name": "Test",
            "email_domains": ["example.com"],
        }))
        .unwrap();
        assert_eq!(w.gid, "w1");
        assert_eq!(w.name, Some("Test".into()));
    }

    #[test]
    fn workspace_serialize_roundtrip() {
        let w = Workspace {
            gid: "ws1".into(),
            name: Some("Org".into()),
            is_organization: Some(false),
        };
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["gid"], "ws1");
        assert_eq!(v["is_organization"], false);
    }

    // -- Project --

    #[test]
    fn project_roundtrip() {
        let p: Project = serde_json::from_value(json!({
            "gid": "proj_123",
            "name": "Backend Redesign",
            "notes": "Rewrite the API layer",
            "color": "light-green",
            "archived": false,
            "workspace": {"gid": "ws_1", "name": "Acme"},
        }))
        .unwrap();
        assert_eq!(p.gid, "proj_123");
        assert_eq!(p.name, Some("Backend Redesign".into()));
        assert_eq!(p.notes, Some("Rewrite the API layer".into()));
        assert_eq!(p.color, Some("light-green".into()));
        assert_eq!(p.archived, Some(false));
        assert!(p.workspace.is_some());
        let ws = p.workspace.unwrap();
        assert_eq!(ws.gid, "ws_1");
        assert_eq!(ws.name, Some("Acme".into()));
    }

    #[test]
    fn project_minimal() {
        let p: Project = serde_json::from_value(json!({"gid": "x"})).unwrap();
        assert_eq!(p.gid, "x");
        assert!(p.name.is_none());
        assert!(p.notes.is_none());
        assert!(p.color.is_none());
        assert!(p.archived.is_none());
        assert!(p.workspace.is_none());
    }

    #[test]
    fn project_extra_fields_ignored() {
        let p: Project = serde_json::from_value(json!({
            "gid": "p1",
            "name": "Test",
            "public": true,
        }))
        .unwrap();
        assert_eq!(p.gid, "p1");
        assert_eq!(p.name, Some("Test".into()));
    }

    #[test]
    fn project_serialize_roundtrip() {
        let p = Project {
            gid: "p1".into(),
            name: Some("My Project".into()),
            notes: Some("Some notes".into()),
            color: None,
            archived: Some(true),
            workspace: Some(ResourceRef {
                gid: "w1".into(),
                name: Some("WS".into()),
            }),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["gid"], "p1");
        assert_eq!(v["archived"], true);
        assert_eq!(v["workspace"]["gid"], "w1");
    }

    // -- Task --

    #[test]
    fn task_roundtrip() {
        let t: Task = serde_json::from_value(json!({
            "gid": "task_123",
            "name": "Implement login page",
            "notes": "Build the login form with OAuth",
            "completed": false,
            "assignee": {"gid": "user_456", "name": "Alice"},
            "projects": [
                {"gid": "proj_1", "name": "Sprint 1"},
                {"gid": "proj_2", "name": "Sprint 2"},
            ],
            "due_on": "2026-04-01",
        }))
        .unwrap();
        assert_eq!(t.gid, "task_123");
        assert_eq!(t.name, Some("Implement login page".into()));
        assert_eq!(t.notes, Some("Build the login form with OAuth".into()));
        assert_eq!(t.completed, Some(false));
        assert!(t.assignee.is_some());
        let assignee = t.assignee.unwrap();
        assert_eq!(assignee.gid, "user_456");
        assert_eq!(assignee.name, Some("Alice".into()));
        assert!(t.projects.is_some());
        let projects = t.projects.unwrap();
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].gid, "proj_1");
        assert_eq!(t.due_on, Some("2026-04-01".into()));
    }

    #[test]
    fn task_minimal() {
        let t: Task = serde_json::from_value(json!({"gid": "x"})).unwrap();
        assert_eq!(t.gid, "x");
        assert!(t.name.is_none());
        assert!(t.notes.is_none());
        assert!(t.completed.is_none());
        assert!(t.assignee.is_none());
        assert!(t.projects.is_none());
        assert!(t.due_on.is_none());
    }

    #[test]
    fn task_extra_fields_ignored() {
        let t: Task = serde_json::from_value(json!({
            "gid": "t1",
            "name": "Test",
            "custom_fields": [],
        }))
        .unwrap();
        assert_eq!(t.gid, "t1");
        assert_eq!(t.name, Some("Test".into()));
    }

    #[test]
    fn task_serialize_roundtrip() {
        let t = Task {
            gid: "t1".into(),
            name: Some("Do thing".into()),
            notes: None,
            completed: Some(true),
            assignee: None,
            projects: Some(vec![ResourceRef {
                gid: "p1".into(),
                name: Some("Proj A".into()),
            }]),
            due_on: Some("2026-12-31".into()),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["gid"], "t1");
        assert_eq!(v["name"], "Do thing");
        assert_eq!(v["completed"], true);
        assert_eq!(v["projects"][0]["gid"], "p1");
        assert_eq!(v["due_on"], "2026-12-31");
    }

    #[test]
    fn task_completed_true() {
        let t: Task = serde_json::from_value(json!({
            "gid": "t2",
            "completed": true,
        }))
        .unwrap();
        assert_eq!(t.completed, Some(true));
    }

    // -- Section --

    #[test]
    fn section_roundtrip() {
        let s: Section = serde_json::from_value(json!({
            "gid": "sec_123",
            "name": "To Do",
        }))
        .unwrap();
        assert_eq!(s.gid, "sec_123");
        assert_eq!(s.name, Some("To Do".into()));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["name"], "To Do");
    }

    #[test]
    fn section_minimal() {
        let s: Section = serde_json::from_value(json!({"gid": "x"})).unwrap();
        assert_eq!(s.gid, "x");
        assert!(s.name.is_none());
    }

    #[test]
    fn section_extra_fields_ignored() {
        let s: Section = serde_json::from_value(json!({
            "gid": "s1",
            "name": "Done",
            "created_at": "2026-01-01",
        }))
        .unwrap();
        assert_eq!(s.gid, "s1");
        assert_eq!(s.name, Some("Done".into()));
    }

    // -- ApiErrorResponse --

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errors": [
                {"message": "Not found", "help": "Check the task GID"},
            ]
        }))
        .unwrap();
        assert!(e.errors.is_some());
        let errors = e.errors.unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, Some("Not found".into()));
        assert_eq!(errors[0].help, Some("Check the task GID".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.errors.is_none());
    }

    #[test]
    fn api_error_response_empty_array() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"errors": []})).unwrap();
        assert!(e.errors.is_some());
        assert!(e.errors.unwrap().is_empty());
    }

    #[test]
    fn api_error_response_multiple_errors() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errors": [
                {"message": "Error 1"},
                {"message": "Error 2", "help": "Try again"},
            ]
        }))
        .unwrap();
        let errors = e.errors.unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].message, Some("Error 1".into()));
        assert!(errors[0].help.is_none());
        assert_eq!(errors[1].message, Some("Error 2".into()));
        assert_eq!(errors[1].help, Some("Try again".into()));
    }

    #[test]
    fn api_error_message_only() {
        let e: ApiError = serde_json::from_value(json!({"message": "Oops"})).unwrap();
        assert_eq!(e.message, Some("Oops".into()));
        assert!(e.help.is_none());
    }

    #[test]
    fn api_error_empty() {
        let e: ApiError = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.help.is_none());
    }
}
