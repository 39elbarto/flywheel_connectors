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

    // ── Additional type coverage ─────────────────────────────────

    #[test]
    fn resource_ref_clone_debug() {
        let r = ResourceRef {
            gid: "123".into(),
            name: Some("Test".into()),
        };
        let cloned = r.clone();
        assert_eq!(cloned.gid, "123");
        assert_eq!(cloned.name, Some("Test".into()));
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ResourceRef"));
        assert!(dbg.contains("123"));
    }

    #[test]
    fn resource_ref_serialize_roundtrip() {
        let r = ResourceRef {
            gid: "456".into(),
            name: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["gid"], "456");
        let back: ResourceRef = serde_json::from_value(v).unwrap();
        assert_eq!(back.gid, "456");
        assert!(back.name.is_none());
    }

    #[test]
    fn workspace_clone_debug() {
        let w = Workspace {
            gid: "ws1".into(),
            name: Some("Acme".into()),
            is_organization: Some(true),
        };
        let cloned = w.clone();
        assert_eq!(cloned.gid, "ws1");
        assert_eq!(cloned.is_organization, Some(true));
        let dbg = format!("{w:?}");
        assert!(dbg.contains("Workspace"));
        assert!(dbg.contains("Acme"));
    }

    #[test]
    fn project_clone_debug() {
        let p = Project {
            gid: "p1".into(),
            name: Some("Proj".into()),
            notes: Some("n".into()),
            color: Some("blue".into()),
            archived: Some(false),
            workspace: None,
        };
        let cloned = p.clone();
        assert_eq!(cloned.gid, "p1");
        assert_eq!(cloned.color, Some("blue".into()));
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Project"));
        assert!(dbg.contains("Proj"));
    }

    #[test]
    fn project_archived_true() {
        let json = json!({"gid": "p1", "archived": true});
        let p: Project = serde_json::from_value(json).unwrap();
        assert_eq!(p.archived, Some(true));
    }

    #[test]
    fn task_clone_debug() {
        let t = Task {
            gid: "t1".into(),
            name: Some("Task".into()),
            notes: None,
            completed: Some(false),
            assignee: None,
            projects: None,
            due_on: None,
        };
        let cloned = t.clone();
        assert_eq!(cloned.gid, "t1");
        assert_eq!(cloned.completed, Some(false));
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Task"));
        assert!(dbg.contains("t1"));
    }

    #[test]
    fn task_with_assignee_and_projects() {
        let t = Task {
            gid: "t1".into(),
            name: Some("Task A".into()),
            notes: Some("notes here".into()),
            completed: Some(true),
            assignee: Some(ResourceRef {
                gid: "u1".into(),
                name: Some("Bob".into()),
            }),
            projects: Some(vec![
                ResourceRef {
                    gid: "p1".into(),
                    name: Some("P1".into()),
                },
                ResourceRef {
                    gid: "p2".into(),
                    name: None,
                },
            ]),
            due_on: Some("2026-06-15".into()),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["assignee"]["name"], "Bob");
        assert_eq!(v["projects"][1]["gid"], "p2");
        assert_eq!(v["due_on"], "2026-06-15");
    }

    #[test]
    fn section_clone_debug() {
        let s = Section {
            gid: "s1".into(),
            name: Some("In Progress".into()),
        };
        let cloned = s.clone();
        assert_eq!(cloned.gid, "s1");
        assert_eq!(cloned.name, Some("In Progress".into()));
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Section"));
        assert!(dbg.contains("In Progress"));
    }

    #[test]
    fn section_serialize_roundtrip() {
        let s = Section {
            gid: "s1".into(),
            name: Some("Done".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        let back: Section = serde_json::from_value(v).unwrap();
        assert_eq!(back.gid, "s1");
        assert_eq!(back.name, Some("Done".into()));
    }

    #[test]
    fn api_error_response_clone_debug() {
        let e = ApiErrorResponse {
            errors: Some(vec![ApiError {
                message: Some("err".into()),
                help: Some("fix it".into()),
            }]),
        };
        let cloned = e.clone();
        let errs = cloned.errors.unwrap();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].message, Some("err".into()));
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_clone_debug() {
        let e = ApiError {
            message: Some("msg".into()),
            help: Some("h".into()),
        };
        let cloned = e.clone();
        assert_eq!(cloned.help, Some("h".into()));
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiError"));
    }

    #[test]
    fn workspace_organization_false() {
        let json = json!({"gid": "w1", "is_organization": false});
        let w: Workspace = serde_json::from_value(json).unwrap();
        assert_eq!(w.is_organization, Some(false));
    }

    #[test]
    fn task_empty_projects_list() {
        let json = json!({"gid": "t1", "projects": []});
        let t: Task = serde_json::from_value(json).unwrap();
        assert!(t.projects.is_some());
        assert!(t.projects.unwrap().is_empty());
    }

    #[test]
    fn project_with_workspace_ref() {
        let p = Project {
            gid: "p1".into(),
            name: None,
            notes: None,
            color: None,
            archived: None,
            workspace: Some(ResourceRef {
                gid: "ws1".into(),
                name: Some("Workspace".into()),
            }),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["workspace"]["gid"], "ws1");
    }

    #[test]
    fn api_error_help_only() {
        let e: ApiError = serde_json::from_value(json!({"help": "Try again"})).unwrap();
        assert!(e.message.is_none());
        assert_eq!(e.help, Some("Try again".into()));
    }

    #[test]
    fn task_due_on_none() {
        let t: Task = serde_json::from_value(json!({"gid": "t1"})).unwrap();
        assert!(t.due_on.is_none());
    }

    #[test]
    fn task_serialize_null_optionals() {
        let t = Task {
            gid: "t1".into(),
            name: None,
            notes: None,
            completed: None,
            assignee: None,
            projects: None,
            due_on: None,
        };
        let v = serde_json::to_value(&t).unwrap();
        // gid should always be present
        assert_eq!(v["gid"], "t1");
    }

    #[test]
    fn api_error_response_single_error() {
        let json = json!({"errors": [{"message": "Only one"}]});
        let e: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let errs = e.errors.unwrap();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].message, Some("Only one".into()));
    }
}
