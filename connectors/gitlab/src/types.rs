//! `GitLab` API types.

use serde::{Deserialize, Serialize};

/// A `GitLab` project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Option<i64>,
    pub name: Option<String>,
    pub path_with_namespace: Option<String>,
    pub description: Option<String>,
    pub web_url: Option<String>,
    pub default_branch: Option<String>,
    pub visibility: Option<String>,
    pub created_at: Option<String>,
    pub last_activity_at: Option<String>,
    pub archived: Option<bool>,
}

/// A `GitLab` issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: Option<i64>,
    pub iid: Option<i64>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub state: Option<String>,
    pub web_url: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    pub author: Option<serde_json::Value>,
    pub assignee: Option<serde_json::Value>,
}

/// A `GitLab` merge request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeRequest {
    pub id: Option<i64>,
    pub iid: Option<i64>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub state: Option<String>,
    pub source_branch: Option<String>,
    pub target_branch: Option<String>,
    pub web_url: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub author: Option<serde_json::Value>,
    pub merge_status: Option<String>,
}

/// A `GitLab` pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    pub id: Option<i64>,
    pub iid: Option<i64>,
    pub status: Option<String>,
    #[serde(rename = "ref")]
    pub ref_name: Option<String>,
    pub sha: Option<String>,
    pub web_url: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub source: Option<String>,
}

/// `GitLab` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn project_roundtrip() {
        let p: Project = serde_json::from_value(json!({
            "id": 1, "name": "my-project", "path_with_namespace": "user/my-project",
            "web_url": "https://gitlab.com/user/my-project", "visibility": "private",
            "default_branch": "main", "archived": false
        })).unwrap();
        assert_eq!(p.name.as_deref(), Some("my-project"));
        assert!(!p.archived.unwrap());
    }

    #[test]
    fn project_minimal() {
        let p: Project = serde_json::from_value(json!({})).unwrap();
        assert!(p.id.is_none());
    }

    #[test]
    fn issue_roundtrip() {
        let i: Issue = serde_json::from_value(json!({
            "id": 1, "iid": 42, "title": "Bug", "state": "opened",
            "labels": ["bug", "critical"], "web_url": "https://gitlab.com/..."
        })).unwrap();
        assert_eq!(i.iid, Some(42));
        assert_eq!(i.labels.len(), 2);
    }

    #[test]
    fn issue_minimal() {
        let i: Issue = serde_json::from_value(json!({})).unwrap();
        assert!(i.labels.is_empty());
    }

    #[test]
    fn merge_request_roundtrip() {
        let m: MergeRequest = serde_json::from_value(json!({
            "id": 1, "iid": 10, "title": "Feature", "state": "merged",
            "source_branch": "feature", "target_branch": "main",
            "merge_status": "can_be_merged"
        })).unwrap();
        assert_eq!(m.state.as_deref(), Some("merged"));
    }

    #[test]
    fn pipeline_roundtrip() {
        let p: Pipeline = serde_json::from_value(json!({
            "id": 1, "iid": 5, "status": "success", "ref": "main",
            "sha": "abc123", "source": "push"
        })).unwrap();
        assert_eq!(p.status.as_deref(), Some("success"));
        assert_eq!(p.ref_name.as_deref(), Some("main"));
    }

    #[test]
    fn api_error_response() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "404 Not Found", "error": "not_found"
        })).unwrap();
        assert_eq!(e.error.as_deref(), Some("not_found"));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
    }

    // ── Project extended ────────────────────────────────────────────

    #[test]
    fn project_all_fields() {
        let p: Project = serde_json::from_value(json!({
            "id": 42, "name": "proj", "path_with_namespace": "group/proj",
            "description": "A project", "web_url": "https://gl.com/proj",
            "default_branch": "develop", "visibility": "public",
            "created_at": "2024-01-01T00:00:00Z", "last_activity_at": "2025-01-01T00:00:00Z",
            "archived": true
        })).unwrap();
        assert_eq!(p.id, Some(42));
        assert_eq!(p.name.as_deref(), Some("proj"));
        assert_eq!(p.path_with_namespace.as_deref(), Some("group/proj"));
        assert_eq!(p.description.as_deref(), Some("A project"));
        assert_eq!(p.web_url.as_deref(), Some("https://gl.com/proj"));
        assert_eq!(p.default_branch.as_deref(), Some("develop"));
        assert_eq!(p.visibility.as_deref(), Some("public"));
        assert_eq!(p.created_at.as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(p.last_activity_at.as_deref(), Some("2025-01-01T00:00:00Z"));
        assert_eq!(p.archived, Some(true));
    }

    #[test]
    fn project_serialize_roundtrip() {
        let p = Project {
            id: Some(1), name: Some("test".into()), path_with_namespace: Some("g/t".into()),
            description: None, web_url: Some("url".into()), default_branch: Some("main".into()),
            visibility: Some("private".into()), created_at: None, last_activity_at: None,
            archived: Some(false),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["id"], 1);
        assert_eq!(v["name"], "test");
        assert_eq!(v["archived"], false);
        // None becomes null in JSON
        assert!(v["description"].is_null());
    }

    #[test]
    fn project_debug() {
        let p: Project = serde_json::from_value(json!({"name": "dbg"})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Project"));
        assert!(dbg.contains("dbg"));
    }

    #[test]
    fn project_clone() {
        let p: Project = serde_json::from_value(json!({"id": 1, "name": "orig"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let c = p.clone();
        assert_eq!(c.id, Some(1));
        assert_eq!(c.name.as_deref(), Some("orig"));
    }

    #[test]
    fn project_extra_fields_ignored() {
        let p: Project = serde_json::from_value(json!({"id": 1, "unknown": "field"})).unwrap();
        assert_eq!(p.id, Some(1));
    }

    #[test]
    fn project_from_json_string() {
        let p: Project = serde_json::from_str(r#"{"id":5,"name":"from_str"}"#).unwrap();
        assert_eq!(p.id, Some(5));
        assert_eq!(p.name.as_deref(), Some("from_str"));
    }

    // ── Issue extended ──────────────────────────────────────────────

    #[test]
    fn issue_all_fields() {
        let i: Issue = serde_json::from_value(json!({
            "id": 100, "iid": 10, "title": "Bug report",
            "description": "Something broke", "state": "opened",
            "web_url": "https://gl.com/issues/10",
            "created_at": "2024-06-01T00:00:00Z",
            "updated_at": "2024-06-02T00:00:00Z",
            "labels": ["bug", "p1"],
            "author": {"id": 1, "name": "Jane"},
            "assignee": {"id": 2, "name": "John"}
        })).unwrap();
        assert_eq!(i.id, Some(100));
        assert_eq!(i.iid, Some(10));
        assert_eq!(i.title.as_deref(), Some("Bug report"));
        assert_eq!(i.description.as_deref(), Some("Something broke"));
        assert_eq!(i.state.as_deref(), Some("opened"));
        assert_eq!(i.web_url.as_deref(), Some("https://gl.com/issues/10"));
        assert_eq!(i.labels.len(), 2);
        assert!(i.author.is_some());
        assert!(i.assignee.is_some());
    }

    #[test]
    fn issue_serialize_roundtrip() {
        let i = Issue {
            id: Some(1), iid: Some(2), title: Some("T".into()),
            description: None, state: Some("closed".into()),
            web_url: None, created_at: None, updated_at: None,
            labels: vec!["a".into(), "b".into()],
            author: None, assignee: None,
        };
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["iid"], 2);
        assert_eq!(v["state"], "closed");
        let labels = v["labels"].as_array().unwrap();
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn issue_debug() {
        let i: Issue = serde_json::from_value(json!({"title": "dbg"})).unwrap();
        let dbg = format!("{i:?}");
        assert!(dbg.contains("Issue"));
    }

    #[test]
    fn issue_clone() {
        let i: Issue = serde_json::from_value(json!({"id": 1, "labels": ["a"]})).unwrap();
        #[allow(clippy::redundant_clone)]
        let c = i.clone();
        assert_eq!(c.id, Some(1));
        assert_eq!(c.labels.len(), 1);
    }

    #[test]
    fn issue_empty_labels_default() {
        let i: Issue = serde_json::from_value(json!({"id": 1})).unwrap();
        assert!(i.labels.is_empty());
    }

    #[test]
    fn issue_extra_fields_ignored() {
        let i: Issue = serde_json::from_value(json!({"id": 1, "unknown_field": true})).unwrap();
        assert_eq!(i.id, Some(1));
    }

    // ── MergeRequest extended ───────────────────────────────────────

    #[test]
    fn merge_request_all_fields() {
        let m: MergeRequest = serde_json::from_value(json!({
            "id": 200, "iid": 20, "title": "Feature X",
            "description": "Adds feature X", "state": "merged",
            "source_branch": "feature-x", "target_branch": "main",
            "web_url": "https://gl.com/mr/20",
            "created_at": "2024-01-01", "updated_at": "2024-01-02",
            "author": {"id": 1}, "merge_status": "can_be_merged"
        })).unwrap();
        assert_eq!(m.id, Some(200));
        assert_eq!(m.iid, Some(20));
        assert_eq!(m.title.as_deref(), Some("Feature X"));
        assert_eq!(m.description.as_deref(), Some("Adds feature X"));
        assert_eq!(m.source_branch.as_deref(), Some("feature-x"));
        assert_eq!(m.target_branch.as_deref(), Some("main"));
        assert_eq!(m.merge_status.as_deref(), Some("can_be_merged"));
        assert!(m.author.is_some());
    }

    #[test]
    fn merge_request_minimal() {
        let m: MergeRequest = serde_json::from_value(json!({})).unwrap();
        assert!(m.id.is_none());
        assert!(m.source_branch.is_none());
        assert!(m.merge_status.is_none());
    }

    #[test]
    fn merge_request_serialize_roundtrip() {
        let m = MergeRequest {
            id: Some(1), iid: Some(5), title: Some("MR".into()),
            description: None, state: Some("opened".into()),
            source_branch: Some("feat".into()), target_branch: Some("main".into()),
            web_url: None, created_at: None, updated_at: None,
            author: None, merge_status: Some("unchecked".into()),
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["source_branch"], "feat");
        assert_eq!(v["merge_status"], "unchecked");
    }

    #[test]
    fn merge_request_debug() {
        let m: MergeRequest = serde_json::from_value(json!({"title": "D"})).unwrap();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("MergeRequest"));
    }

    #[test]
    fn merge_request_clone() {
        let m: MergeRequest = serde_json::from_value(json!({"id": 1})).unwrap();
        #[allow(clippy::redundant_clone)]
        let c = m.clone();
        assert_eq!(c.id, Some(1));
    }

    #[test]
    fn merge_request_extra_fields_ignored() {
        let m: MergeRequest = serde_json::from_value(json!({"id": 1, "approvals_before_merge": 2})).unwrap();
        assert_eq!(m.id, Some(1));
    }

    // ── Pipeline extended ───────────────────────────────────────────

    #[test]
    fn pipeline_all_fields() {
        let p: Pipeline = serde_json::from_value(json!({
            "id": 300, "iid": 30, "status": "running",
            "ref": "develop", "sha": "abc123def456",
            "web_url": "https://gl.com/pipe/30",
            "created_at": "2024-05-01", "updated_at": "2024-05-02",
            "source": "web"
        })).unwrap();
        assert_eq!(p.id, Some(300));
        assert_eq!(p.iid, Some(30));
        assert_eq!(p.status.as_deref(), Some("running"));
        assert_eq!(p.ref_name.as_deref(), Some("develop"));
        assert_eq!(p.sha.as_deref(), Some("abc123def456"));
        assert_eq!(p.source.as_deref(), Some("web"));
    }

    #[test]
    fn pipeline_minimal() {
        let p: Pipeline = serde_json::from_value(json!({})).unwrap();
        assert!(p.id.is_none());
        assert!(p.ref_name.is_none());
    }

    #[test]
    fn pipeline_serialize_roundtrip() {
        let p = Pipeline {
            id: Some(1), iid: Some(2), status: Some("success".into()),
            ref_name: Some("main".into()), sha: Some("abc".into()),
            web_url: None, created_at: None, updated_at: None,
            source: Some("push".into()),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["status"], "success");
        // ref_name serializes as "ref" due to rename
        assert_eq!(v["ref"], "main");
        assert_eq!(v["source"], "push");
    }

    #[test]
    fn pipeline_ref_rename() {
        // Verify that "ref" in JSON maps to ref_name field
        let json_str = r#"{"ref": "release/1.0"}"#;
        let p: Pipeline = serde_json::from_str(json_str).unwrap();
        assert_eq!(p.ref_name.as_deref(), Some("release/1.0"));
    }

    #[test]
    fn pipeline_debug() {
        let p: Pipeline = serde_json::from_value(json!({"status": "failed"})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Pipeline"));
        assert!(dbg.contains("failed"));
    }

    #[test]
    fn pipeline_clone() {
        let p: Pipeline = serde_json::from_value(json!({"id": 9})).unwrap();
        #[allow(clippy::redundant_clone)]
        let c = p.clone();
        assert_eq!(c.id, Some(9));
    }

    #[test]
    fn pipeline_extra_fields_ignored() {
        let p: Pipeline = serde_json::from_value(json!({"id": 1, "yaml_errors": "none"})).unwrap();
        assert_eq!(p.id, Some(1));
    }

    // ── ApiErrorResponse extended ───────────────────────────────────

    #[test]
    fn api_error_response_message_as_object() {
        // GitLab sometimes returns message as an object
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": {"base": ["is invalid"]}
        })).unwrap();
        assert!(e.message.is_some());
        assert!(e.message.unwrap().is_object());
    }

    #[test]
    fn api_error_response_message_as_string() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "404 Not Found"
        })).unwrap();
        assert_eq!(e.message.unwrap().as_str(), Some("404 Not Found"));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"error": "test"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"error": "e1"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let c = e.clone();
        assert_eq!(c.error.as_deref(), Some("e1"));
    }

    #[test]
    fn api_error_response_null_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"error": null, "message": null})).unwrap();
        assert!(e.error.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_extra_fields_ignored() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"error": "e", "extra": 42})).unwrap();
        assert_eq!(e.error.as_deref(), Some("e"));
    }

    #[test]
    fn api_error_from_json_string() {
        let e: ApiErrorResponse = serde_json::from_str(r#"{"error":"parse_err"}"#).unwrap();
        assert_eq!(e.error.as_deref(), Some("parse_err"));
    }

    // ── Cross-type JSON string roundtrips ───────────────────────────

    #[test]
    fn project_json_string_roundtrip() {
        let p = Project {
            id: Some(42), name: Some("roundtrip".into()),
            path_with_namespace: None, description: None,
            web_url: None, default_branch: None,
            visibility: None, created_at: None,
            last_activity_at: None, archived: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: Project = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(42));
        assert_eq!(back.name.as_deref(), Some("roundtrip"));
    }

    #[test]
    fn issue_json_string_roundtrip() {
        let i = Issue {
            id: Some(7), iid: Some(3), title: Some("RT".into()),
            description: None, state: None, web_url: None,
            created_at: None, updated_at: None,
            labels: vec!["l1".into()], author: None, assignee: None,
        };
        let s = serde_json::to_string(&i).unwrap();
        let back: Issue = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(7));
        assert_eq!(back.labels, vec!["l1"]);
    }

    #[test]
    fn merge_request_json_string_roundtrip() {
        let m = MergeRequest {
            id: Some(99), iid: None, title: Some("MR RT".into()),
            description: None, state: None, source_branch: None,
            target_branch: None, web_url: None, created_at: None,
            updated_at: None, author: None, merge_status: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: MergeRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(99));
    }

    #[test]
    fn pipeline_json_string_roundtrip() {
        let p = Pipeline {
            id: Some(77), iid: None, status: Some("pending".into()),
            ref_name: Some("main".into()), sha: None,
            web_url: None, created_at: None, updated_at: None,
            source: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: Pipeline = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(77));
        assert_eq!(back.ref_name.as_deref(), Some("main"));
    }

    // ── Unicode in fields ───────────────────────────────────────────

    #[test]
    fn project_unicode_name() {
        let p: Project = serde_json::from_value(json!({"name": "Projet \u{00e9}l\u{00e8}ve"})).unwrap();
        assert!(p.name.unwrap().contains('\u{00e9}'));
    }

    #[test]
    fn issue_unicode_title() {
        let i: Issue = serde_json::from_value(json!({"title": "\u{1F41B} Bug"})).unwrap();
        assert!(i.title.unwrap().contains('\u{1F41B}'));
    }
}
