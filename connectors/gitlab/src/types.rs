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
}
