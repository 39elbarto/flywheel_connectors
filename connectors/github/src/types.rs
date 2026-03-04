//! GitHub API types.

use serde::{Deserialize, Serialize};

/// GitHub user (author, assignee, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub login: String,
    pub id: u64,
    #[serde(default)]
    pub avatar_url: String,
    #[serde(rename = "type", default)]
    pub user_type: String,
}

/// GitHub label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// GitHub milestone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Milestone {
    pub id: u64,
    pub number: u32,
    pub title: String,
    pub state: String,
}

/// GitHub issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: u64,
    pub number: u32,
    pub title: String,
    pub state: String,
    #[serde(default)]
    pub body: Option<String>,
    pub user: User,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub assignees: Vec<User>,
    #[serde(default)]
    pub milestone: Option<Milestone>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub closed_at: Option<String>,
    pub html_url: String,
    #[serde(default)]
    pub comments: u32,
}

/// GitHub pull request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub id: u64,
    pub number: u32,
    pub title: String,
    pub state: String,
    #[serde(default)]
    pub body: Option<String>,
    pub user: User,
    pub head: PullRequestRef,
    pub base: PullRequestRef,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub assignees: Vec<User>,
    #[serde(default)]
    pub merged: bool,
    #[serde(default)]
    pub mergeable: Option<bool>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub merged_at: Option<String>,
    #[serde(default)]
    pub closed_at: Option<String>,
    pub html_url: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub additions: u32,
    #[serde(default)]
    pub deletions: u32,
    #[serde(default)]
    pub changed_files: u32,
}

/// Git ref in a pull request (head or base).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestRef {
    pub label: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub sha: String,
}

/// GitHub repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub owner: User,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub fork: bool,
    pub html_url: String,
    pub default_branch: String,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub stargazers_count: u32,
    #[serde(default)]
    pub forks_count: u32,
    #[serde(default)]
    pub open_issues_count: u32,
    pub created_at: String,
    pub updated_at: String,
}

/// GitHub Actions workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: u64,
    pub name: String,
    pub path: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}

/// File content from the repository contents API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContent {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub encoding: Option<String>,
    pub html_url: String,
}

/// Search results wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchResults<T> {
    pub total_count: u64,
    pub incomplete_results: bool,
    pub items: Vec<T>,
}

/// Code search result item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSearchItem {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub html_url: String,
    pub repository: CodeSearchRepo,
}

/// Minimal repo info in code search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSearchRepo {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub html_url: String,
}

/// Workflows list response.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowsResponse {
    pub total_count: u32,
    pub workflows: Vec<Workflow>,
}

/// Merge result.
#[derive(Debug, Clone, Deserialize)]
pub struct MergeResult {
    pub sha: String,
    pub merged: bool,
    pub message: String,
}

/// GitHub API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: String,
    #[serde(default)]
    pub documentation_url: Option<String>,
    #[serde(default)]
    pub errors: Option<Vec<ApiValidationError>>,
}

/// Validation error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiValidationError {
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Request to create an issue.
#[derive(Debug, Clone, Serialize)]
pub struct CreateIssueRequest {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignees: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub milestone: Option<u32>,
}

/// Request to create a pull request.
#[derive(Debug, Clone, Serialize)]
pub struct CreatePullRequestRequest {
    pub title: String,
    pub head: String,
    pub base: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft: Option<bool>,
}

/// Request to merge a pull request.
#[derive(Debug, Clone, Serialize)]
pub struct MergePullRequestRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- User ----

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            login: "octocat".to_string(),
            id: 1,
            avatar_url: "https://github.com/images/error/octocat.gif".to_string(),
            user_type: "User".to_string(),
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"type\":\"User\""));
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.login, "octocat");
    }

    #[test]
    fn user_deserialize_defaults() {
        let json = r#"{"login":"bot","id":2}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.avatar_url, "");
        assert_eq!(user.user_type, "");
    }

    // ---- Issue ----

    #[test]
    fn issue_serde_with_defaults() {
        let json = json!({
            "id": 1,
            "number": 42,
            "title": "Bug report",
            "state": "open",
            "user": {"login": "alice", "id": 10},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-03-01T00:00:00Z",
            "html_url": "https://github.com/org/repo/issues/42"
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.number, 42);
        assert!(issue.body.is_none());
        assert!(issue.labels.is_empty());
        assert!(issue.assignees.is_empty());
        assert_eq!(issue.comments, 0);
    }

    // ---- PullRequest ----

    #[test]
    fn pull_request_serde() {
        let json = json!({
            "id": 100,
            "number": 5,
            "title": "Add feature",
            "state": "open",
            "user": {"login": "dev", "id": 20},
            "head": {"label": "dev:feature", "ref": "feature", "sha": "abc123"},
            "base": {"label": "org:main", "ref": "main", "sha": "def456"},
            "created_at": "2026-03-01",
            "updated_at": "2026-03-02",
            "html_url": "https://github.com/org/repo/pull/5"
        });
        let pr: PullRequest = serde_json::from_value(json).unwrap();
        assert_eq!(pr.number, 5);
        assert_eq!(pr.head.ref_name, "feature");
        assert_eq!(pr.base.ref_name, "main");
        assert!(!pr.merged);
        assert!(!pr.draft);
        assert_eq!(pr.additions, 0);
    }

    // ---- Repository ----

    #[test]
    fn repository_serde() {
        let json = json!({
            "id": 1,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": {"login": "octocat", "id": 1},
            "html_url": "https://github.com/octocat/hello-world",
            "default_branch": "main",
            "created_at": "2026-01-01",
            "updated_at": "2026-03-01"
        });
        let repo: Repository = serde_json::from_value(json).unwrap();
        assert_eq!(repo.full_name, "octocat/hello-world");
        assert!(!repo.private);
        assert!(!repo.fork);
        assert_eq!(repo.stargazers_count, 0);
    }

    // ---- Label ----

    #[test]
    fn label_serde() {
        let label = Label {
            id: 1,
            name: "bug".to_string(),
            color: "d73a4a".to_string(),
            description: Some("Something isn't working".to_string()),
        };
        let json = serde_json::to_string(&label).unwrap();
        let back: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "bug");
    }

    // ---- FileContent ----

    #[test]
    fn file_content_serde() {
        let json = json!({
            "name": "README.md",
            "path": "README.md",
            "sha": "abc123",
            "size": 1024,
            "type": "file",
            "content": "SGVsbG8=",
            "encoding": "base64",
            "html_url": "https://github.com/org/repo/blob/main/README.md"
        });
        let fc: FileContent = serde_json::from_value(json).unwrap();
        assert_eq!(fc.content_type, "file");
        assert_eq!(fc.content.as_deref(), Some("SGVsbG8="));
    }

    // ---- SearchResults ----

    #[test]
    fn search_results_deserialize() {
        let json = json!({
            "total_count": 2,
            "incomplete_results": false,
            "items": [{"id": 1, "number": 1, "title": "A", "state": "open",
                       "user": {"login": "a", "id": 1}, "created_at": "2026-01-01",
                       "updated_at": "2026-01-01", "html_url": "https://github.com/a/b/issues/1"}]
        });
        let results: SearchResults<Issue> = serde_json::from_value(json).unwrap();
        assert_eq!(results.total_count, 2);
        assert!(!results.incomplete_results);
        assert_eq!(results.items.len(), 1);
    }

    // ---- ApiErrorResponse ----

    #[test]
    fn api_error_response_deserialize() {
        let json = json!({
            "message": "Not Found",
            "documentation_url": "https://docs.github.com/",
            "errors": [{"resource": "Issue", "field": "title", "code": "missing"}]
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.message, "Not Found");
        assert!(err.errors.is_some());
        assert_eq!(err.errors.unwrap()[0].code.as_deref(), Some("missing"));
    }

    // ---- CreateIssueRequest ----

    #[test]
    fn create_issue_request_serialize_minimal() {
        let req = CreateIssueRequest {
            title: "Bug".to_string(),
            body: None,
            assignees: None,
            labels: None,
            milestone: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("body"));
        assert!(!json.contains("assignees"));
    }

    // ---- CreatePullRequestRequest ----

    #[test]
    fn create_pr_request_serialize() {
        let req = CreatePullRequestRequest {
            title: "Feature".to_string(),
            head: "feature-branch".to_string(),
            base: "main".to_string(),
            body: Some("Adds feature".to_string()),
            draft: Some(true),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"draft\":true"));
    }

    // ---- MergePullRequestRequest ----

    #[test]
    fn merge_pr_request_serialize_minimal() {
        let req = MergePullRequestRequest {
            commit_title: None,
            commit_message: None,
            merge_method: None,
            sha: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "{}");
    }

    // ---- MergeResult ----

    #[test]
    fn merge_result_deserialize() {
        let json = r#"{"sha":"abc123","merged":true,"message":"Pull Request successfully merged"}"#;
        let result: MergeResult = serde_json::from_str(json).unwrap();
        assert!(result.merged);
    }

    // ---- Workflow ----

    #[test]
    fn workflow_serde() {
        let wf = Workflow {
            id: 1,
            name: "CI".to_string(),
            path: ".github/workflows/ci.yml".to_string(),
            state: "active".to_string(),
            created_at: "2026-01-01".to_string(),
            updated_at: "2026-03-01".to_string(),
        };
        let json = serde_json::to_string(&wf).unwrap();
        let back: Workflow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "CI");
    }
}
