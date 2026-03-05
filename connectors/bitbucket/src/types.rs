//! `Bitbucket` API types.

use serde::{Deserialize, Serialize};

/// A `Bitbucket` user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// The user's UUID (e.g., `"{123-456}"`).
    pub uuid: Option<String>,
    /// The user's username.
    pub username: Option<String>,
    /// The user's display name.
    pub display_name: Option<String>,
    /// The user's nickname.
    pub nickname: Option<String>,
}

/// A `Bitbucket` repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    /// The repository UUID.
    pub uuid: Option<String>,
    /// Full name in `workspace/repo_slug` format.
    pub full_name: Option<String>,
    /// The repository name.
    pub name: Option<String>,
    /// The repository description.
    pub description: Option<String>,
    /// Whether the repository is private.
    pub is_private: Option<bool>,
    /// The primary programming language.
    pub language: Option<String>,
}

/// A `Bitbucket` pull request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    /// The pull request ID.
    pub id: Option<u64>,
    /// The pull request title.
    pub title: Option<String>,
    /// The pull request state (e.g., `"OPEN"`, `"MERGED"`, `"DECLINED"`).
    pub state: Option<String>,
    /// The author of the pull request.
    pub author: Option<UserRef>,
    /// The source branch reference.
    pub source: Option<BranchRef>,
    /// The destination branch reference.
    pub destination: Option<BranchRef>,
}

/// A lightweight user reference within a `Bitbucket` pull request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRef {
    /// The user's display name.
    pub display_name: Option<String>,
    /// The user's UUID.
    pub uuid: Option<String>,
}

/// A branch reference within a `Bitbucket` pull request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRef {
    /// The branch details.
    pub branch: Option<BranchName>,
    /// The repository reference.
    pub repository: Option<RepoRef>,
}

/// A branch name object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchName {
    /// The branch name.
    pub name: Option<String>,
}

/// A repository reference within a `Bitbucket` branch ref.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRef {
    /// Full name in `workspace/repo_slug` format.
    pub full_name: Option<String>,
}

/// A `Bitbucket` branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    /// The branch name.
    pub name: Option<String>,
    /// The target commit.
    pub target: Option<CommitRef>,
}

/// A commit reference returned by `Bitbucket`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRef {
    /// The commit hash.
    pub hash: Option<String>,
    /// The commit message.
    pub message: Option<String>,
}

/// A `Bitbucket` pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    /// The pipeline UUID.
    pub uuid: Option<String>,
    /// The pipeline state (varies by status).
    pub state: Option<serde_json::Value>,
    /// The build number.
    pub build_number: Option<u64>,
}

/// A `Bitbucket` workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    /// The workspace UUID.
    pub uuid: Option<String>,
    /// The workspace slug (URL-friendly identifier).
    pub slug: Option<String>,
    /// The workspace display name.
    pub name: Option<String>,
}

/// Inner error detail from the `Bitbucket` API.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    /// The error message.
    pub message: Option<String>,
    /// Additional error detail.
    pub detail: Option<String>,
}

/// `Bitbucket` API error response body.
///
/// `Bitbucket` returns `{"error": {"message": "...", "detail": "..."}}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error object.
    pub error: Option<ApiErrorDetail>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn user_roundtrip() {
        let u: User = serde_json::from_value(json!({
            "uuid": "{abc-123}",
            "username": "jdoe",
            "display_name": "John Doe",
            "nickname": "johnd",
        }))
        .unwrap();
        assert_eq!(u.uuid, Some("{abc-123}".into()));
        assert_eq!(u.username, Some("jdoe".into()));
        assert_eq!(u.display_name, Some("John Doe".into()));
        assert_eq!(u.nickname, Some("johnd".into()));
        let re = serde_json::to_value(&u).unwrap();
        assert_eq!(re["display_name"], "John Doe");
    }

    #[test]
    fn user_minimal() {
        let u: User = serde_json::from_value(json!({})).unwrap();
        assert!(u.uuid.is_none());
        assert!(u.username.is_none());
        assert!(u.display_name.is_none());
        assert!(u.nickname.is_none());
    }

    #[test]
    fn repository_roundtrip() {
        let r: Repository = serde_json::from_value(json!({
            "uuid": "{repo-uuid}",
            "full_name": "myteam/backend",
            "name": "backend",
            "description": "Backend service",
            "is_private": true,
            "language": "rust",
        }))
        .unwrap();
        assert_eq!(r.uuid, Some("{repo-uuid}".into()));
        assert_eq!(r.full_name, Some("myteam/backend".into()));
        assert_eq!(r.name, Some("backend".into()));
        assert_eq!(r.description, Some("Backend service".into()));
        assert_eq!(r.is_private, Some(true));
        assert_eq!(r.language, Some("rust".into()));
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["full_name"], "myteam/backend");
    }

    #[test]
    fn repository_minimal() {
        let r: Repository = serde_json::from_value(json!({})).unwrap();
        assert!(r.uuid.is_none());
        assert!(r.full_name.is_none());
        assert!(r.name.is_none());
        assert!(r.is_private.is_none());
    }

    #[test]
    fn pull_request_roundtrip() {
        let pr: PullRequest = serde_json::from_value(json!({
            "id": 42,
            "title": "Fix login bug",
            "state": "OPEN",
            "author": {
                "display_name": "Jane",
                "uuid": "{user-uuid}",
            },
            "source": {
                "branch": {"name": "fix/login"},
                "repository": {"full_name": "myteam/backend"},
            },
            "destination": {
                "branch": {"name": "main"},
                "repository": {"full_name": "myteam/backend"},
            },
        }))
        .unwrap();
        assert_eq!(pr.id, Some(42));
        assert_eq!(pr.title, Some("Fix login bug".into()));
        assert_eq!(pr.state, Some("OPEN".into()));
        assert!(pr.author.is_some());
        let author = pr.author.unwrap();
        assert_eq!(author.display_name, Some("Jane".into()));
        assert!(pr.source.is_some());
        let source = pr.source.unwrap();
        assert_eq!(
            source.branch.as_ref().and_then(|b| b.name.as_deref()),
            Some("fix/login")
        );
        assert!(pr.destination.is_some());
        let dest = pr.destination.unwrap();
        assert_eq!(
            dest.branch.as_ref().and_then(|b| b.name.as_deref()),
            Some("main")
        );
    }

    #[test]
    fn pull_request_minimal() {
        let pr: PullRequest = serde_json::from_value(json!({})).unwrap();
        assert!(pr.id.is_none());
        assert!(pr.title.is_none());
        assert!(pr.state.is_none());
        assert!(pr.author.is_none());
        assert!(pr.source.is_none());
        assert!(pr.destination.is_none());
    }

    #[test]
    fn branch_roundtrip() {
        let b: Branch = serde_json::from_value(json!({
            "name": "main",
            "target": {
                "hash": "abc123def456",
                "message": "Initial commit",
            },
        }))
        .unwrap();
        assert_eq!(b.name, Some("main".into()));
        assert!(b.target.is_some());
        let re = serde_json::to_value(&b).unwrap();
        assert_eq!(re["name"], "main");
        let target = b.target.unwrap();
        assert_eq!(target.hash, Some("abc123def456".into()));
        assert_eq!(target.message, Some("Initial commit".into()));
    }

    #[test]
    fn branch_minimal() {
        let b: Branch = serde_json::from_value(json!({})).unwrap();
        assert!(b.name.is_none());
        assert!(b.target.is_none());
    }

    #[test]
    fn commit_ref_roundtrip() {
        let c: CommitRef = serde_json::from_value(json!({
            "hash": "deadbeef",
            "message": "Fix bug",
        }))
        .unwrap();
        assert_eq!(c.hash, Some("deadbeef".into()));
        assert_eq!(c.message, Some("Fix bug".into()));
    }

    #[test]
    fn pipeline_roundtrip() {
        let p: Pipeline = serde_json::from_value(json!({
            "uuid": "{pipe-uuid}",
            "state": {"name": "COMPLETED", "result": {"name": "SUCCESSFUL"}},
            "build_number": 123,
        }))
        .unwrap();
        assert_eq!(p.uuid, Some("{pipe-uuid}".into()));
        assert!(p.state.is_some());
        assert_eq!(p.build_number, Some(123));
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["build_number"], 123);
    }

    #[test]
    fn pipeline_minimal() {
        let p: Pipeline = serde_json::from_value(json!({})).unwrap();
        assert!(p.uuid.is_none());
        assert!(p.state.is_none());
        assert!(p.build_number.is_none());
    }

    #[test]
    fn workspace_roundtrip() {
        let w: Workspace = serde_json::from_value(json!({
            "uuid": "{ws-uuid}",
            "slug": "myteam",
            "name": "My Team",
        }))
        .unwrap();
        assert_eq!(w.uuid, Some("{ws-uuid}".into()));
        assert_eq!(w.slug, Some("myteam".into()));
        assert_eq!(w.name, Some("My Team".into()));
        let re = serde_json::to_value(&w).unwrap();
        assert_eq!(re["slug"], "myteam");
    }

    #[test]
    fn workspace_minimal() {
        let w: Workspace = serde_json::from_value(json!({})).unwrap();
        assert!(w.uuid.is_none());
        assert!(w.slug.is_none());
        assert!(w.name.is_none());
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {
                "message": "Repository not found",
                "detail": "The repository myteam/missing does not exist.",
            }
        }))
        .unwrap();
        let inner = e.error.unwrap();
        assert_eq!(inner.message, Some("Repository not found".into()));
        assert_eq!(
            inner.detail,
            Some("The repository myteam/missing does not exist.".into())
        );
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {
                "message": "Rate limit exceeded",
            }
        }))
        .unwrap();
        let inner = e.error.unwrap();
        assert_eq!(inner.message, Some("Rate limit exceeded".into()));
        assert!(inner.detail.is_none());
    }

    #[test]
    fn user_extra_fields_ignored() {
        let u: User = serde_json::from_value(json!({
            "uuid": "{u1}",
            "display_name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(u.uuid, Some("{u1}".into()));
        assert_eq!(u.display_name, Some("Test".into()));
    }

    #[test]
    fn repository_extra_fields_ignored() {
        let r: Repository = serde_json::from_value(json!({
            "full_name": "team/repo",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(r.full_name, Some("team/repo".into()));
    }

    #[test]
    fn pull_request_extra_fields_ignored() {
        let pr: PullRequest = serde_json::from_value(json!({
            "id": 1,
            "title": "Test PR",
            "unknown_field": true,
        }))
        .unwrap();
        assert_eq!(pr.id, Some(1));
        assert_eq!(pr.title, Some("Test PR".into()));
    }

    #[test]
    fn user_ref_roundtrip() {
        let ur: UserRef = serde_json::from_value(json!({
            "display_name": "Alice",
            "uuid": "{user-123}",
        }))
        .unwrap();
        assert_eq!(ur.display_name, Some("Alice".into()));
        assert_eq!(ur.uuid, Some("{user-123}".into()));
    }

    #[test]
    fn branch_ref_roundtrip() {
        let br: BranchRef = serde_json::from_value(json!({
            "branch": {"name": "develop"},
            "repository": {"full_name": "team/repo"},
        }))
        .unwrap();
        assert_eq!(
            br.branch.as_ref().and_then(|b| b.name.as_deref()),
            Some("develop")
        );
        assert_eq!(
            br.repository.as_ref().and_then(|r| r.full_name.as_deref()),
            Some("team/repo")
        );
    }

    #[test]
    fn repo_ref_roundtrip() {
        let rr: RepoRef = serde_json::from_value(json!({
            "full_name": "team/repo",
        }))
        .unwrap();
        assert_eq!(rr.full_name, Some("team/repo".into()));
    }

    #[test]
    fn branch_name_roundtrip() {
        let bn: BranchName = serde_json::from_value(json!({"name": "feature/xyz"})).unwrap();
        assert_eq!(bn.name, Some("feature/xyz".into()));
    }

    #[test]
    fn pull_request_serialize_roundtrip() {
        let pr = PullRequest {
            id: Some(7),
            title: Some("Add tests".into()),
            state: Some("OPEN".into()),
            author: Some(UserRef {
                display_name: Some("Bob".into()),
                uuid: None,
            }),
            source: None,
            destination: None,
        };
        let v = serde_json::to_value(&pr).unwrap();
        assert_eq!(v["id"], 7);
        assert_eq!(v["title"], "Add tests");
        assert_eq!(v["author"]["display_name"], "Bob");
    }

    #[test]
    fn workspace_serialize_roundtrip() {
        let w = Workspace {
            uuid: Some("{ws-1}".into()),
            slug: Some("team".into()),
            name: Some("Team Workspace".into()),
        };
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["slug"], "team");
        assert_eq!(v["name"], "Team Workspace");
    }
}
