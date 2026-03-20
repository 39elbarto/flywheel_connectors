use serde::{Deserialize, Serialize};

// ── Auth ──

/// Vercel authentication via Bearer token.
#[derive(Clone, Deserialize)]
pub struct VercelAuth {
    pub token: String,
}

impl std::fmt::Debug for VercelAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VercelAuth")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

// ── Deployments ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Deployment {
    pub uid: String,
    pub name: String,
    pub url: Option<String>,
    pub state: Option<String>,
    pub created: Option<u64>,
    #[serde(rename = "readyState")]
    pub ready_state: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<u64>,
    pub meta: Option<serde_json::Value>,
    #[serde(rename = "inspectorUrl")]
    pub inspector_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDeployment {
    pub name: String,
    #[serde(rename = "gitSource", skip_serializing_if = "Option::is_none")]
    pub git_source: Option<GitSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(rename = "projectSettings", skip_serializing_if = "Option::is_none")]
    pub project_settings: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub repo: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
}

// ── Projects ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(rename = "accountId")]
    pub account_id: Option<String>,
    pub framework: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<u64>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<u64>,
    #[serde(rename = "latestDeployments")]
    pub latest_deployments: Option<Vec<Deployment>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateProject {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(rename = "gitRepository", skip_serializing_if = "Option::is_none")]
    pub git_repository: Option<GitRepository>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRepository {
    #[serde(rename = "type")]
    pub repo_type: String,
    pub repo: String,
}

/// Wrapper for paginated project list responses.
#[derive(Debug, Clone, Deserialize)]
pub struct ProjectListResponse {
    pub projects: Vec<Project>,
    pub pagination: Option<Pagination>,
}

// ── Domains ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Domain {
    pub name: String,
    #[serde(rename = "apexName")]
    pub apex_name: Option<String>,
    #[serde(rename = "projectId")]
    pub project_id: Option<String>,
    pub redirect: Option<String>,
    #[serde(rename = "redirectStatusCode")]
    pub redirect_status_code: Option<u16>,
    #[serde(rename = "gitBranch")]
    pub git_branch: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<u64>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<u64>,
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddDomain {
    pub name: String,
    #[serde(rename = "gitBranch", skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(rename = "redirectStatusCode", skip_serializing_if = "Option::is_none")]
    pub redirect_status_code: Option<u16>,
}

/// Wrapper for paginated domain list responses.
#[derive(Debug, Clone, Deserialize)]
pub struct DomainListResponse {
    pub domains: Vec<Domain>,
    pub pagination: Option<Pagination>,
}

// ── Environment Variables ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvVar {
    pub id: Option<String>,
    pub key: String,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub env_type: Option<String>,
    pub target: Option<Vec<String>>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<u64>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<u64>,
    #[serde(rename = "configurationId")]
    pub configuration_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateEnvVar {
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub env_type: String,
    pub target: Vec<String>,
}

/// Wrapper for paginated env var list responses.
#[derive(Debug, Clone, Deserialize)]
pub struct EnvVarListResponse {
    pub envs: Vec<EnvVar>,
    pub pagination: Option<Pagination>,
}

// ── User (health check) ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub username: Option<String>,
}

/// Wrapper for /v2/user response.
#[derive(Debug, Clone, Deserialize)]
pub struct UserResponse {
    pub user: User,
}

// ── Pagination ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Pagination {
    pub count: Option<u64>,
    pub next: Option<u64>,
    pub prev: Option<u64>,
}

// ── Deployment list response ──

#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentListResponse {
    pub deployments: Vec<Deployment>,
    pub pagination: Option<Pagination>,
}

// ── Error response ──

#[derive(Debug, Clone, Deserialize)]
pub struct VercelErrorResponse {
    pub error: Option<VercelApiError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VercelApiError {
    pub code: Option<String>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_deployment() {
        let json = serde_json::json!({
            "uid": "dpl_abc123",
            "name": "my-app",
            "url": "my-app-abc123.vercel.app",
            "state": "READY",
            "created": 1_700_000_000_000u64,
            "readyState": "READY"
        });
        let dep: Deployment = serde_json::from_value(json).unwrap();
        assert_eq!(dep.uid, "dpl_abc123");
        assert_eq!(dep.name, "my-app");
        assert_eq!(dep.ready_state.unwrap(), "READY");
    }

    #[test]
    fn deserialize_project() {
        let json = serde_json::json!({
            "id": "prj_abc123",
            "name": "my-project",
            "accountId": "team_xyz",
            "framework": "nextjs",
            "createdAt": 1_700_000_000_000u64
        });
        let proj: Project = serde_json::from_value(json).unwrap();
        assert_eq!(proj.id, "prj_abc123");
        assert_eq!(proj.name, "my-project");
        assert_eq!(proj.framework.unwrap(), "nextjs");
    }

    #[test]
    fn deserialize_domain() {
        let json = serde_json::json!({
            "name": "example.com",
            "apexName": "example.com",
            "projectId": "prj_abc",
            "verified": true,
            "createdAt": 1_700_000_000_000u64
        });
        let domain: Domain = serde_json::from_value(json).unwrap();
        assert_eq!(domain.name, "example.com");
        assert!(domain.verified.unwrap());
    }

    #[test]
    fn deserialize_env_var() {
        let json = serde_json::json!({
            "id": "env_abc",
            "key": "DATABASE_URL",
            "value": "postgres://...",
            "type": "encrypted",
            "target": ["production", "preview"]
        });
        let env: EnvVar = serde_json::from_value(json).unwrap();
        assert_eq!(env.key, "DATABASE_URL");
        assert_eq!(env.target.unwrap(), vec!["production", "preview"]);
    }

    #[test]
    fn deserialize_user() {
        let json = serde_json::json!({
            "id": "user_abc",
            "email": "user@example.com",
            "name": "Test User",
            "username": "testuser"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, "user_abc");
        assert_eq!(user.username.unwrap(), "testuser");
    }

    #[test]
    fn deserialize_user_response() {
        let json = serde_json::json!({
            "user": {
                "id": "user_abc",
                "email": "user@example.com",
                "name": "Test User",
                "username": "testuser"
            }
        });
        let resp: UserResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.user.id, "user_abc");
    }

    #[test]
    fn auth_debug_redacts_token() {
        let auth = VercelAuth {
            token: "super-secret-token".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn serialize_create_deployment() {
        let dep = CreateDeployment {
            name: "my-app".into(),
            git_source: Some(GitSource {
                source_type: "github".into(),
                repo: "user/repo".into(),
                git_ref: Some("main".into()),
            }),
            target: Some("production".into()),
            project_settings: None,
        };
        let json = serde_json::to_value(&dep).unwrap();
        assert_eq!(json["name"], "my-app");
        assert_eq!(json["gitSource"]["type"], "github");
        assert_eq!(json["gitSource"]["ref"], "main");
        assert!(json.get("projectSettings").is_none());
    }

    #[test]
    fn serialize_create_project() {
        let proj = CreateProject {
            name: "my-project".into(),
            framework: Some("nextjs".into()),
            git_repository: Some(GitRepository {
                repo_type: "github".into(),
                repo: "user/repo".into(),
            }),
        };
        let json = serde_json::to_value(&proj).unwrap();
        assert_eq!(json["name"], "my-project");
        assert_eq!(json["framework"], "nextjs");
        assert_eq!(json["gitRepository"]["type"], "github");
    }

    #[test]
    fn serialize_add_domain() {
        let domain = AddDomain {
            name: "example.com".into(),
            git_branch: None,
            redirect: Some("www.example.com".into()),
            redirect_status_code: Some(308),
        };
        let json = serde_json::to_value(&domain).unwrap();
        assert_eq!(json["name"], "example.com");
        assert!(json.get("gitBranch").is_none());
        assert_eq!(json["redirect"], "www.example.com");
        assert_eq!(json["redirectStatusCode"], 308);
    }

    #[test]
    fn serialize_create_env_var() {
        let env = CreateEnvVar {
            key: "API_KEY".into(),
            value: "secret123".into(),
            env_type: "encrypted".into(),
            target: vec!["production".into(), "preview".into()],
        };
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["key"], "API_KEY");
        assert_eq!(json["type"], "encrypted");
    }

    #[test]
    fn deserialize_deployment_list_response() {
        let json = serde_json::json!({
            "deployments": [{
                "uid": "dpl_1",
                "name": "app",
                "state": "READY"
            }],
            "pagination": {
                "count": 1,
                "next": null,
                "prev": null
            }
        });
        let resp: DeploymentListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.deployments.len(), 1);
        assert_eq!(resp.deployments[0].uid, "dpl_1");
    }

    #[test]
    fn deserialize_error_response() {
        let json = serde_json::json!({
            "error": {
                "code": "forbidden",
                "message": "Not authorized"
            }
        });
        let resp: VercelErrorResponse = serde_json::from_value(json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code.unwrap(), "forbidden");
        assert_eq!(err.message.unwrap(), "Not authorized");
    }

    #[test]
    fn deserialize_project_list_response() {
        let json = serde_json::json!({
            "projects": [{
                "id": "prj_1",
                "name": "proj"
            }],
            "pagination": { "count": 1 }
        });
        let resp: ProjectListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.projects.len(), 1);
    }

    #[test]
    fn deserialize_domain_list_response() {
        let json = serde_json::json!({
            "domains": [{
                "name": "example.com"
            }],
            "pagination": { "count": 1 }
        });
        let resp: DomainListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.domains.len(), 1);
    }

    #[test]
    fn deserialize_env_var_list_response() {
        let json = serde_json::json!({
            "envs": [{
                "key": "DB_URL",
                "value": "postgres://localhost"
            }],
            "pagination": { "count": 1 }
        });
        let resp: EnvVarListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.envs.len(), 1);
        assert_eq!(resp.envs[0].key, "DB_URL");
    }
}
