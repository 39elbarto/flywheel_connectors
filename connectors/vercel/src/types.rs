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

// ── Projects ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub framework: Option<String>,
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<u64>,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: Option<u64>,
    #[serde(rename = "accountId", default)]
    pub account_id: Option<String>,
    #[serde(rename = "nodeVersion", default)]
    pub node_version: Option<String>,
    #[serde(rename = "latestDeployments", default)]
    pub latest_deployments: Option<Vec<Deployment>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProjectsResponse {
    pub projects: Vec<Project>,
    pub pagination: Option<Pagination>,
}

// ── Deployments ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Deployment {
    pub uid: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(rename = "readyState", default)]
    pub ready_state: Option<String>,
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<u64>,
    #[serde(rename = "buildingAt", default)]
    pub building_at: Option<u64>,
    #[serde(default)]
    pub ready: Option<u64>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(rename = "projectId", default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub creator: Option<Creator>,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Creator {
    pub uid: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeploymentsResponse {
    pub deployments: Vec<Deployment>,
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDeploymentRequest {
    pub name: String,
    #[serde(rename = "gitSource", skip_serializing_if = "Option::is_none")]
    pub git_source: Option<GitSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(rename = "projectSettings", skip_serializing_if = "Option::is_none")]
    pub project_settings: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GitSource {
    #[serde(rename = "type")]
    pub source_type: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    #[serde(rename = "repoId")]
    pub repo_id: String,
}

// ── Domains ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Domain {
    pub name: String,
    #[serde(rename = "apexName", default)]
    pub apex_name: Option<String>,
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(rename = "projectId", default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub redirect: Option<String>,
    #[serde(rename = "redirectStatusCode", default)]
    pub redirect_status_code: Option<u16>,
    #[serde(rename = "gitBranch", default)]
    pub git_branch: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainsResponse {
    pub domains: Vec<Domain>,
    pub pagination: Option<Pagination>,
}

// ── Environment Variables ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvVar {
    pub id: Option<String>,
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub target: Option<Vec<String>>,
    #[serde(rename = "type", default)]
    pub env_type: Option<String>,
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<u64>,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: Option<u64>,
    #[serde(rename = "configurationId", default)]
    pub configuration_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvVarsResponse {
    pub envs: Vec<EnvVar>,
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateEnvVarRequest {
    pub key: String,
    pub value: String,
    pub target: Vec<String>,
    #[serde(rename = "type")]
    pub env_type: String,
}

// ── Pagination ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Pagination {
    pub count: Option<u32>,
    pub next: Option<u64>,
    pub prev: Option<u64>,
}

// ── User (for health check) ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserResponse {
    pub user: User,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub uid: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_project() {
        let json = serde_json::json!({
            "id": "prj_123",
            "name": "my-app",
            "framework": "nextjs",
            "createdAt": 1700000000000_u64,
            "updatedAt": 1700000001000_u64
        });
        let proj: Project = serde_json::from_value(json).unwrap();
        assert_eq!(proj.id, "prj_123");
        assert_eq!(proj.name, "my-app");
        assert_eq!(proj.framework.unwrap(), "nextjs");
    }

    #[test]
    fn deserialize_deployment() {
        let json = serde_json::json!({
            "uid": "dpl_abc",
            "name": "my-app",
            "url": "my-app-abc.vercel.app",
            "state": "READY",
            "readyState": "READY",
            "createdAt": 1700000000000_u64,
            "target": "production"
        });
        let dep: Deployment = serde_json::from_value(json).unwrap();
        assert_eq!(dep.uid, "dpl_abc");
        assert_eq!(dep.state.unwrap(), "READY");
        assert_eq!(dep.target.unwrap(), "production");
    }

    #[test]
    fn deserialize_domain() {
        let json = serde_json::json!({
            "name": "example.com",
            "verified": true,
            "createdAt": 1700000000000_u64
        });
        let domain: Domain = serde_json::from_value(json).unwrap();
        assert_eq!(domain.name, "example.com");
        assert!(domain.verified.unwrap());
    }

    #[test]
    fn deserialize_env_var() {
        let json = serde_json::json!({
            "id": "env_123",
            "key": "DATABASE_URL",
            "value": "postgres://...",
            "target": ["production", "preview"],
            "type": "encrypted"
        });
        let env: EnvVar = serde_json::from_value(json).unwrap();
        assert_eq!(env.key, "DATABASE_URL");
        assert_eq!(env.target.unwrap().len(), 2);
    }

    #[test]
    fn deserialize_projects_response() {
        let json = serde_json::json!({
            "projects": [{
                "id": "prj_1",
                "name": "app-one"
            }, {
                "id": "prj_2",
                "name": "app-two"
            }],
            "pagination": {
                "count": 2,
                "next": null,
                "prev": null
            }
        });
        let resp: ProjectsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.projects.len(), 2);
        assert_eq!(resp.projects[0].name, "app-one");
    }

    #[test]
    fn deserialize_deployments_response() {
        let json = serde_json::json!({
            "deployments": [{
                "uid": "dpl_1",
                "state": "READY"
            }],
            "pagination": { "count": 1 }
        });
        let resp: DeploymentsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.deployments.len(), 1);
    }

    #[test]
    fn deserialize_user_response() {
        let json = serde_json::json!({
            "user": {
                "uid": "user_123",
                "email": "user@example.com",
                "name": "Test User",
                "username": "testuser"
            }
        });
        let resp: UserResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.user.uid, "user_123");
        assert_eq!(resp.user.email.unwrap(), "user@example.com");
    }

    #[test]
    fn auth_debug_redacts_token() {
        let auth = VercelAuth {
            token: "super-secret-vercel-token".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn serialize_create_deployment_request() {
        let req = CreateDeploymentRequest {
            name: "my-app".into(),
            git_source: Some(GitSource {
                source_type: "github".into(),
                git_ref: "main".into(),
                repo_id: "12345".into(),
            }),
            target: Some("production".into()),
            project_settings: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "my-app");
        assert_eq!(json["gitSource"]["type"], "github");
        assert_eq!(json["gitSource"]["ref"], "main");
        assert!(json.get("projectSettings").is_none());
    }

    #[test]
    fn serialize_create_env_var_request() {
        let req = CreateEnvVarRequest {
            key: "API_KEY".into(),
            value: "secret123".into(),
            target: vec!["production".into(), "preview".into()],
            env_type: "encrypted".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["key"], "API_KEY");
        assert_eq!(json["type"], "encrypted");
        assert_eq!(json["target"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn deserialize_domains_response() {
        let json = serde_json::json!({
            "domains": [{
                "name": "example.com",
                "verified": true
            }],
            "pagination": { "count": 1 }
        });
        let resp: DomainsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.domains.len(), 1);
        assert_eq!(resp.domains[0].name, "example.com");
    }

    #[test]
    fn deserialize_env_vars_response() {
        let json = serde_json::json!({
            "envs": [{
                "id": "env_1",
                "key": "FOO",
                "value": "bar",
                "target": ["production"]
            }],
            "pagination": { "count": 1 }
        });
        let resp: EnvVarsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.envs.len(), 1);
        assert_eq!(resp.envs[0].key, "FOO");
    }
}
