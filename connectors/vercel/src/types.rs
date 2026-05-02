use fcp_prelude::CredentialId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum VercelAuth {
    AccessToken { access_token: String },
    CredentialId { credential_id: CredentialId },
}

impl VercelAuth {
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::AccessToken { .. } => "access_token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }
}

impl std::fmt::Debug for VercelAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessToken { .. } => f
                .debug_struct("AccessToken")
                .field("access_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId { credential_id } => f
                .debug_struct("CredentialId")
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TeamScope {
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default, rename = "team_slug")]
    pub team_slug: Option<String>,
}

impl TeamScope {
    #[must_use]
    pub fn describe(&self) -> String {
        match (self.team_id.as_deref(), self.team_slug.as_deref()) {
            (Some(team_id), None) => format!("team_id:{team_id}"),
            (None, Some(team_slug)) => format!("team_slug:{team_slug}"),
            (None, None) => "personal".into(),
            (Some(team_id), Some(team_slug)) => format!("team_id:{team_id}, team_slug:{team_slug}"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pagination {
    #[serde(default)]
    pub count: Option<u64>,
    #[serde(default)]
    pub next: Option<u64>,
    #[serde(default)]
    pub prev: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectListResponse {
    #[serde(default)]
    pub projects: Vec<Project>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub framework: Option<String>,
    #[serde(default, rename = "accountId")]
    pub account_id: Option<String>,
    #[serde(default, rename = "rootDirectory")]
    pub root_directory: Option<String>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<u64>,
    #[serde(default, rename = "updatedAt")]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "rootDirectory")]
    pub root_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "publicSource")]
    pub public_source: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "buildCommand")]
    pub build_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "installCommand")]
    pub install_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "outputDirectory")]
    pub output_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "devCommand")]
    pub dev_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentListResponse {
    #[serde(default)]
    pub deployments: Vec<Deployment>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    #[serde(alias = "uid")]
    pub id: String,
    pub name: String,
    #[serde(default, rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default, rename = "readyState")]
    pub ready_state: Option<String>,
    #[serde(default, rename = "inspectorUrl")]
    pub inspector_url: Option<String>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDeploymentRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "gitSource")]
    pub git_source: Option<GitSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSource {
    #[serde(rename = "type")]
    pub source_type: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "repoId")]
    pub repo_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "projectId")]
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainListResponse {
    #[serde(default)]
    pub domains: Vec<ProjectDomain>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectDomain {
    pub name: String,
    #[serde(default, rename = "apexName")]
    pub apex_name: Option<String>,
    #[serde(default, rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(default, rename = "gitBranch")]
    pub git_branch: Option<String>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default, rename = "redirect")]
    pub redirect: Option<String>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddDomainRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "gitBranch")]
    pub git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "redirectStatusCode")]
    pub redirect_status_code: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarListResponse {
    #[serde(default)]
    pub envs: Vec<ProjectEnvVar>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectEnvVar {
    pub id: String,
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default, rename = "type")]
    pub env_type: Option<String>,
    #[serde(default)]
    pub target: Vec<String>,
    #[serde(default, rename = "gitBranch")]
    pub git_branch: Option<String>,
    #[serde(default, rename = "configurationId")]
    pub configuration_id: Option<String>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEnvVarRequest {
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub env_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "gitBranch")]
    pub git_branch: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        rename = "customEnvironmentIds"
    )]
    pub custom_environment_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteStatus {
    #[serde(default, alias = "id", alias = "uid")]
    pub resource_id: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(default)]
    pub error: Option<ApiErrorDetail>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    #[serde(default)]
    pub code: Option<String>,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vercel_auth_debug_redacts_access_token() {
        let auth = VercelAuth::AccessToken {
            access_token: "secret".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn vercel_auth_reports_secretless_mode() {
        let auth = VercelAuth::CredentialId {
            credential_id: CredentialId::parse("12345678-1234-5678-1234-567812345678").unwrap(),
        };
        assert_eq!(auth.redacted_label(), "credential_id");
        assert!(auth.is_secretless());
    }

    #[test]
    fn team_scope_describes_shape() {
        assert_eq!(TeamScope::default().describe(), "personal");
        assert_eq!(
            TeamScope {
                team_id: Some("team_123".into()),
                team_slug: None,
            }
            .describe(),
            "team_id:team_123"
        );
    }

    #[test]
    fn create_env_request_serializes_targets() {
        let request = CreateEnvVarRequest {
            key: "API_KEY".into(),
            value: "redacted".into(),
            env_type: "encrypted".into(),
            target: vec!["production".into(), "preview".into()],
            git_branch: Some("main".into()),
            custom_environment_ids: vec![],
        };

        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["target"], serde_json::json!(["production", "preview"]));
        assert_eq!(json["gitBranch"], "main");
    }
}
