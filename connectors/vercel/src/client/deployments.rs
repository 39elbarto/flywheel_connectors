use crate::{
    error::VercelResult,
    types::{CreateDeploymentRequest, DeleteStatus, Deployment, DeploymentListResponse},
};

use super::{VercelClient, sanitize_path_segment};

impl VercelClient {
    pub async fn list_deployments(
        &self,
        project_id: Option<&str>,
        limit: Option<u32>,
    ) -> VercelResult<DeploymentListResponse> {
        let mut query = Vec::new();
        if let Some(project_id) = project_id {
            query.push(("projectId", project_id.to_string()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        self.get("/v6/deployments", query).await
    }

    pub async fn get_deployment(&self, deployment_id_or_url: &str) -> VercelResult<Deployment> {
        let safe = sanitize_path_segment(deployment_id_or_url, "deployment_id_or_url")?;
        self.get(&format!("/v13/deployments/{safe}"), Vec::new())
            .await
    }

    pub async fn create_deployment(
        &self,
        request: &CreateDeploymentRequest,
    ) -> VercelResult<Deployment> {
        self.post("/v13/deployments", Vec::new(), request).await
    }

    pub async fn delete_deployment(&self, deployment_id: &str) -> VercelResult<DeleteStatus> {
        let safe = sanitize_path_segment(deployment_id, "deployment_id")?;
        self.delete(&format!("/v13/deployments/{safe}"), Vec::new())
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fcp_sdk::migration::HttpRetryConfig;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path},
    };

    use crate::types::{CreateDeploymentRequest, GitSource, TeamScope, VercelAuth};

    use super::*;

    #[test]
    fn create_deployment_posts_expected_shape() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v13/deployments"))
                .and(body_partial_json(serde_json::json!({
                    "name": "demo-web",
                    "gitSource": {
                        "type": "github",
                        "ref": "main"
                    }
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uid": "dpl_123",
                    "name": "demo-web",
                    "readyState": "QUEUED"
                })))
                .mount(&server)
                .await;

            let client = VercelClient::new(
                VercelAuth::AccessToken {
                    access_token: "token".into(),
                },
                TeamScope::default(),
                HttpRetryConfig::default(),
                Duration::from_secs(5),
            )
            .unwrap()
            .with_base_url(&server.uri());

            let deployment = client
                .create_deployment(&CreateDeploymentRequest {
                    name: "demo-web".into(),
                    project: Some("demo-web".into()),
                    target: Some("production".into()),
                    git_source: Some(GitSource {
                        source_type: "github".into(),
                        git_ref: "main".into(),
                        repo_id: None,
                        sha: None,
                        project_id: None,
                    }),
                    meta: None,
                })
                .await
                .unwrap();

            assert_eq!(deployment.id, "dpl_123");
            assert_eq!(deployment.ready_state.as_deref(), Some("QUEUED"));
        })
        .unwrap();
    }
}
