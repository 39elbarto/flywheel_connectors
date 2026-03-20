use crate::{
    error::VercelResult,
    types::{CreateEnvVarRequest, DeleteStatus, EnvVarListResponse, ProjectEnvVar},
};

use super::{VercelClient, sanitize_path_segment};

impl VercelClient {
    pub async fn list_env_vars(
        &self,
        project_id_or_name: &str,
    ) -> VercelResult<EnvVarListResponse> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        self.get(&format!("/v9/projects/{project}/env"), Vec::new())
            .await
    }

    pub async fn create_env_vars(
        &self,
        project_id_or_name: &str,
        requests: &[CreateEnvVarRequest],
    ) -> VercelResult<Vec<ProjectEnvVar>> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        self.post(
            &format!("/v10/projects/{project}/env"),
            Vec::new(),
            requests,
        )
        .await
    }

    pub async fn delete_env_var(
        &self,
        project_id_or_name: &str,
        env_var_id: &str,
    ) -> VercelResult<DeleteStatus> {
        let project = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        let env_id = sanitize_path_segment(env_var_id, "environment_variable_id")?;
        self.delete(&format!("/v9/projects/{project}/env/{env_id}"), Vec::new())
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

    use crate::types::{TeamScope, VercelAuth};

    use super::*;

    #[test]
    fn create_env_vars_posts_array_payload() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v10/projects/demo/env"))
                .and(body_partial_json(serde_json::json!([{
                    "key": "API_KEY",
                    "type": "encrypted",
                    "target": ["production"]
                }])))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "id": "env_123",
                        "key": "API_KEY",
                        "type": "encrypted",
                        "target": ["production"]
                    }
                ])))
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

            let created = client
                .create_env_vars(
                    "demo",
                    &[CreateEnvVarRequest {
                        key: "API_KEY".into(),
                        value: "redacted".into(),
                        env_type: "encrypted".into(),
                        target: vec!["production".into()],
                        git_branch: None,
                        custom_environment_ids: vec![],
                    }],
                )
                .await
                .unwrap();

            assert_eq!(created.len(), 1);
            assert_eq!(created[0].key, "API_KEY");
        })
        .unwrap();
    }
}
