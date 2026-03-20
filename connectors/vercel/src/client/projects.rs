use crate::{
    error::VercelResult,
    types::{CreateProjectRequest, Project, ProjectListResponse},
};

use super::{VercelClient, sanitize_path_segment};

impl VercelClient {
    pub async fn list_projects(&self, limit: Option<u32>) -> VercelResult<ProjectListResponse> {
        let mut query = Vec::new();
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        self.get("/v9/projects", query).await
    }

    pub async fn get_project(&self, project_id_or_name: &str) -> VercelResult<Project> {
        let safe = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        self.get(&format!("/v9/projects/{safe}"), Vec::new()).await
    }

    pub async fn create_project(&self, request: &CreateProjectRequest) -> VercelResult<Project> {
        self.post("/v10/projects", Vec::new(), request).await
    }

    pub async fn delete_project(&self, project_id_or_name: &str) -> VercelResult<()> {
        let safe = sanitize_path_segment(project_id_or_name, "project_id_or_name")?;
        self.delete_no_content(&format!("/v9/projects/{safe}"), Vec::new())
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fcp_sdk::migration::HttpRetryConfig;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    use crate::types::{TeamScope, VercelAuth};

    use super::*;

    #[test]
    fn list_projects_returns_typed_payload() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v9/projects"))
                .and(query_param("limit", "10"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "projects": [
                        { "id": "prj_1", "name": "demo", "framework": "nextjs" }
                    ],
                    "pagination": { "count": 1 }
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

            let response = client.list_projects(Some(10)).await.unwrap();
            assert_eq!(response.projects.len(), 1);
            assert_eq!(response.projects[0].name, "demo");
        })
        .unwrap();
    }
}
