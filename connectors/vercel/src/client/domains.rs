use crate::{
    error::VercelResult,
    types::{AddDomainRequest, DeleteStatus, DomainListResponse, ProjectDomain},
};

use super::{VercelClient, encode_path_segment};

impl VercelClient {
    pub async fn list_domains(&self, project_id_or_name: &str) -> VercelResult<DomainListResponse> {
        let project = encode_path_segment(project_id_or_name);
        self.get(
            &format!("/v9/projects/{project}/domains"),
            Vec::new(),
        )
        .await
    }

    pub async fn add_domain(
        &self,
        project_id_or_name: &str,
        request: &AddDomainRequest,
    ) -> VercelResult<ProjectDomain> {
        let project = encode_path_segment(project_id_or_name);
        self.post(
            &format!("/v10/projects/{project}/domains"),
            Vec::new(),
            request,
        )
        .await
    }

    pub async fn remove_domain(
        &self,
        project_id_or_name: &str,
        domain_name: &str,
    ) -> VercelResult<DeleteStatus> {
        let project = encode_path_segment(project_id_or_name);
        let domain = encode_path_segment(domain_name);
        self.delete(
            &format!("/v10/projects/{project}/domains/{domain}"),
            Vec::new(),
        )
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
    fn add_domain_serializes_redirect_metadata() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v10/projects/demo/domains"))
                .and(body_partial_json(serde_json::json!({
                    "name": "demo.example.com",
                    "gitBranch": "main"
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": "demo.example.com",
                    "projectId": "prj_123",
                    "verified": true
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

            let domain = client
                .add_domain(
                    "demo",
                    &AddDomainRequest {
                        name: "demo.example.com".into(),
                        git_branch: Some("main".into()),
                        redirect: None,
                        redirect_status_code: None,
                    },
                )
                .await
                .unwrap();

            assert_eq!(domain.name, "demo.example.com");
            assert_eq!(domain.verified, Some(true));
        })
        .unwrap();
    }
}
