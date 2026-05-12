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
