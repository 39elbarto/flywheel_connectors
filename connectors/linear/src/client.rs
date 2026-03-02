//! Linear GraphQL API client.

use reqwest::{Client, StatusCode, header};
use tracing::{debug, warn};

use crate::{
    error::{LinearError, LinearResult},
    types::{
        CommentCreatePayload, Cycle, GraphQLRequest, GraphQLResponse, Issue, IssueCreatePayload,
        IssueUpdatePayload, Project, Team,
    },
};

const DEFAULT_API_URL: &str = "https://api.linear.app/graphql";

/// Linear GraphQL API client.
pub struct LinearClient {
    http: Client,
    api_url: String,
    max_retries: u32,
}

impl LinearClient {
    /// Create a new Linear client with an API key.
    pub fn new(api_key: &str) -> LinearResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {api_key}").parse().unwrap(),
        );

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-linear/0.1.0")
            .build()
            .map_err(LinearError::Http)?;

        Ok(Self {
            http,
            api_url: DEFAULT_API_URL.to_string(),
            max_retries: 2,
        })
    }

    /// Set a custom API URL (for testing).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    // ── API Methods ──────────────────────────────────────────────

    /// Create a new issue.
    pub async fn create_issue(
        &self,
        title: &str,
        team_id: &str,
        description: Option<&str>,
    ) -> LinearResult<Issue> {
        let mut variables = serde_json::json!({
            "title": title,
            "teamId": team_id,
        });
        if let Some(desc) = description {
            variables["description"] = serde_json::Value::String(desc.into());
        }

        let query = r"
            mutation IssueCreate($title: String!, $teamId: String!, $description: String) {
                issueCreate(input: { title: $title, teamId: $teamId, description: $description }) {
                    success
                    issue {
                        id identifier title description priority priorityLabel
                        state { id name color type }
                        assignee { id name displayName email }
                        team { id name key }
                        labels { nodes { id name color } }
                        createdAt updatedAt url
                    }
                }
            }
        ";

        let data = self.execute_graphql(query, Some(variables)).await?;
        let payload: IssueCreatePayload =
            serde_json::from_value(data["issueCreate"].clone())?;

        payload.issue.ok_or(LinearError::Api {
            message: "Issue creation returned no issue".into(),
            status_code: None,
        })
    }

    /// Get an issue by ID.
    pub async fn get_issue(&self, issue_id: &str) -> LinearResult<Issue> {
        let query = r"
            query GetIssue($id: String!) {
                issue(id: $id) {
                    id identifier title description priority priorityLabel
                    state { id name color type }
                    assignee { id name displayName email }
                    team { id name key }
                    labels { nodes { id name color } }
                    createdAt updatedAt url
                }
            }
        ";

        let variables = serde_json::json!({ "id": issue_id });
        let data = self.execute_graphql(query, Some(variables)).await?;

        if data["issue"].is_null() {
            return Err(LinearError::NotFound {
                resource: format!("issue:{issue_id}"),
            });
        }

        Ok(serde_json::from_value(data["issue"].clone())?)
    }

    /// Update an issue.
    pub async fn update_issue(
        &self,
        issue_id: &str,
        title: Option<&str>,
        state_id: Option<&str>,
        description: Option<&str>,
    ) -> LinearResult<Issue> {
        let mut input = serde_json::Map::new();
        if let Some(t) = title {
            input.insert("title".into(), serde_json::Value::String(t.into()));
        }
        if let Some(s) = state_id {
            input.insert("stateId".into(), serde_json::Value::String(s.into()));
        }
        if let Some(d) = description {
            input.insert("description".into(), serde_json::Value::String(d.into()));
        }

        let query = r"
            mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
                issueUpdate(id: $id, input: $input) {
                    success
                    issue {
                        id identifier title description priority priorityLabel
                        state { id name color type }
                        assignee { id name displayName email }
                        team { id name key }
                        labels { nodes { id name color } }
                        createdAt updatedAt url
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "id": issue_id,
            "input": serde_json::Value::Object(input),
        });

        let data = self.execute_graphql(query, Some(variables)).await?;
        let payload: IssueUpdatePayload =
            serde_json::from_value(data["issueUpdate"].clone())?;

        payload.issue.ok_or(LinearError::Api {
            message: "Issue update returned no issue".into(),
            status_code: None,
        })
    }

    /// Search issues by text query.
    pub async fn search_issues(&self, query_text: &str) -> LinearResult<Vec<Issue>> {
        let query = r"
            query SearchIssues($query: String!) {
                searchIssues(query: $query) {
                    nodes {
                        id identifier title description priority priorityLabel
                        state { id name color type }
                        assignee { id name displayName email }
                        team { id name key }
                        labels { nodes { id name color } }
                        createdAt updatedAt url
                    }
                }
            }
        ";

        let variables = serde_json::json!({ "query": query_text });
        let data = self.execute_graphql(query, Some(variables)).await?;

        let nodes = data["searchIssues"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let issues: Vec<Issue> = nodes
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        Ok(issues)
    }

    /// List all teams.
    pub async fn list_teams(&self) -> LinearResult<Vec<Team>> {
        let query = r"
            query ListTeams {
                teams {
                    nodes {
                        id name key description
                    }
                }
            }
        ";

        let data = self.execute_graphql(query, None).await?;

        let nodes = data["teams"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let teams: Vec<Team> = nodes
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        Ok(teams)
    }

    /// List cycles for a team.
    pub async fn list_cycles(&self, team_id: &str) -> LinearResult<Vec<Cycle>> {
        let query = r"
            query ListCycles($teamId: String!) {
                team(id: $teamId) {
                    cycles {
                        nodes {
                            id number name startsAt endsAt completedAt
                        }
                    }
                }
            }
        ";

        let variables = serde_json::json!({ "teamId": team_id });
        let data = self.execute_graphql(query, Some(variables)).await?;

        if data["team"].is_null() {
            return Err(LinearError::NotFound {
                resource: format!("team:{team_id}"),
            });
        }

        let nodes = data["team"]["cycles"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let cycles: Vec<Cycle> = nodes
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        Ok(cycles)
    }

    /// Add a comment to an issue.
    pub async fn add_comment(
        &self,
        issue_id: &str,
        body: &str,
    ) -> LinearResult<crate::types::IssueComment> {
        let query = r"
            mutation CommentCreate($issueId: String!, $body: String!) {
                commentCreate(input: { issueId: $issueId, body: $body }) {
                    success
                    comment {
                        id body
                        user { id name displayName email }
                        createdAt updatedAt
                    }
                }
            }
        ";

        let variables = serde_json::json!({
            "issueId": issue_id,
            "body": body,
        });

        let data = self.execute_graphql(query, Some(variables)).await?;
        let payload: CommentCreatePayload =
            serde_json::from_value(data["commentCreate"].clone())?;

        payload.comment.ok_or(LinearError::Api {
            message: "Comment creation returned no comment".into(),
            status_code: None,
        })
    }

    /// List projects.
    pub async fn list_projects(&self) -> LinearResult<Vec<Project>> {
        let query = r"
            query ListProjects {
                projects {
                    nodes {
                        id name description state progress createdAt updatedAt url
                    }
                }
            }
        ";

        let data = self.execute_graphql(query, None).await?;

        let nodes = data["projects"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let projects: Vec<Project> = nodes
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();

        Ok(projects)
    }

    // ── Internal GraphQL helpers ─────────────────────────────────

    async fn execute_graphql(
        &self,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> LinearResult<serde_json::Value> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            debug!("GraphQL request to {}", self.api_url);

            let result = self.http.post(&self.api_url).json(&request).send().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(LinearError::Unauthorized);
                    }

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let err = LinearError::RateLimited {
                            retry_after_ms: 60_000,
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, "rate limited, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if status.is_server_error() {
                        let err = LinearError::Api {
                            message: format!("Server error: {status}"),
                            status_code: Some(status.as_u16()),
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, status = %status, "server error, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        return Err(LinearError::Api {
                            message: format!("HTTP {status}: {body}"),
                            status_code: Some(status.as_u16()),
                        });
                    }

                    let body = response.text().await.map_err(LinearError::Http)?;
                    let gql_response: GraphQLResponse = serde_json::from_str(&body)?;

                    if let Some(errors) = gql_response.errors {
                        if !errors.is_empty() {
                            let messages: Vec<&str> =
                                errors.iter().map(|e| e.message.as_str()).collect();
                            return Err(LinearError::Api {
                                message: messages.join("; "),
                                status_code: None,
                            });
                        }
                    }

                    return gql_response.data.ok_or(LinearError::Api {
                        message: "Empty response data".into(),
                        status_code: None,
                    });
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(LinearError::Http(e));
                        continue;
                    }
                    return Err(LinearError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(LinearError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn graphql_success(data: &serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": data }))
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_issue() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(graphql_success(&serde_json::json!({
                "issue": {
                    "id": "issue-1",
                    "identifier": "LIN-1",
                    "title": "Test issue",
                    "state": { "id": "s1", "name": "In Progress" },
                    "team": { "id": "t1", "name": "Engineering", "key": "ENG" }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()));

        let issue = client.get_issue("issue-1").await.unwrap();
        assert_eq!(issue.identifier, "LIN-1");
        assert_eq!(issue.title, "Test issue");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_issue() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(graphql_success(&serde_json::json!({
                "issueCreate": {
                    "success": true,
                    "issue": {
                        "id": "issue-2",
                        "identifier": "LIN-2",
                        "title": "New bug",
                        "team": { "id": "t1" }
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()));

        let issue = client
            .create_issue("New bug", "t1", None)
            .await
            .unwrap();
        assert_eq!(issue.identifier, "LIN-2");
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_issues() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(graphql_success(&serde_json::json!({
                "searchIssues": {
                    "nodes": [
                        { "id": "i1", "identifier": "LIN-1", "title": "Login bug" },
                        { "id": "i2", "identifier": "LIN-2", "title": "Logout bug" }
                    ]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()));

        let issues = client.search_issues("bug").await.unwrap();
        assert_eq!(issues.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_teams() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(graphql_success(&serde_json::json!({
                "teams": {
                    "nodes": [
                        { "id": "t1", "name": "Engineering", "key": "ENG" },
                        { "id": "t2", "name": "Design", "key": "DES" }
                    ]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()));

        let teams = client.list_teams().await.unwrap();
        assert_eq!(teams.len(), 2);
        assert_eq!(teams[0].key, "ENG");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_cycles() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(graphql_success(&serde_json::json!({
                "team": {
                    "cycles": {
                        "nodes": [
                            { "id": "c1", "number": 1, "name": "Sprint 1" },
                            { "id": "c2", "number": 2, "name": "Sprint 2" }
                        ]
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()));

        let cycles = client.list_cycles("t1").await.unwrap();
        assert_eq!(cycles.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_projects() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(graphql_success(&serde_json::json!({
                "projects": {
                    "nodes": [
                        { "id": "p1", "name": "Q1 Goals" }
                    ]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()));

        let projects = client.list_projects().await.unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Q1 Goals");
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("bad-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()))
            .with_retry_config(0);

        let result = client.list_teams().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LinearError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_graphql_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errors": [{ "message": "Variable '$id' is not defined" }]
            })))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_issue("bad-id").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            LinearError::Api { message, .. } => {
                assert!(message.contains("not defined"));
            }
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()))
            .with_retry_config(0);

        let result = client.list_teams().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LinearError::RateLimited { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = LinearError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = LinearError::Unauthorized;
        assert!(!err.is_retryable());

        let err = LinearError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }
}
