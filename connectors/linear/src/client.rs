//! Linear GraphQL API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use reqwest::{Client, StatusCode, header};
use tracing::debug;

use crate::{
    error::{LinearError, LinearResult},
    types::{
        CommentCreatePayload, Cycle, GraphQLRequest, GraphQLResponse, Issue, IssueCreatePayload,
        IssueUpdatePayload, Project, Team,
    },
};

/// Default Linear GraphQL API URL.
pub const DEFAULT_API_URL: &str = "https://api.linear.app/graphql";

/// Authentication mode for the Linear API.
#[derive(Clone)]
pub enum LinearAuth {
    /// Direct API key.
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl LinearAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for LinearAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Linear GraphQL API client.
pub struct LinearClient {
    http: Client,
    auth: LinearAuth,
    api_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl LinearClient {
    /// Create a new Linear client with a direct API key.
    pub fn new(api_key: &str) -> LinearResult<Self> {
        Self::new_with_auth(LinearAuth::ApiKey(api_key.to_string()))
    }

    /// Create a new Linear client with explicit auth mode.
    pub fn new_with_auth(auth: LinearAuth) -> LinearResult<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("fcp-linear/0.1.0")
            .build()
            .map_err(LinearError::Http)?;

        Ok(Self {
            http,
            auth,
            api_url: DEFAULT_API_URL.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
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
        self.retry_config.max_retries = max_retries;
        self
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get the auth mode.
    #[must_use]
    pub const fn auth(&self) -> &LinearAuth {
        &self.auth
    }

    /// Get the API URL.
    #[must_use]
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Perform a safe, read-only health check by querying the viewer.
    ///
    /// Validates that the API key is valid and the Linear API is reachable
    /// without any side effects.
    pub async fn health_check(&self) -> LinearResult<()> {
        let query = r"query { viewer { id } }";
        let _data = self.execute_graphql(query, None).await?;
        Ok(())
    }

    /// Apply authentication headers to a request builder.
    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            LinearAuth::ApiKey(key) => {
                builder.header(header::AUTHORIZATION, format!("Bearer {key}"))
            }
            LinearAuth::CredentialId(_) => {
                // Secretless: egress proxy injects credentials. Send without auth header.
                builder
            }
        }
    }

    fn parse_retry_after(headers: &header::HeaderMap) -> Option<Duration> {
        headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
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
        let payload: IssueCreatePayload = serde_json::from_value(data["issueCreate"].clone())?;

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
        let payload: IssueUpdatePayload = serde_json::from_value(data["issueUpdate"].clone())?;

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
        let payload: CommentCreatePayload = serde_json::from_value(data["commentCreate"].clone())?;

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
        let ctx = self.runtime.request_context();
        let retry_ctx = ctx.clone();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let request = &request;
            let retry_ctx = retry_ctx.clone();
            async move {
                debug!(attempt, api_url = %self.api_url, "GraphQL request");

                let builder = self
                    .http
                    .post(&self.api_url)
                    .header(header::CONTENT_TYPE, "application/json");
                let builder = self.apply_auth(builder);

                match builder.json(request).send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            return AttemptOutcome::Terminal(LinearError::Unauthorized);
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after = Self::parse_retry_after(response.headers())
                                .unwrap_or_else(|| {
                                    Duration::from_millis(self.retry_config.max_delay_ms)
                                });
                            let error = LinearError::RateLimited {
                                retry_after_ms: u64::try_from(retry_after.as_millis())
                                    .unwrap_or(u64::MAX),
                            };
                            let within_retry_budget = attempt < self.retry_config.max_retries;
                            let within_time_budget = match retry_ctx.remaining_budget() {
                                Some(budget) => retry_after <= budget,
                                None => true,
                            };

                            return if within_retry_budget && within_time_budget {
                                AttemptOutcome::Retryable {
                                    error,
                                    retry_after: Some(retry_after),
                                }
                            } else {
                                AttemptOutcome::Terminal(error)
                            };
                        }

                        if status.is_server_error() {
                            return AttemptOutcome::Retryable {
                                error: LinearError::Api {
                                    message: format!("Server error: {status}"),
                                    status_code: Some(status.as_u16()),
                                },
                                retry_after: None,
                            };
                        }

                        match response.text().await {
                            Ok(body) if !status.is_success() => {
                                AttemptOutcome::Terminal(LinearError::Api {
                                    message: format!("HTTP {status}: {body}"),
                                    status_code: Some(status.as_u16()),
                                })
                            }
                            Ok(body) => match serde_json::from_str::<GraphQLResponse>(&body) {
                                Ok(gql_response) => {
                                    if let Some(errors) = gql_response.errors {
                                        if !errors.is_empty() {
                                            let messages: Vec<&str> =
                                                errors.iter().map(|e| e.message.as_str()).collect();
                                            return AttemptOutcome::Terminal(LinearError::Api {
                                                message: messages.join("; "),
                                                status_code: None,
                                            });
                                        }
                                    }

                                    match gql_response.data {
                                        Some(data) => AttemptOutcome::Success(data),
                                        None => AttemptOutcome::Terminal(LinearError::Api {
                                            message: "Empty response data".into(),
                                            status_code: None,
                                        }),
                                    }
                                }
                                Err(error) => AttemptOutcome::Terminal(LinearError::Json(error)),
                            },
                            Err(error) if error.is_timeout() || error.is_connect() => {
                                AttemptOutcome::Retryable {
                                    error: LinearError::Http(error),
                                    retry_after: None,
                                }
                            }
                            Err(error) => AttemptOutcome::Terminal(LinearError::Http(error)),
                        }
                    }
                    Err(error) if error.is_timeout() || error.is_connect() => {
                        AttemptOutcome::Retryable {
                            error: LinearError::Http(error),
                            retry_after: None,
                        }
                    }
                    Err(error) => AttemptOutcome::Terminal(LinearError::Http(error)),
                }
            }
        })
        .await
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

        let issue = client.create_issue("New bug", "t1", None).await.unwrap();
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

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited_retry_after_beyond_request_budget_is_terminal() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount(&mock_server)
            .await;

        let client = LinearClient::new("test-key")
            .unwrap()
            .with_api_url(&format!("{}/graphql", mock_server.uri()))
            .with_retry_config(1);

        let result = client.list_teams().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LinearError::RateLimited {
                retry_after_ms: 60_000
            }
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
