//! Monday.com GraphQL API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{MondayError, MondayResult},
    types::{ApiErrorResponse, GraphQLResponse},
};

/// Default Monday.com API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.monday.com/v2";

/// Authentication mode for the Monday.com API.
#[derive(Clone)]
pub enum MondayAuth {
    /// API token (passed as `Authorization: <token>` without Bearer prefix).
    ApiToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl MondayAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiToken(_) => "api_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for MondayAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiToken(_) => f.debug_tuple("ApiToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Monday.com GraphQL API client.
pub struct MondayClient {
    client: Client,
    auth: MondayAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for MondayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MondayClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl MondayClient {
    /// Create a new Monday.com client.
    pub fn new(auth: MondayAuth, base_url: Option<&str>) -> MondayResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-monday/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            MondayAuth::ApiToken(token) => req.header("Authorization", token),
            MondayAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    /// Execute a GraphQL query against the Monday.com API.
    #[instrument(skip(self, graphql_query))]
    pub async fn query(&self, graphql_query: &str) -> MondayResult<serde_json::Value> {
        let body = json!({ "query": graphql_query });
        debug!(url = %self.base_url, "GraphQL POST request");
        let req = self
            .add_auth(self.client.post(&self.base_url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    async fn handle_response(&self, resp: Response) -> MondayResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(json!({}));
            }
            // Monday.com returns 200 for GraphQL errors, so check for errors in the body.
            let gql_resp: GraphQLResponse = serde_json::from_str(&body)?;
            if let Some(errors) = gql_resp.errors {
                if !errors.is_empty() {
                    let messages: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
                    return Err(MondayError::GraphQL {
                        message: messages.join("; "),
                    });
                }
            }
            gql_resp.data.ok_or_else(|| MondayError::GraphQL {
                message: "No data in response".into(),
            })
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> MondayResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error_message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(MondayError::Unauthorized),
            403 => Err(MondayError::Forbidden),
            404 => Err(MondayError::NotFound { resource: detail }),
            429 => Err(MondayError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(MondayError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    // -- Board operations --

    /// List boards.
    pub async fn list_boards(&self, limit: u64) -> MondayResult<serde_json::Value> {
        let query = format!("{{ boards(limit: {limit}) {{ id name state board_kind }} }}");
        self.query(&query).await
    }

    /// Get a single board by ID.
    pub async fn get_board(&self, board_id: &str) -> MondayResult<serde_json::Value> {
        let query = format!("{{ boards(ids: [{board_id}]) {{ id name description state }} }}");
        self.query(&query).await
    }

    // -- Item operations --

    /// List items on a board.
    pub async fn list_items(&self, board_id: &str) -> MondayResult<serde_json::Value> {
        let query = format!(
            "{{ boards(ids: [{board_id}]) {{ items_page(limit: 50) {{ items {{ id name state column_values {{ id text value }} }} }} }} }}"
        );
        self.query(&query).await
    }

    /// Create an item on a board.
    pub async fn create_item(
        &self,
        board_id: &str,
        item_name: &str,
        column_values: Option<&str>,
    ) -> MondayResult<serde_json::Value> {
        let cv_arg = match column_values {
            Some(cv) => {
                // Escape the column_values JSON string for embedding in GraphQL.
                let escaped = cv.replace('\\', "\\\\").replace('"', "\\\"");
                format!(", column_values: \"{escaped}\"")
            }
            None => String::new(),
        };
        let escaped_name = item_name.replace('\\', "\\\\").replace('"', "\\\"");
        let query = format!(
            "mutation {{ create_item(board_id: {board_id}, item_name: \"{escaped_name}\"{cv_arg}) {{ id name }} }}"
        );
        self.query(&query).await
    }

    /// Delete an item.
    pub async fn delete_item(&self, item_id: &str) -> MondayResult<serde_json::Value> {
        let query = format!("mutation {{ delete_item(item_id: {item_id}) {{ id }} }}");
        self.query(&query).await
    }

    // -- Update operations --

    /// List updates on an item.
    pub async fn list_updates(&self, item_id: &str) -> MondayResult<serde_json::Value> {
        let query = format!(
            "{{ items(ids: [{item_id}]) {{ updates {{ id text_body creator {{ name }} created_at }} }} }}"
        );
        self.query(&query).await
    }

    /// Create an update (comment) on an item.
    pub async fn create_update(
        &self,
        item_id: &str,
        body_text: &str,
    ) -> MondayResult<serde_json::Value> {
        let escaped = body_text.replace('\\', "\\\\").replace('"', "\\\"");
        let query = format!(
            "mutation {{ create_update(item_id: {item_id}, body: \"{escaped}\") {{ id text_body }} }}"
        );
        self.query(&query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = MondayAuth::ApiToken("secret-api-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = MondayAuth::ApiToken("tok".into());
        assert!(!token.is_secretless());
        let cred = MondayAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = MondayAuth::ApiToken("tok".into());
        assert_eq!(token.redacted_label(), "api_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = MondayAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = MondayClient::new(MondayAuth::ApiToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = MondayClient::new(
            MondayAuth::ApiToken("tok".into()),
            Some("https://test.example.com/v2/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/v2");
    }

    #[test]
    fn client_debug_redacts() {
        let client = MondayClient::new(MondayAuth::ApiToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_clone() {
        let auth = MondayAuth::ApiToken("tok".into());
        let auth2 = auth.clone();
        assert_eq!(auth.redacted_label(), auth2.redacted_label());
    }

    #[test]
    fn auth_credential_debug_shows_id() {
        let cred = MondayAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_new_trailing_slash_stripped() {
        let client = MondayClient::new(
            MondayAuth::ApiToken("tok".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = MondayClient::new(MondayAuth::ApiToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("MondayClient"));
        assert!(dbg.contains("monday.com"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_no_trailing_slash() {
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn auth_api_token_not_in_label() {
        let auth = MondayAuth::ApiToken("super-secret-123".into());
        let label = auth.redacted_label();
        assert!(!label.contains("super-secret-123"));
    }

    #[test]
    fn auth_api_token_not_secretless() {
        let auth = MondayAuth::ApiToken("tok".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = MondayAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }
}
