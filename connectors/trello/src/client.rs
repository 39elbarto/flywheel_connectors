//! Trello API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{TrelloError, TrelloResult},
    types::ApiErrorResponse,
};

/// Default Trello REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.trello.com/1";

/// Authentication mode for the Trello API.
#[derive(Clone)]
pub enum TrelloAuth {
    /// API key + token (passed as query params `?key=KEY&token=TOKEN`).
    ApiKeyToken { api_key: String, token: String },
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl TrelloAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKeyToken { .. } => "api_key_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for TrelloAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKeyToken { .. } => f
                .debug_struct("ApiKeyToken")
                .field("api_key", &"<redacted>")
                .field("token", &"<redacted>")
                .finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Trello API client.
pub struct TrelloClient {
    client: Client,
    auth: TrelloAuth,
    base_url: String,
}

impl fmt::Debug for TrelloClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrelloClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl TrelloClient {
    /// Create a new Trello client.
    pub fn new(auth: TrelloAuth, base_url: Option<&str>) -> TrelloResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-trello/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    /// Build the full URL with authentication query parameters (for API key/token auth).
    fn build_url(&self, path: &str) -> String {
        let base = format!("{}{path}", self.base_url);
        match &self.auth {
            TrelloAuth::ApiKeyToken { api_key, token } => {
                let sep = if base.contains('?') { '&' } else { '?' };
                format!("{base}{sep}key={api_key}&token={token}")
            }
            TrelloAuth::CredentialId(_) => base,
        }
    }

    fn add_auth_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            TrelloAuth::ApiKeyToken { .. } => req, // auth is in query params
            TrelloAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> TrelloResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> TrelloResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        // Trello returns {"message": "...", "error": "..."} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(TrelloError::Unauthorized),
            403 => Err(TrelloError::Forbidden),
            404 => Err(TrelloError::NotFound { resource: detail }),
            429 => Err(TrelloError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(10) * 1000,
            }),
            code => Err(TrelloError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> TrelloResult<serde_json::Value> {
        let url = self.build_url(path);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth_headers(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> TrelloResult<serde_json::Value> {
        let url = self.build_url(path);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth_headers(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn put(&self, path: &str, body: &serde_json::Value) -> TrelloResult<serde_json::Value> {
        let url = self.build_url(path);
        debug!(url = %url, "PUT request");
        let req = self
            .add_auth_headers(self.client.put(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> TrelloResult<serde_json::Value> {
        let url = self.build_url(path);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth_headers(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Boards --

    /// List boards for a member.
    pub async fn list_boards(&self, member: &str) -> TrelloResult<serde_json::Value> {
        self.get(&format!("/members/{member}/boards")).await
    }

    /// Get a single board by ID.
    pub async fn get_board(&self, board_id: &str) -> TrelloResult<serde_json::Value> {
        self.get(&format!("/boards/{board_id}")).await
    }

    // -- Lists --

    /// List all lists on a board.
    pub async fn list_lists(&self, board_id: &str) -> TrelloResult<serde_json::Value> {
        self.get(&format!("/boards/{board_id}/lists")).await
    }

    // -- Cards --

    /// List cards on a list.
    pub async fn list_cards(&self, list_id: &str) -> TrelloResult<serde_json::Value> {
        self.get(&format!("/lists/{list_id}/cards")).await
    }

    /// Get a single card by ID.
    pub async fn get_card(&self, card_id: &str) -> TrelloResult<serde_json::Value> {
        self.get(&format!("/cards/{card_id}")).await
    }

    /// Create a new card.
    pub async fn create_card(&self, body: &serde_json::Value) -> TrelloResult<serde_json::Value> {
        self.post("/cards", body).await
    }

    /// Update an existing card.
    pub async fn update_card(
        &self,
        card_id: &str,
        body: &serde_json::Value,
    ) -> TrelloResult<serde_json::Value> {
        self.put(&format!("/cards/{card_id}"), body).await
    }

    /// Delete a card.
    pub async fn delete_card(&self, card_id: &str) -> TrelloResult<serde_json::Value> {
        self.delete(&format!("/cards/{card_id}")).await
    }

    // -- Labels --

    /// List labels on a board.
    pub async fn list_labels(&self, board_id: &str) -> TrelloResult<serde_json::Value> {
        self.get(&format!("/boards/{board_id}/labels")).await
    }

    // -- Members --

    /// List members of a board.
    pub async fn list_members(&self, board_id: &str) -> TrelloResult<serde_json::Value> {
        self.get(&format!("/boards/{board_id}/members")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key_and_token() {
        let auth = TrelloAuth::ApiKeyToken {
            api_key: "secret-api-key".into(),
            token: "secret-token".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-key"));
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = TrelloAuth::ApiKeyToken {
            api_key: "key".into(),
            token: "tok".into(),
        };
        assert!(!token.is_secretless());
        let cred = TrelloAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_api_key_token() {
        let auth = TrelloAuth::ApiKeyToken {
            api_key: "key".into(),
            token: "tok".into(),
        };
        assert_eq!(auth.redacted_label(), "api_key_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = TrelloAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "k".into(),
                token: "t".into(),
            },
            None,
        )
        .unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "k".into(),
                token: "t".into(),
            },
            Some("https://test.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api");
    }

    #[test]
    fn client_debug_redacts() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "secret-key".into(),
                token: "secret-token".into(),
            },
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret-key"));
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "k".into(),
                token: "t".into(),
            },
            Some("https://api.trello.com/1/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://api.trello.com/1");
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = TrelloAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }
}
