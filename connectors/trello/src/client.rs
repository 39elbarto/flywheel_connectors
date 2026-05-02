//! Trello API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{TrelloError, TrelloResult},
    types::ApiErrorResponse,
};

/// Default Trello REST API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.trello.com/1";

/// Validate a path segment to prevent path traversal attacks.
fn sanitize_path_segment(segment: &str) -> TrelloResult<&str> {
    if segment.trim().is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('\0')
        || segment == "."
        || segment == ".."
    {
        return Err(TrelloError::InvalidInput(format!(
            "Invalid path segment: {segment}"
        )));
    }
    Ok(segment)
}

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
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
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

        let request_timeout = Duration::from_secs(30);
        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config: HttpRetryConfig::default(),
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Build the base URL for a request (without credentials).
    fn build_url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Add authentication to a request builder.
    ///
    /// For API key/token auth, credentials are added as query parameters
    /// via reqwest's `.query()` to avoid embedding secrets in the URL string.
    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            TrelloAuth::ApiKeyToken { api_key, token } => {
                req.query(&[("key", api_key.as_str()), ("token", token.as_str())])
            }
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
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> TrelloResult<serde_json::Value> {
        let url = self.build_url(path);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn put(&self, path: &str, body: &serde_json::Value) -> TrelloResult<serde_json::Value> {
        let url = self.build_url(path);
        debug!(url = %redact_url(&url), "PUT request");
        let req = self
            .add_auth(self.client.put(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> TrelloResult<serde_json::Value> {
        let url = self.build_url(path);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Boards --

    /// List boards for a member.
    pub async fn list_boards(&self, member: &str) -> TrelloResult<serde_json::Value> {
        let member = sanitize_path_segment(member)?;
        self.get(&format!("/members/{member}/boards")).await
    }

    /// Get a single board by ID.
    pub async fn get_board(&self, board_id: &str) -> TrelloResult<serde_json::Value> {
        let board_id = sanitize_path_segment(board_id)?;
        self.get(&format!("/boards/{board_id}")).await
    }

    // -- Lists --

    /// List all lists on a board.
    pub async fn list_lists(&self, board_id: &str) -> TrelloResult<serde_json::Value> {
        let board_id = sanitize_path_segment(board_id)?;
        self.get(&format!("/boards/{board_id}/lists")).await
    }

    // -- Cards --

    /// List cards on a list.
    pub async fn list_cards(&self, list_id: &str) -> TrelloResult<serde_json::Value> {
        let list_id = sanitize_path_segment(list_id)?;
        self.get(&format!("/lists/{list_id}/cards")).await
    }

    /// Get a single card by ID.
    pub async fn get_card(&self, card_id: &str) -> TrelloResult<serde_json::Value> {
        let card_id = sanitize_path_segment(card_id)?;
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
        let card_id = sanitize_path_segment(card_id)?;
        self.put(&format!("/cards/{card_id}"), body).await
    }

    /// Delete a card.
    pub async fn delete_card(&self, card_id: &str) -> TrelloResult<serde_json::Value> {
        let card_id = sanitize_path_segment(card_id)?;
        self.delete(&format!("/cards/{card_id}")).await
    }

    // -- Labels --

    /// List labels on a board.
    pub async fn list_labels(&self, board_id: &str) -> TrelloResult<serde_json::Value> {
        let board_id = sanitize_path_segment(board_id)?;
        self.get(&format!("/boards/{board_id}/labels")).await
    }

    // -- Members --

    /// List members of a board.
    pub async fn list_members(&self, board_id: &str) -> TrelloResult<serde_json::Value> {
        let board_id = sanitize_path_segment(board_id)?;
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

    #[test]
    fn client_debug_contains_struct_name() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "k".into(),
                token: "t".into(),
            },
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("TrelloClient"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "k".into(),
                token: "t".into(),
            },
            Some("https://custom.trello.com/1"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.trello.com"));
    }

    #[test]
    fn auth_debug_api_key_token_contains_type() {
        let auth = TrelloAuth::ApiKeyToken {
            api_key: "k".into(),
            token: "t".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiKeyToken"));
    }

    #[test]
    fn default_base_url_starts_with_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_is_trello_v1() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.trello.com/1");
    }

    #[test]
    fn auth_api_key_token_clone() {
        let auth = TrelloAuth::ApiKeyToken {
            api_key: "my-key".into(),
            token: "my-token".into(),
        };
        let cloned = TrelloAuth::clone(&auth);
        assert!(!cloned.is_secretless());
        assert_eq!(cloned.redacted_label(), "api_key_token:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let auth = TrelloAuth::CredentialId(CredentialId::new());
        let cloned = TrelloAuth::clone(&auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "k".into(),
                token: "t".into(),
            },
            Some("https://api.trello.com/1///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_credential_debug_does_not_contain_redacted_tag() {
        let cred = TrelloAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("<redacted>"));
    }

    #[test]
    fn client_new_empty_url() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "k".into(),
                token: "t".into(),
            },
            Some(""),
        )
        .unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn auth_redacted_label_does_not_leak_key_or_token() {
        let auth = TrelloAuth::ApiKeyToken {
            api_key: "my-super-key".into(),
            token: "my-super-token".into(),
        };
        let label = auth.redacted_label();
        assert!(!label.contains("my-super-key"));
        assert!(!label.contains("my-super-token"));
    }

    #[test]
    fn client_debug_does_not_leak_token_value() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "xyzzy-key-42".into(),
                token: "xyzzy-token-99".into(),
            },
            None,
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("xyzzy-key-42"));
        assert!(!dbg.contains("xyzzy-token-99"));
        assert!(dbg.contains("TrelloClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn build_url_does_not_embed_credentials() {
        let client = TrelloClient::new(
            TrelloAuth::ApiKeyToken {
                api_key: "secret-key-abc".into(),
                token: "secret-token-xyz".into(),
            },
            None,
        )
        .unwrap();
        let url = client.build_url("/boards/123");
        assert!(!url.contains("secret-key-abc"));
        assert!(!url.contains("secret-token-xyz"));
        assert!(url.contains("/boards/123"));
    }

    #[test]
    fn sanitize_rejects_path_traversal() {
        assert!(sanitize_path_segment("..").is_err());
        assert!(sanitize_path_segment(".").is_err());
        assert!(sanitize_path_segment("foo/bar").is_err());
        assert!(sanitize_path_segment("").is_err());
        assert!(sanitize_path_segment("foo\0bar").is_err());
        assert!(sanitize_path_segment("foo\\bar").is_err());
    }

    #[test]
    fn sanitize_accepts_valid_ids() {
        assert!(sanitize_path_segment("abc123").is_ok());
        assert!(sanitize_path_segment("5f4e3d2c1b0a").is_ok());
        assert!(sanitize_path_segment("my-board").is_ok());
    }
}
