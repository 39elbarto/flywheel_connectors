//! Google Chat API v1 client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use tracing::{instrument, warn};

use crate::error::{ChatError, ChatResult};
use crate::types::{
    ApiErrorDetail, ApiErrorResponse, ListMembershipsResponse, ListMessagesResponse,
    ListSpacesResponse, Membership, Message, Space,
};

const DEFAULT_BASE_URL: &str = "https://chat.googleapis.com/v1";

/// Validate a Google Chat resource name (e.g. `spaces/ABC` or `spaces/ABC/messages/XYZ`).
///
/// Rejects path traversal (`..`), query strings (`?`), fragments (`#`),
/// and percent-encoded separators that could escape the intended API path.
fn validate_resource_name(name: &str, field: &str) -> ChatResult<()> {
    if name.is_empty()
        || name.contains("..")
        || name.contains('?')
        || name.contains('#')
        || name.to_ascii_lowercase().contains("%2f")
        || name.to_ascii_lowercase().contains("%5c")
        || name.starts_with('/')
    {
        return Err(ChatError::Api {
            status_code: 0,
            message: format!("{field} contains invalid characters: {name:?}"),
        });
    }
    Ok(())
}

/// Google Chat API client.
pub struct ChatClient {
    client: Client,
    auth: GoogleMaterializedAuth,
    base_url: String,
    total_requests: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for ChatClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatClient")
            .field("base_url", &self.base_url)
            .field("total_requests", &self.total_requests)
            .field("auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ChatClient {
    /// Create a new Chat client with the shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> ChatResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-chat/0.1.0")
            .build()
            .map_err(ChatError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            total_requests: AtomicU64::new(0),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Get current auth.
    #[must_use]
    pub const fn auth(&self) -> &GoogleMaterializedAuth {
        &self.auth
    }

    #[cfg(test)]
    #[must_use]
    fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
    }

    /// Render a redacted auth label for diagnostics.
    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
            GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
                format!("credential_id:{credential_id}")
            }
        }
    }

    /// List all spaces the authenticated user has access to.
    #[instrument(skip(self))]
    pub async fn list_spaces(&self) -> ChatResult<Vec<Space>> {
        let url = format!("{}/spaces", self.base_url);
        let resp: ListSpacesResponse = self.get_json(&url).await?;
        Ok(resp.spaces)
    }

    /// Get a specific space by resource name.
    #[instrument(skip(self), fields(space_name))]
    pub async fn get_space(&self, space_name: &str) -> ChatResult<Space> {
        validate_resource_name(space_name, "space_name")?;
        let url = format!("{}/{space_name}", self.base_url);
        self.get_json(&url).await
    }

    /// Create (send) a message in a space.
    #[instrument(skip(self), fields(space_name))]
    pub async fn create_message(&self, space_name: &str, text: &str) -> ChatResult<Message> {
        validate_resource_name(space_name, "space_name")?;
        let url = format!("{}/{space_name}/messages", self.base_url);
        let body = serde_json::json!({ "text": text });
        self.post_json(&url, &body).await
    }

    /// List messages in a space.
    #[instrument(skip(self), fields(space_name))]
    pub async fn list_messages(&self, space_name: &str) -> ChatResult<Vec<Message>> {
        validate_resource_name(space_name, "space_name")?;
        let url = format!("{}/{space_name}/messages", self.base_url);
        let resp: ListMessagesResponse = self.get_json(&url).await?;
        Ok(resp.messages)
    }

    /// Get a specific message by resource name.
    #[instrument(skip(self), fields(message_name))]
    pub async fn get_message(&self, message_name: &str) -> ChatResult<Message> {
        validate_resource_name(message_name, "message_name")?;
        let url = format!("{}/{message_name}", self.base_url);
        self.get_json(&url).await
    }

    /// List members of a space.
    #[instrument(skip(self), fields(space_name))]
    pub async fn list_members(&self, space_name: &str) -> ChatResult<Vec<Membership>> {
        validate_resource_name(space_name, "space_name")?;
        let url = format!("{}/{space_name}/members", self.base_url);
        let resp: ListMembershipsResponse = self.get_json(&url).await?;
        Ok(resp.memberships)
    }

    /// Shut down the runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get total request count.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    fn apply_auth_headers(&self, mut builder: RequestBuilder) -> RequestBuilder {
        let mut headers = Vec::new();
        self.auth.apply_headers(&mut headers);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        builder
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> ChatResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .apply_auth_headers(self.client.get(url))
            .send()
            .await
            .map_err(ChatError::Http)?;
        self.handle_response(resp).await
    }

    async fn post_json<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> ChatResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .apply_auth_headers(self.client.post(url))
            .json(body)
            .send()
            .await
            .map_err(ChatError::Http)?;
        self.handle_response(resp).await
    }

    async fn handle_response<T: DeserializeOwned>(&self, resp: reqwest::Response) -> ChatResult<T> {
        let status = resp.status();
        if status.is_success() {
            return resp.json().await.map_err(ChatError::Http);
        }
        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&body) {
            Err(map_api_error(api_err.error))
        } else {
            let preview: String = body.chars().take(200).collect();
            warn!(status = code, body_preview = %preview, "Chat API error");
            Err(ChatError::Api {
                status_code: code,
                message: body,
            })
        }
    }
}

fn map_api_error(error: ApiErrorDetail) -> ChatError {
    match error.code {
        401 => ChatError::Unauthorized,
        403 => ChatError::Forbidden {
            message: error.message,
        },
        404 => ChatError::SpaceNotFound {
            space_name: error.message,
        },
        429 => ChatError::RateLimited {
            retry_after_ms: 60_000,
        },
        code => ChatError::Api {
            status_code: code,
            message: error.message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_google_discovery::auth::{
        FCP_CREDENTIAL_ID_HEADER, GOOGLE_AUTHORIZATION_HEADER, GoogleAuthSourceKind,
    };
    use std::future::Future;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn run_async_test<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    #[test]
    fn map_api_error_401() {
        let err = map_api_error(ApiErrorDetail {
            code: 401,
            message: "bad token".into(),
        });
        assert!(matches!(err, ChatError::Unauthorized));
    }

    #[test]
    fn map_api_error_403() {
        let err = map_api_error(ApiErrorDetail {
            code: 403,
            message: "forbidden".into(),
        });
        assert!(matches!(err, ChatError::Forbidden { .. }));
    }

    #[test]
    fn map_api_error_404() {
        let err = map_api_error(ApiErrorDetail {
            code: 404,
            message: "not found".into(),
        });
        assert!(matches!(err, ChatError::SpaceNotFound { .. }));
    }

    #[test]
    fn map_api_error_429() {
        let err = map_api_error(ApiErrorDetail {
            code: 429,
            message: "rate limited".into(),
        });
        assert!(matches!(err, ChatError::RateLimited { .. }));
    }

    #[test]
    fn map_api_error_500() {
        let err = map_api_error(ApiErrorDetail {
            code: 500,
            message: "internal".into(),
        });
        assert!(matches!(
            err,
            ChatError::Api {
                status_code: 500,
                ..
            }
        ));
    }

    #[test]
    fn auth_redacted_label_credential_ref() {
        let cred_id = fcp_core::CredentialId::new();
        let label = format!("credential_id:{cred_id}");
        let client = ChatClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: cred_id,
            quota_project_id: None,
        })
        .unwrap();
        assert_eq!(client.auth_redacted_label(), label);
    }

    #[test]
    fn total_requests_starts_at_zero() {
        let cred_id = fcp_core::CredentialId::new();
        let client = ChatClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: cred_id,
            quota_project_id: None,
        })
        .unwrap();
        assert_eq!(client.total_requests(), 0);
    }

    #[test]
    fn bearer_token_requests_use_authorization_header() {
        run_async_test(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v1/spaces"))
                .and(header(GOOGLE_AUTHORIZATION_HEADER, "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "spaces": [
                        {
                            "name": "spaces/AAAA",
                            "displayName": "Auth Header"
                        }
                    ]
                })))
                .mount(&server)
                .await;

            let client = ChatClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
                access_token: "test-token".into(),
                source: GoogleAuthSourceKind::AccessToken,
                granted_scopes: Vec::new(),
                quota_project_id: None,
            })
            .unwrap()
            .with_base_url(format!("{}/v1", server.uri()));

            let spaces = client.list_spaces().await.unwrap();
            assert_eq!(spaces[0].name, "spaces/AAAA");
        });
    }

    #[test]
    fn credential_reference_requests_use_fcp_credential_header() {
        run_async_test(async {
            let server = MockServer::start().await;
            let credential_id = fcp_core::CredentialId::new();
            Mock::given(method("GET"))
                .and(path("/v1/spaces"))
                .and(header(FCP_CREDENTIAL_ID_HEADER, credential_id.to_string()))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "spaces": [
                        {
                            "name": "spaces/BBBB",
                            "displayName": "Credential Header"
                        }
                    ]
                })))
                .mount(&server)
                .await;

            let client = ChatClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
                credential_id,
                quota_project_id: None,
            })
            .unwrap()
            .with_base_url(format!("{}/v1", server.uri()));

            let spaces = client.list_spaces().await.unwrap();
            assert_eq!(spaces[0].name, "spaces/BBBB");
        });
    }
}
