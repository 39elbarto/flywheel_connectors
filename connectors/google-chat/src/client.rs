//! Google Chat API v1 client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use reqwest::Client;
use serde::de::DeserializeOwned;
use tracing::{instrument, warn};

use crate::error::{ChatError, ChatResult};
use crate::types::{
    ApiErrorDetail, ApiErrorResponse, ListMembershipsResponse, ListMessagesResponse,
    ListSpacesResponse, Message, Membership, Space,
};

const DEFAULT_BASE_URL: &str = "https://chat.googleapis.com/v1";

/// Google Chat API client.
#[derive(Debug)]
pub struct ChatClient {
    client: Client,
    auth: GoogleMaterializedAuth,
    base_url: String,
    total_requests: AtomicU64,
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
        })
    }

    /// Get current auth.
    #[must_use]
    pub const fn auth(&self) -> &GoogleMaterializedAuth {
        &self.auth
    }

    /// Render a redacted auth label for diagnostics.
    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
            GoogleMaterializedAuth::CredentialReference {
                credential_id, ..
            } => format!("credential_id:{credential_id}"),
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
        let url = format!("{}/{space_name}", self.base_url);
        self.get_json(&url).await
    }

    /// Create (send) a message in a space.
    #[instrument(skip(self), fields(space_name))]
    pub async fn create_message(&self, space_name: &str, text: &str) -> ChatResult<Message> {
        let url = format!("{}/{space_name}/messages", self.base_url);
        let body = serde_json::json!({ "text": text });
        self.post_json(&url, &body).await
    }

    /// List messages in a space.
    #[instrument(skip(self), fields(space_name))]
    pub async fn list_messages(&self, space_name: &str) -> ChatResult<Vec<Message>> {
        let url = format!("{}/{space_name}/messages", self.base_url);
        let resp: ListMessagesResponse = self.get_json(&url).await?;
        Ok(resp.messages)
    }

    /// Get a specific message by resource name.
    #[instrument(skip(self), fields(message_name))]
    pub async fn get_message(&self, message_name: &str) -> ChatResult<Message> {
        let url = format!("{}/{message_name}", self.base_url);
        self.get_json(&url).await
    }

    /// List members of a space.
    #[instrument(skip(self), fields(space_name))]
    pub async fn list_members(&self, space_name: &str) -> ChatResult<Vec<Membership>> {
        let url = format!("{}/{space_name}/members", self.base_url);
        let resp: ListMembershipsResponse = self.get_json(&url).await?;
        Ok(resp.memberships)
    }

    /// Get total request count.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    fn bearer_token(&self) -> Option<&str> {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { access_token, .. } => Some(access_token),
            GoogleMaterializedAuth::CredentialReference { .. } => None,
        }
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> ChatResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let token = self.bearer_token().ok_or(ChatError::Unauthorized)?;
        let resp = self
            .client
            .get(url)
            .bearer_auth(token)
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
        let token = self.bearer_token().ok_or(ChatError::Unauthorized)?;
        let resp = self
            .client
            .post(url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(ChatError::Http)?;
        self.handle_response(resp).await
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> ChatResult<T> {
        let status = resp.status();
        if status.is_success() {
            return resp.json().await.map_err(ChatError::Http);
        }
        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&body) {
            Err(map_api_error(api_err.error))
        } else {
            warn!(status = code, body_preview = &body[..body.len().min(200)], "Chat API error");
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
        assert!(matches!(err, ChatError::Api { status_code: 500, .. }));
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
}
