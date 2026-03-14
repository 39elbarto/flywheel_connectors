//! Google Docs API v1 client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use reqwest::Client;
use serde::de::DeserializeOwned;
use tracing::{instrument, warn};

use crate::error::{DocsError, DocsResult};
use crate::types::{ApiErrorDetail, ApiErrorResponse, BatchUpdateResponse, Document};

const DEFAULT_BASE_URL: &str = "https://docs.googleapis.com/v1";

/// Google Docs API client.
#[derive(Debug)]
pub struct DocsClient {
    client: Client,
    auth: GoogleMaterializedAuth,
    base_url: String,
    total_requests: AtomicU64,
}

impl DocsClient {
    /// Create a new Docs client with the shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> DocsResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-docs/0.1.0")
            .build()
            .map_err(DocsError::Http)?;

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

    /// Get a document by ID.
    #[instrument(skip(self), fields(document_id))]
    pub async fn get_document(&self, document_id: &str) -> DocsResult<Document> {
        let url = format!("{}/documents/{document_id}", self.base_url);
        self.get_json(&url).await
    }

    /// Create a new document.
    #[instrument(skip(self), fields(title))]
    pub async fn create_document(&self, title: &str) -> DocsResult<Document> {
        let url = format!("{}/documents", self.base_url);
        let body = serde_json::json!({ "title": title });
        self.post_json(&url, &body).await
    }

    /// Apply batch updates to a document.
    #[instrument(skip(self, requests), fields(document_id))]
    pub async fn batch_update(
        &self,
        document_id: &str,
        requests: Vec<serde_json::Value>,
    ) -> DocsResult<BatchUpdateResponse> {
        let url = format!("{}/documents/{document_id}:batchUpdate", self.base_url);
        let body = serde_json::json!({ "requests": requests });
        self.post_json(&url, &body).await
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

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> DocsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let token = self.bearer_token().ok_or(DocsError::Unauthorized)?;
        let resp = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(DocsError::Http)?;
        self.handle_response(resp).await
    }

    async fn post_json<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> DocsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let token = self.bearer_token().ok_or(DocsError::Unauthorized)?;
        let resp = self
            .client
            .post(url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(DocsError::Http)?;
        self.handle_response(resp).await
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> DocsResult<T> {
        let status = resp.status();
        if status.is_success() {
            return resp.json().await.map_err(DocsError::Http);
        }
        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&body) {
            Err(map_api_error(api_err.error))
        } else {
            warn!(status = code, body_preview = &body[..body.len().min(200)], "Docs API error");
            Err(DocsError::Api {
                status_code: code,
                message: body,
            })
        }
    }
}

fn map_api_error(error: ApiErrorDetail) -> DocsError {
    match error.code {
        401 => DocsError::Unauthorized,
        403 => DocsError::Forbidden {
            message: error.message,
        },
        404 => DocsError::DocumentNotFound {
            document_id: error.message,
        },
        429 => DocsError::RateLimited {
            retry_after_ms: 60_000,
        },
        code => DocsError::Api {
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
        assert!(matches!(err, DocsError::Unauthorized));
    }

    #[test]
    fn map_api_error_403() {
        let err = map_api_error(ApiErrorDetail {
            code: 403,
            message: "forbidden".into(),
        });
        assert!(matches!(err, DocsError::Forbidden { .. }));
    }

    #[test]
    fn map_api_error_404() {
        let err = map_api_error(ApiErrorDetail {
            code: 404,
            message: "not found".into(),
        });
        assert!(matches!(err, DocsError::DocumentNotFound { .. }));
    }

    #[test]
    fn map_api_error_429() {
        let err = map_api_error(ApiErrorDetail {
            code: 429,
            message: "rate limited".into(),
        });
        assert!(matches!(err, DocsError::RateLimited { .. }));
    }

    #[test]
    fn map_api_error_500() {
        let err = map_api_error(ApiErrorDetail {
            code: 500,
            message: "internal".into(),
        });
        assert!(matches!(err, DocsError::Api { status_code: 500, .. }));
    }

    #[test]
    fn auth_redacted_label_credential_ref() {
        let cred_id = fcp_core::CredentialId::new();
        let label = format!("credential_id:{cred_id}");
        let client = DocsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: cred_id,
            quota_project_id: None,
        })
        .unwrap();
        assert_eq!(client.auth_redacted_label(), label);
    }
}
