//! Minimal Drive Activity v2 HTTP client. The query RPC is replay-safe.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleResponseBody, GoogleResponseMode, GoogleRestError,
    GoogleRestExecutor,
};
use fcp_google_discovery::{DiscoveryMethod, DiscoveryParameter};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Url, header};
use serde_json::Value;
use tracing::debug;

use crate::error::{DriveActivityError, DriveActivityResult};

pub const DEFAULT_BASE_URL: &str = "https://driveactivity.googleapis.com/v2";
const MAX_RESPONSE_BYTES: usize = 60_000;

pub struct DriveActivityClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl std::fmt::Debug for DriveActivityClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriveActivityClient")
            .field("base_url", &self.base_url)
            .field("auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl DriveActivityClient {
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> DriveActivityResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-drive-activity/0.1.0")
            .build()?;
        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(client),
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                initial_delay_ms: 500,
                max_delay_ms: 30_000,
                jitter_enabled: true,
            },
            total_requests: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
    }

    #[must_use]
    pub const fn auth_redacted_label(&self) -> &'static str {
        match self.auth {
            GoogleMaterializedAuth::BearerToken { .. } => "bearer:redacted",
            GoogleMaterializedAuth::CredentialReference { .. } => "credential_reference",
        }
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    pub async fn query(&self, body: &Value) -> DriveActivityResult<Value> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let url = format!("{}/activity:query", self.base_url);
        let context = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let response = RetryLoop::execute(&context, &policy, |attempt| {
            let url = url.clone();
            async move {
                debug!(
                    attempt,
                    operation = "drive_activity.query",
                    "drive activity request"
                );
                match self.execute_once(&url, body).await {
                    Ok(value) => AttemptOutcome::Success(value),
                    Err(error) if error.is_retryable() => {
                        let retry_after = error.retry_after();
                        AttemptOutcome::Retryable { error, retry_after }
                    }
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await?;
        let bytes = serde_json::to_vec(&response)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(DriveActivityError::Oversize);
        }
        Ok(response)
    }

    async fn execute_once(&self, raw_url: &str, body: &Value) -> DriveActivityResult<Value> {
        let parsed =
            Url::parse(raw_url).map_err(|_| DriveActivityError::Api { status_code: 400 })?;
        let path = parsed.path().trim_start_matches('/').to_string();
        let method = DiscoveryMethod {
            key: "driveactivity.activity.query".into(),
            id: "driveactivity.activity.query".into(),
            http_method: "POST".into(),
            path: path.clone(),
            flat_path: None,
            canonical_path: path,
            resource_path: Vec::new(),
            description: None,
            scopes: vec!["https://www.googleapis.com/auth/drive.activity.readonly".into()],
            request_ref: None,
            response_ref: None,
            parameters: BTreeMap::<String, DiscoveryParameter>::new(),
            supports_media_download: false,
            supports_media_upload: false,
            media_upload: None,
        };
        let mut base_url = parsed.origin().ascii_serialization();
        base_url.push('/');
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&method, &schemas, &base_url);
        request.body = Some(body.clone());
        request.response_mode = GoogleResponseMode::Json;
        request.auth = Some(&self.auth);
        let response = self
            .executor
            .execute(&request)
            .await
            .map_err(map_rest_error)?;
        match response.body {
            GoogleResponseBody::Json(value) => Ok(value),
            GoogleResponseBody::Binary(bytes) => Ok(serde_json::from_slice(&bytes)?),
            GoogleResponseBody::Empty => Err(DriveActivityError::Api {
                status_code: response.status_code,
            }),
        }
    }
}

fn map_rest_error(error: GoogleRestError) -> DriveActivityError {
    match error {
        GoogleRestError::Http { source } => DriveActivityError::Http(source),
        GoogleRestError::JsonDecode { source } => DriveActivityError::Json(source),
        GoogleRestError::Api { error, .. } => map_api_error(&error),
        _ => DriveActivityError::Api { status_code: 500 },
    }
}

fn map_api_error(error: &GoogleApiError) -> DriveActivityError {
    match error.status_code {
        401 => DriveActivityError::Unauthorized,
        403 => DriveActivityError::Forbidden,
        429 => DriveActivityError::RateLimited {
            retry_after_ms: error.retry_after_ms.unwrap_or(60_000),
        },
        status_code => DriveActivityError::Api { status_code },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_error(status_code: u16) -> GoogleApiError {
        GoogleApiError {
            status_code,
            message: "private provider message".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        }
    }

    #[test]
    fn provider_details_are_redacted() {
        for status in [400, 401, 403, 429, 500] {
            let error = map_api_error(&api_error(status));
            assert!(!error.to_string().contains("private provider message"));
        }
    }
}
