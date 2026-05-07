//! Whisper API client for OpenAI-compatible endpoints.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{WhisperError, WhisperResult},
    types::ApiErrorResponse,
};

/// Default API base URL for the Whisper service.
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
/// Default request timeout for Whisper API calls.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Authentication mode for the Whisper API.
#[derive(Clone)]
pub enum WhisperAuth {
    /// API key (passed as Bearer token).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl WhisperAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for WhisperAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Whisper API client.
///
/// Sends audio transcription and translation requests to a Whisper-compatible REST API.
pub struct WhisperClient {
    client: Client,
    auth: WhisperAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for WhisperClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WhisperClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl WhisperClient {
    /// Create a new Whisper API client.
    pub fn new(auth: WhisperAuth, base_url: Option<&str>) -> WhisperResult<Self> {
        Self::new_with_timeout(auth, base_url, DEFAULT_REQUEST_TIMEOUT)
    }

    /// Create a new Whisper API client with an explicit request timeout.
    pub fn new_with_timeout(
        auth: WhisperAuth,
        base_url: Option<&str>,
        request_timeout: Duration,
    ) -> WhisperResult<Self> {
        let client = Client::builder()
            .timeout(request_timeout)
            .user_agent("fcp-whisper/0.1.0 (FCP connector)")
            .build()?;

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

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            WhisperAuth::ApiKey(key) => req.bearer_auth(key),
            WhisperAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> WhisperResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(json!({}));
            }
            let parsed: serde_json::Value = serde_json::from_str(&body)?;
            Ok(parsed)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> WhisperResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .and_then(|d| d.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(WhisperError::Auth("Invalid or expired API key".into())),
            429 => Err(WhisperError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(WhisperError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Transcribe audio to text.
    #[instrument(skip(self, body))]
    pub async fn transcribe(&self, body: serde_json::Value) -> WhisperResult<serde_json::Value> {
        let url = format!("{}/audio/transcriptions", self.base_url);
        debug!(url = %redact_url(&url), "POST transcribe");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Translate audio to English.
    #[instrument(skip(self, body))]
    pub async fn translate(&self, body: serde_json::Value) -> WhisperResult<serde_json::Value> {
        let url = format!("{}/audio/translations", self.base_url);
        debug!(url = %redact_url(&url), "POST translate");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// List available models (lightweight API check).
    #[instrument(skip(self))]
    pub async fn list_models(&self) -> WhisperResult<serde_json::Value> {
        let url = format!("{}/models", self.base_url);
        debug!(url = %redact_url(&url), "GET models");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }
}
