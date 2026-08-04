//! Google Slides API v1 client.
//!
//! Uses `fcp-google-discovery` shared auth substrate and retry infrastructure.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor,
};
use fcp_google_discovery::{DiscoveryMethod, DiscoveryParameter};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Url, header};
use serde::de::DeserializeOwned;
use tracing::{debug, instrument};

use crate::error::{SlidesError, SlidesResult};
use crate::types::{BatchUpdateResponse, Request};

const DEFAULT_BASE_URL: &str = "https://slides.googleapis.com/v1";

/// Google Slides API client.
pub struct SlidesClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    total_requests: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for SlidesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlidesClient")
            .field("base_url", &self.base_url)
            .field("total_requests", &self.total_requests)
            .field("auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl SlidesClient {
    /// Create a new Slides client with the shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> SlidesResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-slides/0.1.0")
            .build()
            .map_err(SlidesError::Http)?;

        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(client),
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            total_requests: AtomicU64::new(0),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                initial_delay_ms: 500,
                max_delay_ms: 30_000,
                jitter_enabled: true,
            },
        })
    }

    /// Override the API base URL, primarily for deterministic tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
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
            GoogleMaterializedAuth::CredentialReference { .. } => "credential_reference".into(),
        }
    }

    /// Get a presentation by ID.
    #[instrument(skip(self, presentation_id), fields(operation = "slides.get"))]
    pub async fn get_presentation(&self, presentation_id: &str) -> SlidesResult<serde_json::Value> {
        let presentation_id = sanitize_path_segment(presentation_id, "presentation_id")?;
        let url = format!("{}/presentations/{presentation_id}", self.base_url);
        self.get_json(&url).await
    }

    /// Get one slide, notes page, master, or layout by object ID.
    #[instrument(
        skip(self, presentation_id, page_object_id),
        fields(operation = "slides.pages.get")
    )]
    pub async fn get_page(
        &self,
        presentation_id: &str,
        page_object_id: &str,
    ) -> SlidesResult<serde_json::Value> {
        let presentation_id = sanitize_path_segment(presentation_id, "presentation_id")?;
        let page_object_id = sanitize_path_segment(page_object_id, "page_object_id")?;
        let url = format!(
            "{}/presentations/{presentation_id}/pages/{page_object_id}",
            self.base_url
        );
        self.get_json(&url).await
    }

    /// Get bounded thumbnail metadata. The returned content URL is caller-only
    /// transient data and must never be logged.
    #[instrument(
        skip(self, presentation_id, page_object_id),
        fields(operation = "slides.pages.get_thumbnail")
    )]
    pub async fn get_thumbnail(
        &self,
        presentation_id: &str,
        page_object_id: &str,
        size: &str,
    ) -> SlidesResult<serde_json::Value> {
        let presentation_id = sanitize_path_segment(presentation_id, "presentation_id")?;
        let page_object_id = sanitize_path_segment(page_object_id, "page_object_id")?;
        let url = format!(
            "{}/presentations/{presentation_id}/pages/{page_object_id}/thumbnail?thumbnailProperties.mimeType=PNG&thumbnailProperties.thumbnailSize={size}",
            self.base_url
        );
        self.get_json(&url).await
    }

    /// Create a new presentation.
    #[instrument(skip(self, title), fields(operation = "slides.create"))]
    pub async fn create_presentation(&self, title: &str) -> SlidesResult<serde_json::Value> {
        let url = format!("{}/presentations", self.base_url);
        let body = serde_json::json!({ "title": title });
        self.post_json(&url, &body).await
    }

    /// Apply batch updates to a presentation.
    #[instrument(
        skip(self, presentation_id, requests, required_revision_id),
        fields(operation = "slides.batch_update")
    )]
    pub async fn batch_update(
        &self,
        presentation_id: &str,
        requests: &[Request],
        required_revision_id: &str,
    ) -> SlidesResult<BatchUpdateResponse> {
        let presentation_id = sanitize_path_segment(presentation_id, "presentation_id")?;
        let url = format!(
            "{}/presentations/{presentation_id}:batchUpdate",
            self.base_url
        );
        let body = serde_json::json!({
            "requests": requests,
            "writeControl": { "requiredRevisionId": required_revision_id },
        });
        self.post_json(&url, &body).await
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

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> SlidesResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> SlidesResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json, false)
            .await?;
        decode_json_response(response)
    }

    /// Execute with retry.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). It is a parameter rather than a function of
    /// `http_method` because Google models several state changes — and some
    /// pure reads — as POSTs, so the verb alone decides nothing.
    async fn execute_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
        replay_safe: bool,
    ) -> SlidesResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, "slides request");

            match self
                .execute_once(http_method, url, body, response_mode)
                .await
            {
                Ok(response) => AttemptOutcome::Success(response),
                Err(error) if error.is_retryable() => {
                    // A rate limit was refused WITHOUT performing the work, so
                    // it stays retryable; a 5xx means Google received the
                    // request and may already have done it.
                    let replayable = replay_safe || error.replay_is_safe();
                    let retry_after = error.retry_after();
                    AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                }
                Err(error) => AttemptOutcome::Terminal(error),
            }
        })
        .await
    }

    async fn execute_once(
        &self,
        http_method: &'static str,
        raw_url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
    ) -> SlidesResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| SlidesError::Api {
            status_code: 400,
            message: format!("invalid request url: {error}"),
        })?;

        let mut parameters: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, value) in parsed_url.query_pairs() {
            parameters
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }

        let method_parameters = parameters
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    DiscoveryParameter {
                        location: Some("query".to_string()),
                        required: false,
                        repeated: true,
                        type_name: Some("string".to_string()),
                        format: None,
                        description: None,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let path = parsed_url.path().trim_start_matches('/').to_string();
        let method = DiscoveryMethod {
            key: format!("slides.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("slides.transport.{}", http_method.to_ascii_lowercase()),
            http_method: http_method.to_string(),
            path: path.clone(),
            flat_path: None,
            canonical_path: path,
            resource_path: Vec::new(),
            description: None,
            scopes: Vec::new(),
            request_ref: None,
            response_ref: None,
            parameters: method_parameters,
            supports_media_download: false,
            supports_media_upload: false,
            media_upload: None,
        };

        let schemas = BTreeMap::new();
        let mut base_url = parsed_url.origin().ascii_serialization();
        if !base_url.ends_with('/') {
            base_url.push('/');
        }

        let mut request = GoogleExecuteRequest::new(&method, &schemas, &base_url);
        request.parameters = parameters;
        request.body = body.cloned();
        request.response_mode = response_mode;
        request.auth = Some(&self.auth);

        self.executor
            .execute(&request)
            .await
            .map_err(map_rest_error)
    }
}

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path/query separators, traversal sequences (`..`),
/// and percent-encoded variants.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> SlidesResult<&'a str> {
    if value.trim().is_empty() {
        return Err(SlidesError::Api {
            status_code: 400,
            message: format!("{field} must not be empty"),
        });
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%25")
    {
        return Err(SlidesError::Api {
            status_code: 400,
            message: format!("{field} contains path traversal characters"),
        });
    }
    Ok(value)
}

/// Fuzz-only entry points for Slides client parsers.
///
/// Exposed for the Slides path-segment fuzz target so the fuzz crate can
/// exercise the private guard before presentation IDs enter REST URL paths.
///
/// Bead flywheel_connectors-qle2j.
#[doc(hidden)]
pub mod __fuzz {
    use super::sanitize_path_segment;

    /// Validate an arbitrary Slides URL path segment candidate.
    #[must_use]
    pub fn sanitize_path_segment_candidate(value: &str) -> bool {
        sanitize_path_segment(value, "presentation_id").is_ok()
    }
}

fn decode_json_response<T: DeserializeOwned>(response: GoogleExecuteResponse) -> SlidesResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => serde_json::from_value(value).map_err(SlidesError::Json),
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(SlidesError::Json)
        }
        GoogleResponseBody::Empty => Err(SlidesError::Api {
            status_code: response.status_code,
            message: "expected JSON response body".to_string(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> SlidesError {
    match error {
        GoogleRestError::Http { source } => SlidesError::Http(source),
        GoogleRestError::JsonDecode { source } => SlidesError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(&error),
        _ => SlidesError::Api {
            status_code: 500,
            message: "provider transport failure".into(),
        },
    }
}

fn map_google_api_error(error: &GoogleApiError) -> SlidesError {
    match error.status_code {
        401 => SlidesError::Unauthorized,
        403 => SlidesError::Forbidden {
            message: "provider denied access".into(),
        },
        404 => SlidesError::PresentationNotFound {
            presentation_id: "[REDACTED]".into(),
        },
        429 => SlidesError::RateLimited {
            retry_after_ms: error.retry_after_ms.unwrap_or(60_000),
        },
        code => SlidesError::Api {
            status_code: code,
            message: "provider rejected request".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_google_api_error_401() {
        let err = map_google_api_error(&GoogleApiError {
            status_code: 401,
            message: "bad token".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(err, SlidesError::Unauthorized));
    }

    #[test]
    fn map_google_api_error_403() {
        let err = map_google_api_error(&GoogleApiError {
            status_code: 403,
            message: "forbidden".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(err, SlidesError::Forbidden { .. }));
    }

    #[test]
    fn map_google_api_error_404() {
        let err = map_google_api_error(&GoogleApiError {
            status_code: 404,
            message: "not found".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(err, SlidesError::PresentationNotFound { .. }));
    }

    #[test]
    fn map_google_api_error_429() {
        let err = map_google_api_error(&GoogleApiError {
            status_code: 429,
            message: "rate limited".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(err, SlidesError::RateLimited { .. }));
    }

    #[test]
    fn map_google_api_error_500() {
        let err = map_google_api_error(&GoogleApiError {
            status_code: 500,
            message: "internal".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(
            &err,
            SlidesError::Api {
                status_code: 500,
                ..
            }
        ));
        assert!(!err.to_fcp_error().to_string().contains("internal"));
    }

    #[test]
    fn auth_redacted_label_credential_ref() {
        let cred_id = fcp_core::CredentialId::new();
        let client = SlidesClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: cred_id,
            quota_project_id: None,
        })
        .unwrap();
        assert_eq!(client.auth_redacted_label(), "credential_reference");
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "presentation_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "presentation_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "presentation_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "presentation_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "presentation_id").is_err());
        assert!(sanitize_path_segment("doc?alt=media", "presentation_id").is_err());
        assert!(sanitize_path_segment("doc#frag", "presentation_id").is_err());
        assert!(sanitize_path_segment("doc%3Falt=media", "presentation_id").is_err());
        assert!(sanitize_path_segment("doc%23frag", "presentation_id").is_err());
        assert!(sanitize_path_segment("", "presentation_id").is_err());
        assert!(sanitize_path_segment("  ", "presentation_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_double_percent_encoding() {
        // br-rjok0: a server that decodes the request path twice (some
        // proxies / sidecars do) would unwrap `%252F` → `%2F` → `/`,
        // which is the very traversal the lowercase-`%2f` check is
        // meant to block. Refuse any segment carrying a literal-`%`
        // encoding so the second decode pass cannot resurrect a slash.
        assert!(sanitize_path_segment("foo%252Fbar", "presentation_id").is_err());
        assert!(sanitize_path_segment("foo%252fbar", "presentation_id").is_err());
        assert!(sanitize_path_segment("doc%2523frag", "presentation_id").is_err());
        assert!(sanitize_path_segment("doc%2523FRAG", "presentation_id").is_err());
        // A lone `%25` (literal `%` encoded) is also rejected — it has no
        // legitimate use in a Drive presentation/file id.
        assert!(sanitize_path_segment("foo%25", "presentation_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("1abc-xyz_123", "presentation_id").unwrap(),
            "1abc-xyz_123"
        );
    }
}
