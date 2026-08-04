//! Google Forms API v1 client.
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

use crate::error::{FormsError, FormsResult};
use crate::types::{BatchUpdateResponse, PublishSettings, Request};

const DEFAULT_BASE_URL: &str = "https://forms.googleapis.com/v1";

/// Google Forms API client.
pub struct FormsClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    total_requests: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for FormsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormsClient")
            .field("base_url", &self.base_url)
            .field("total_requests", &self.total_requests)
            .field("auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl FormsClient {
    /// Create a new Forms client with the shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> FormsResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-forms/0.1.0")
            .build()
            .map_err(FormsError::Http)?;

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

    /// Get a form by ID.
    #[instrument(skip(self, form_id), fields(operation = "forms.get"))]
    pub async fn get_form(&self, form_id: &str) -> FormsResult<serde_json::Value> {
        let form_id = sanitize_path_segment(form_id, "form_id")?;
        let url = format!("{}/forms/{form_id}", self.base_url);
        self.get_json(&url).await
    }

    /// Create a new form.
    #[instrument(skip(self, title), fields(operation = "forms.create"))]
    pub async fn create_form(&self, title: &str) -> FormsResult<serde_json::Value> {
        let url = format!("{}/forms", self.base_url);
        let body = serde_json::json!({
            "info": { "title": title, "documentTitle": title }
        });
        self.post_json(&url, &body).await
    }

    /// Get one response. The provider payload is caller-only and never logged.
    #[instrument(
        skip(self, form_id, response_id),
        fields(operation = "forms.responses.get")
    )]
    pub async fn get_response(
        &self,
        form_id: &str,
        response_id: &str,
    ) -> FormsResult<serde_json::Value> {
        let form_id = sanitize_path_segment(form_id, "form_id")?;
        let response_id = sanitize_path_segment(response_id, "response_id")?;
        self.get_json(&format!(
            "{}/forms/{form_id}/responses/{response_id}",
            self.base_url
        ))
        .await
    }

    /// List a bounded response page with an optional timestamp filter.
    #[instrument(
        skip(self, form_id, filter, page_token),
        fields(operation = "forms.responses.list")
    )]
    pub async fn list_responses(
        &self,
        form_id: &str,
        filter: Option<&str>,
        page_size: u32,
        page_token: Option<&str>,
    ) -> FormsResult<serde_json::Value> {
        let form_id = sanitize_path_segment(form_id, "form_id")?;
        let mut url = Url::parse(&format!("{}/forms/{form_id}/responses", self.base_url)).map_err(
            |error| FormsError::Api {
                status_code: 400,
                message: error.to_string(),
            },
        )?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("pageSize", &page_size.to_string());
            if let Some(filter) = filter {
                query.append_pair("filter", filter);
            }
            if let Some(page_token) = page_token {
                query.append_pair("pageToken", page_token);
            }
        }
        self.get_json(url.as_str()).await
    }

    /// Explicitly publish/unpublish and accept/stop responses.
    #[instrument(
        skip(self, form_id, settings),
        fields(operation = "forms.set_publish_settings")
    )]
    pub async fn set_publish_settings(
        &self,
        form_id: &str,
        settings: &PublishSettings,
    ) -> FormsResult<serde_json::Value> {
        let form_id = sanitize_path_segment(form_id, "form_id")?;
        let body = serde_json::json!({
            "publishSettings": settings,
            "updateMask": "publishState"
        });
        self.post_json(
            &format!("{}/forms/{form_id}:setPublishSettings", self.base_url),
            &body,
        )
        .await
    }

    /// Apply batch updates to a form.
    #[instrument(
        skip(self, form_id, requests, required_revision_id),
        fields(operation = "forms.batch_update")
    )]
    pub async fn batch_update(
        &self,
        form_id: &str,
        requests: &[Request],
        required_revision_id: &str,
    ) -> FormsResult<BatchUpdateResponse> {
        let form_id = sanitize_path_segment(form_id, "form_id")?;
        let url = format!("{}/forms/{form_id}:batchUpdate", self.base_url);
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

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> FormsResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> FormsResult<T> {
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
    ) -> FormsResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, "forms request");

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
    ) -> FormsResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| FormsError::Api {
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
            key: format!("forms.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("forms.transport.{}", http_method.to_ascii_lowercase()),
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
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> FormsResult<&'a str> {
    if value.trim().is_empty() {
        return Err(FormsError::Api {
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
        return Err(FormsError::Api {
            status_code: 400,
            message: format!("{field} contains path traversal characters"),
        });
    }
    Ok(value)
}

/// Fuzz-only entry points for Forms client parsers.
///
/// Exposed for the Forms path-segment fuzz target so the fuzz crate can
/// exercise the private guard before form IDs enter REST URL paths.
///
/// Bead flywheel_connectors-qle2j.
#[doc(hidden)]
pub mod __fuzz {
    use super::sanitize_path_segment;

    /// Validate an arbitrary Forms URL path segment candidate.
    #[must_use]
    pub fn sanitize_path_segment_candidate(value: &str) -> bool {
        sanitize_path_segment(value, "form_id").is_ok()
    }
}

fn decode_json_response<T: DeserializeOwned>(response: GoogleExecuteResponse) -> FormsResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => serde_json::from_value(value).map_err(FormsError::Json),
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(FormsError::Json)
        }
        GoogleResponseBody::Empty => Err(FormsError::Api {
            status_code: response.status_code,
            message: "expected JSON response body".to_string(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> FormsError {
    match error {
        GoogleRestError::Http { source } => FormsError::Http(source),
        GoogleRestError::JsonDecode { source } => FormsError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(&error),
        _ => FormsError::Api {
            status_code: 500,
            message: "provider transport failure".into(),
        },
    }
}

fn map_google_api_error(error: &GoogleApiError) -> FormsError {
    match error.status_code {
        401 => FormsError::Unauthorized,
        403 => FormsError::Forbidden {
            message: "provider denied access".into(),
        },
        404 => FormsError::FormNotFound {
            form_id: "[REDACTED]".into(),
        },
        429 => FormsError::RateLimited {
            retry_after_ms: error.retry_after_ms.unwrap_or(60_000),
        },
        code => FormsError::Api {
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
        assert!(matches!(err, FormsError::Unauthorized));
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
        assert!(matches!(err, FormsError::Forbidden { .. }));
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
        assert!(matches!(err, FormsError::FormNotFound { .. }));
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
        assert!(matches!(err, FormsError::RateLimited { .. }));
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
            FormsError::Api {
                status_code: 500,
                ..
            }
        ));
        assert!(!err.to_fcp_error().to_string().contains("internal"));
    }

    #[test]
    fn auth_redacted_label_credential_ref() {
        let cred_id = fcp_core::CredentialId::new();
        let client = FormsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: cred_id,
            quota_project_id: None,
        })
        .unwrap();
        assert_eq!(client.auth_redacted_label(), "credential_reference");
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "form_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "form_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "form_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "form_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "form_id").is_err());
        assert!(sanitize_path_segment("doc?alt=media", "form_id").is_err());
        assert!(sanitize_path_segment("doc#frag", "form_id").is_err());
        assert!(sanitize_path_segment("doc%3Falt=media", "form_id").is_err());
        assert!(sanitize_path_segment("doc%23frag", "form_id").is_err());
        assert!(sanitize_path_segment("", "form_id").is_err());
        assert!(sanitize_path_segment("  ", "form_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_double_percent_encoding() {
        // br-rjok0: a server that decodes the request path twice (some
        // proxies / sidecars do) would unwrap `%252F` → `%2F` → `/`,
        // which is the very traversal the lowercase-`%2f` check is
        // meant to block. Refuse any segment carrying a literal-`%`
        // encoding so the second decode pass cannot resurrect a slash.
        assert!(sanitize_path_segment("foo%252Fbar", "form_id").is_err());
        assert!(sanitize_path_segment("foo%252fbar", "form_id").is_err());
        assert!(sanitize_path_segment("doc%2523frag", "form_id").is_err());
        assert!(sanitize_path_segment("doc%2523FRAG", "form_id").is_err());
        // A lone `%25` (literal `%` encoded) is also rejected — it has no
        // legitimate use in a Drive form/file id.
        assert!(sanitize_path_segment("foo%25", "form_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("1abc-xyz_123", "form_id").unwrap(),
            "1abc-xyz_123"
        );
    }
}
