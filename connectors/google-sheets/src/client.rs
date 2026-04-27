//! Google Sheets API v4 client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use tracing::{instrument, warn};

use crate::error::{SheetsError, SheetsResult};
use crate::types::{
    ApiErrorDetail, ApiErrorResponse, AppendValuesResponse, Spreadsheet, UpdateValuesResponse,
    ValueRange,
};

const DEFAULT_BASE_URL: &str = "https://sheets.googleapis.com/v4";

/// Google Sheets API client.
pub struct SheetsClient {
    client: Client,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl std::fmt::Debug for SheetsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SheetsClient")
            .field("base_url", &self.base_url)
            .field("total_requests", &self.total_requests)
            .field("auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl SheetsClient {
    /// Create a new Sheets client with the shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> SheetsResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-sheets/0.1.0")
            .build()
            .map_err(SheetsError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
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
            GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
                format!("credential_id:{credential_id}")
            }
        }
    }

    /// Get a spreadsheet by ID.
    #[instrument(skip(self), fields(spreadsheet_id))]
    pub async fn get_spreadsheet(&self, spreadsheet_id: &str) -> SheetsResult<Spreadsheet> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let url = format!("{}/spreadsheets/{spreadsheet_id}", self.base_url);
        self.get_json(&url).await
    }

    /// Read values from a range.
    #[instrument(skip(self), fields(spreadsheet_id, range))]
    pub async fn get_values(&self, spreadsheet_id: &str, range: &str) -> SheetsResult<ValueRange> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let encoded_range = encode_range(range);
        let url = format!(
            "{}/spreadsheets/{spreadsheet_id}/values/{encoded_range}",
            self.base_url
        );
        self.get_json(&url).await
    }

    /// Update values in a range.
    #[instrument(skip(self, values), fields(spreadsheet_id, range))]
    pub async fn update_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
        values: Vec<Vec<serde_json::Value>>,
    ) -> SheetsResult<UpdateValuesResponse> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let encoded_range = encode_range(range);
        let url = format!(
            "{}/spreadsheets/{spreadsheet_id}/values/{encoded_range}?valueInputOption=USER_ENTERED",
            self.base_url
        );
        let body = ValueRange {
            range: range.to_string(),
            major_dimension: "ROWS".to_string(),
            values,
        };
        self.put_json(&url, &body).await
    }

    /// Append values to a sheet.
    #[instrument(skip(self, values), fields(spreadsheet_id, range))]
    pub async fn append_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
        values: Vec<Vec<serde_json::Value>>,
    ) -> SheetsResult<AppendValuesResponse> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let encoded_range = encode_range(range);
        let url = format!(
            "{}/spreadsheets/{spreadsheet_id}/values/{encoded_range}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS",
            self.base_url
        );
        let body = ValueRange {
            range: range.to_string(),
            major_dimension: "ROWS".to_string(),
            values,
        };
        self.post_json(&url, &body).await
    }

    /// Clear values in a range.
    #[instrument(skip(self), fields(spreadsheet_id, range))]
    pub async fn clear_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
    ) -> SheetsResult<serde_json::Value> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let encoded_range = encode_range(range);
        let url = format!(
            "{}/spreadsheets/{spreadsheet_id}/values/{encoded_range}:clear",
            self.base_url
        );
        self.post_json::<serde_json::Value, serde_json::Value>(&url, &serde_json::json!({}))
            .await
    }

    /// Get total request count.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn apply_auth_headers(&self, mut builder: RequestBuilder) -> RequestBuilder {
        let mut headers = Vec::new();
        self.auth.apply_headers(&mut headers);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        builder
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> SheetsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .apply_auth_headers(self.client.get(url))
            .send()
            .await
            .map_err(SheetsError::Http)?;
        self.handle_response(resp).await
    }

    async fn put_json<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> SheetsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .apply_auth_headers(self.client.put(url))
            .json(body)
            .send()
            .await
            .map_err(SheetsError::Http)?;
        self.handle_response(resp).await
    }

    async fn post_json<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> SheetsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .apply_auth_headers(self.client.post(url))
            .json(body)
            .send()
            .await
            .map_err(SheetsError::Http)?;
        self.handle_response(resp).await
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> SheetsResult<T> {
        let status = resp.status();
        if status.is_success() {
            return resp.json().await.map_err(SheetsError::Http);
        }
        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&body) {
            Err(map_api_error(api_err.error))
        } else {
            let preview: String = body.chars().take(200).collect();
            warn!(status = code, body_preview = %preview, "Sheets API error");
            Err(SheetsError::Api {
                status_code: code,
                message: body,
            })
        }
    }
}

fn map_api_error(error: ApiErrorDetail) -> SheetsError {
    match error.code {
        401 => SheetsError::Unauthorized,
        403 => SheetsError::Forbidden {
            message: error.message,
        },
        404 => SheetsError::SpreadsheetNotFound {
            spreadsheet_id: error.message,
        },
        429 => SheetsError::RateLimited {
            retry_after_ms: 60_000,
        },
        code => SheetsError::Api {
            status_code: code,
            message: error.message,
        },
    }
}

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path/query separators, traversal sequences (`..`),
/// and percent-encoded variants.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> SheetsResult<&'a str> {
    if value.trim().is_empty() {
        return Err(SheetsError::Api {
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
    {
        return Err(SheetsError::Api {
            status_code: 400,
            message: format!("{field} contains path traversal characters"),
        });
    }
    Ok(value)
}

/// Percent-encode a Sheets range expression for use in a URL path segment.
///
/// Uses `percent_encoding::NON_ALPHANUMERIC` which encodes all non-alphanumeric
/// characters. This is a proper superset of the 3 characters the old custom
/// `urlencoded()` handled and covers all edge cases.
fn encode_range(range: &str) -> String {
    percent_encoding::utf8_percent_encode(range, percent_encoding::NON_ALPHANUMERIC).to_string()
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
    fn encode_range_basic() {
        let encoded = encode_range("Sheet1!A1:B2");
        assert!(encoded.contains("%21")); // '!' encoded
        assert!(encoded.contains("%3A")); // ':' encoded
        assert!(encoded.contains("Sheet1"));
        assert!(encoded.contains("A1"));
        assert!(encoded.contains("B2"));
    }

    #[test]
    fn encode_range_spaces() {
        let encoded = encode_range("My Sheet!A1");
        assert!(encoded.contains("%20")); // space encoded
        assert!(encoded.contains("%21")); // '!' encoded
    }

    #[test]
    fn encode_range_handles_slash() {
        let encoded = encode_range("Sheet/1!A1");
        assert!(encoded.contains("%2F")); // '/' encoded, not left bare
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet?alt=media", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet#frag", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet%3Falt=media", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet%23frag", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("  ", "spreadsheet_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("abc123", "spreadsheet_id").unwrap(),
            "abc123"
        );
        assert_eq!(
            sanitize_path_segment(
                "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms",
                "spreadsheet_id"
            )
            .unwrap(),
            "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"
        );
    }

    #[test]
    fn map_api_error_401() {
        let err = map_api_error(ApiErrorDetail {
            code: 401,
            message: "bad token".into(),
        });
        assert!(matches!(err, SheetsError::Unauthorized));
    }

    #[test]
    fn map_api_error_403() {
        let err = map_api_error(ApiErrorDetail {
            code: 403,
            message: "forbidden".into(),
        });
        assert!(matches!(err, SheetsError::Forbidden { .. }));
    }

    #[test]
    fn map_api_error_404() {
        let err = map_api_error(ApiErrorDetail {
            code: 404,
            message: "not found".into(),
        });
        assert!(matches!(err, SheetsError::SpreadsheetNotFound { .. }));
    }

    #[test]
    fn map_api_error_429() {
        let err = map_api_error(ApiErrorDetail {
            code: 429,
            message: "rate limited".into(),
        });
        assert!(matches!(err, SheetsError::RateLimited { .. }));
    }

    #[test]
    fn map_api_error_500() {
        let err = map_api_error(ApiErrorDetail {
            code: 500,
            message: "internal".into(),
        });
        assert!(matches!(
            err,
            SheetsError::Api {
                status_code: 500,
                ..
            }
        ));
    }

    #[test]
    fn auth_redacted_label_credential_ref() {
        let cred_id = fcp_core::CredentialId::new();
        let label = format!("credential_id:{cred_id}");
        let client = SheetsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: cred_id,
            quota_project_id: None,
        })
        .unwrap();
        assert_eq!(client.auth_redacted_label(), label);
    }

    #[test]
    fn bearer_token_requests_use_authorization_header() {
        run_async_test(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v4/spreadsheets/sheet123"))
                .and(header(GOOGLE_AUTHORIZATION_HEADER, "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "spreadsheetId": "sheet123",
                    "properties": { "title": "Auth Header" },
                    "sheets": [],
                    "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/sheet123"
                })))
                .mount(&server)
                .await;

            let client = SheetsClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
                access_token: "test-token".into(),
                source: GoogleAuthSourceKind::AccessToken,
                granted_scopes: Vec::new(),
                quota_project_id: None,
            })
            .unwrap()
            .with_base_url(format!("{}/v4", server.uri()));

            let spreadsheet = client.get_spreadsheet("sheet123").await.unwrap();
            assert_eq!(spreadsheet.spreadsheet_id, "sheet123");
        });
    }

    #[test]
    fn credential_reference_requests_use_fcp_credential_header() {
        run_async_test(async {
            let server = MockServer::start().await;
            let credential_id = fcp_core::CredentialId::new();
            Mock::given(method("GET"))
                .and(path("/v4/spreadsheets/sheet123"))
                .and(header(FCP_CREDENTIAL_ID_HEADER, credential_id.to_string()))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "spreadsheetId": "sheet123",
                    "properties": { "title": "Credential Header" },
                    "sheets": [],
                    "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/sheet123"
                })))
                .mount(&server)
                .await;

            let client = SheetsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
                credential_id,
                quota_project_id: None,
            })
            .unwrap()
            .with_base_url(format!("{}/v4", server.uri()));

            let spreadsheet = client.get_spreadsheet("sheet123").await.unwrap();
            assert_eq!(spreadsheet.spreadsheet_id, "sheet123");
        });
    }
}
