//! Google Sheets API v4 client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use reqwest::Client;
use serde::de::DeserializeOwned;
use tracing::{instrument, warn};

use crate::error::{SheetsError, SheetsResult};
use crate::types::{
    ApiErrorDetail, ApiErrorResponse, AppendValuesResponse, Spreadsheet, UpdateValuesResponse,
    ValueRange,
};

const DEFAULT_BASE_URL: &str = "https://sheets.googleapis.com/v4";

/// Google Sheets API client.
#[derive(Debug)]
pub struct SheetsClient {
    client: Client,
    auth: GoogleMaterializedAuth,
    base_url: String,
    total_requests: AtomicU64,
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

    /// Get a spreadsheet by ID.
    #[instrument(skip(self), fields(spreadsheet_id))]
    pub async fn get_spreadsheet(&self, spreadsheet_id: &str) -> SheetsResult<Spreadsheet> {
        let url = format!("{}/spreadsheets/{spreadsheet_id}", self.base_url);
        self.get_json(&url).await
    }

    /// Read values from a range.
    #[instrument(skip(self), fields(spreadsheet_id, range))]
    pub async fn get_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
    ) -> SheetsResult<ValueRange> {
        let encoded_range = urlencoded(range);
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
        let encoded_range = urlencoded(range);
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
        let encoded_range = urlencoded(range);
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
        let encoded_range = urlencoded(range);
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

    fn bearer_token(&self) -> Option<&str> {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { access_token, .. } => Some(access_token),
            GoogleMaterializedAuth::CredentialReference { .. } => None,
        }
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> SheetsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let token = self.bearer_token().ok_or(SheetsError::Unauthorized)?;
        let resp = self
            .client
            .get(url)
            .bearer_auth(token)
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
        let token = self.bearer_token().ok_or(SheetsError::Unauthorized)?;
        let resp = self
            .client
            .put(url)
            .bearer_auth(token)
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
        let token = self.bearer_token().ok_or(SheetsError::Unauthorized)?;
        let resp = self
            .client
            .post(url)
            .bearer_auth(token)
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

fn urlencoded(s: &str) -> String {
    s.replace(' ', "%20")
        .replace('!', "%21")
        .replace(':', "%3A")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoded_basic() {
        assert_eq!(urlencoded("Sheet1!A1:B2"), "Sheet1%21A1%3AB2");
    }

    #[test]
    fn urlencoded_spaces() {
        assert_eq!(urlencoded("My Sheet!A1"), "My%20Sheet%21A1");
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
        assert!(matches!(err, SheetsError::Api { status_code: 500, .. }));
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
}
