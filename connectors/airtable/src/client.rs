//! Airtable REST API client.

use std::fmt;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{instrument, warn};

use crate::{
    error::{AirtableError, AirtableResult},
    types::{
        AirtableApiError, AttachmentDownload, BaseSchemaResponse, CreateRecordsResponse,
        DeleteRecordResponse, ListBasesResponse, ListRecordsResponse, Record, SortSpec,
    },
};

/// Default Airtable API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.airtable.com/v0";

/// Authentication mode for the Airtable API.
#[derive(Clone)]
pub enum AirtableAuth {
    /// Direct `OAuth2` / personal access token (bearer auth).
    Token(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl AirtableAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::Token(_) => "token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for AirtableAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Airtable REST API client with retry logic and rate limit awareness.
pub struct AirtableClient {
    client: Client,
    auth: AirtableAuth,
    base_url: String,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    total_requests: AtomicU64,
}

impl fmt::Debug for AirtableClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AirtableClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl AirtableClient {
    /// Create a new Airtable client with a personal access token.
    pub fn new(token: impl Into<String>) -> AirtableResult<Self> {
        Self::new_with_auth(AirtableAuth::Token(token.into()))
    }

    /// Create a new Airtable client with explicit auth mode.
    pub fn new_with_auth(auth: AirtableAuth) -> AirtableResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-airtable/0.1.0")
            .build()
            .map_err(AirtableError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
            total_requests: AtomicU64::new(0),
        })
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub const fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.max_retries = max_retries;
        self.initial_delay_ms = initial_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Apply authentication to an outgoing request.
    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            AirtableAuth::Token(token) => builder.bearer_auth(token),
            AirtableAuth::CredentialId(id) => builder.header("X-FCP-Credential-ID", id.to_string()),
        }
    }

    /// Lightweight connectivity probe (list bases with no offset).
    pub async fn health_check(&self) -> AirtableResult<()> {
        let _: ListBasesResponse = self.get_with_params("/meta/bases", &[]).await?;
        Ok(())
    }

    // ── Base operations ─────────────────────────────────────────────

    /// List all accessible bases.
    #[instrument(skip(self))]
    pub async fn list_bases(&self, offset: Option<&str>) -> AirtableResult<ListBasesResponse> {
        let mut params: Vec<(&str, String)> = vec![];
        if let Some(o) = offset {
            params.push(("offset", o.to_string()));
        }
        self.get_with_params("/meta/bases", &params).await
    }

    /// Get the schema of a base.
    #[instrument(skip(self))]
    pub async fn get_base_schema(&self, base_id: &str) -> AirtableResult<BaseSchemaResponse> {
        let path = format!("/meta/bases/{base_id}/tables");
        self.get_with_params(&path, &[]).await
    }

    // ── Record operations ───────────────────────────────────────────

    /// List records from a table.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list_records(
        &self,
        base_id: &str,
        table_id: &str,
        fields: Option<&[String]>,
        filter_by_formula: Option<&str>,
        max_records: Option<u32>,
        page_size: Option<u32>,
        sort: Option<&[SortSpec]>,
        view: Option<&str>,
        offset: Option<&str>,
    ) -> AirtableResult<ListRecordsResponse> {
        let path = format!("/{base_id}/{table_id}");

        // Build URL manually since sort params need dynamic keys
        let mut url = format!("{}{path}", self.base_url);
        let mut first = true;

        let mut append_param = |url: &mut String, key: &str, value: &str| {
            if first {
                url.push('?');
                first = false;
            } else {
                url.push('&');
            }
            let encoded =
                percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC);
            let _ = write!(url, "{key}={encoded}");
        };

        if let Some(fields) = fields {
            for f in fields {
                append_param(&mut url, "fields[]", f);
            }
        }
        if let Some(formula) = filter_by_formula {
            append_param(&mut url, "filterByFormula", formula);
        }
        if let Some(max) = max_records {
            append_param(&mut url, "maxRecords", &max.to_string());
        }
        if let Some(ps) = page_size {
            append_param(&mut url, "pageSize", &ps.to_string());
        }
        if let Some(sort) = sort {
            for (i, s) in sort.iter().enumerate() {
                let field_key = format!("sort[{i}][field]");
                let dir_key = format!("sort[{i}][direction]");
                append_param(&mut url, &field_key, &s.field);
                append_param(&mut url, &dir_key, &s.direction);
            }
        }
        if let Some(v) = view {
            append_param(&mut url, "view", v);
        }
        if let Some(o) = offset {
            append_param(&mut url, "offset", o);
        }

        self.get_raw_url(&url).await
    }

    /// Get a single record by ID.
    #[instrument(skip(self))]
    pub async fn get_record(
        &self,
        base_id: &str,
        table_id: &str,
        record_id: &str,
    ) -> AirtableResult<Record> {
        let path = format!("/{base_id}/{table_id}/{record_id}");
        self.get_with_params(&path, &[]).await
    }

    /// Create a single record.
    #[instrument(skip(self, fields))]
    pub async fn create_record(
        &self,
        base_id: &str,
        table_id: &str,
        fields: &serde_json::Value,
        typecast: Option<bool>,
    ) -> AirtableResult<Record> {
        let path = format!("/{base_id}/{table_id}");
        let mut body = serde_json::json!({ "fields": fields });
        if let Some(tc) = typecast {
            body["typecast"] = serde_json::Value::Bool(tc);
        }
        self.post_json(&path, &body).await
    }

    /// Create multiple records (batch, max 10).
    #[instrument(skip(self, records))]
    pub async fn create_records(
        &self,
        base_id: &str,
        table_id: &str,
        records: &[serde_json::Value],
        typecast: Option<bool>,
    ) -> AirtableResult<CreateRecordsResponse> {
        let path = format!("/{base_id}/{table_id}");
        let mut body = serde_json::json!({ "records": records });
        if let Some(tc) = typecast {
            body["typecast"] = serde_json::Value::Bool(tc);
        }
        self.post_json(&path, &body).await
    }

    /// Update a record (PATCH - partial update).
    #[instrument(skip(self, fields))]
    pub async fn update_record(
        &self,
        base_id: &str,
        table_id: &str,
        record_id: &str,
        fields: &serde_json::Value,
        typecast: Option<bool>,
    ) -> AirtableResult<Record> {
        let path = format!("/{base_id}/{table_id}/{record_id}");
        let mut body = serde_json::json!({ "fields": fields });
        if let Some(tc) = typecast {
            body["typecast"] = serde_json::Value::Bool(tc);
        }
        self.patch_json(&path, &body).await
    }

    /// Replace a record (PUT - full replacement).
    #[instrument(skip(self, fields))]
    pub async fn replace_record(
        &self,
        base_id: &str,
        table_id: &str,
        record_id: &str,
        fields: &serde_json::Value,
    ) -> AirtableResult<Record> {
        let path = format!("/{base_id}/{table_id}/{record_id}");
        let body = serde_json::json!({ "fields": fields });
        self.put_json(&path, &body).await
    }

    /// Delete a record.
    #[instrument(skip(self))]
    pub async fn delete_record(
        &self,
        base_id: &str,
        table_id: &str,
        record_id: &str,
    ) -> AirtableResult<DeleteRecordResponse> {
        let path = format!("/{base_id}/{table_id}/{record_id}");
        self.delete(&path).await
    }

    // ── Attachment operations ───────────────────────────────────────

    /// Download an attachment from a URL.
    #[instrument(skip(self))]
    pub async fn download_attachment(&self, url: &str) -> AirtableResult<AttachmentDownload> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(AirtableError::Http)?;

        let status = response.status();
        if !status.is_success() {
            return Err(AirtableError::Api {
                error_type: "DOWNLOAD_ERROR".into(),
                message: format!("Attachment download failed with status {status}"),
                status_code: Some(status.as_u16()),
            });
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        // Try to extract filename from content-disposition header
        let filename = response
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split("filename=")
                    .nth(1)
                    .map(|f| f.trim_matches('"').to_string())
            });

        let bytes = response.bytes().await.map_err(AirtableError::Http)?;
        let data = base64::engine::general_purpose::STANDARD.encode(&bytes);

        Ok(AttachmentDownload {
            data,
            content_type,
            filename,
        })
    }

    // ── Internal HTTP helpers ────────────────────────────────────────

    async fn get_raw_url<T: serde::de::DeserializeOwned>(&self, url: &str) -> AirtableResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self.apply_auth(self.client.get(url)).send().await;

            match response {
                Ok(resp) => {
                    if let Some(retry_result) = Self::check_rate_limit(&resp) {
                        if attempt <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(url, attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(AirtableError::RateLimited {
                            retry_after_secs: retry_result.map_or(30, |d| d.as_secs()),
                        });
                    }
                    let status = resp.status();
                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(AirtableError::Unauthorized);
                    }
                    if !status.is_success() {
                        return Err(Self::parse_error_response(resp).await);
                    }
                    return resp.json::<T>().await.map_err(Into::into);
                }
                Err(e) if e.is_timeout() && attempt <= self.max_retries => {
                    warn!(url, attempt, "Request timed out, retrying in {delay:?}");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> AirtableResult<T> {
        let mut url = format!("{}{path}", self.base_url);
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self.apply_auth(self.client.get(&url)).send().await;

            match response {
                Ok(resp) => {
                    if let Some(retry_result) = Self::check_rate_limit(&resp) {
                        if attempt <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(path, attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(AirtableError::RateLimited {
                            retry_after_secs: retry_result.map_or(30, |d| d.as_secs()),
                        });
                    }
                    let status = resp.status();
                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(AirtableError::Unauthorized);
                    }
                    if !status.is_success() {
                        return Err(Self::parse_error_response(resp).await);
                    }
                    return resp.json::<T>().await.map_err(Into::into);
                }
                Err(e) if e.is_timeout() && attempt <= self.max_retries => {
                    warn!(path, attempt, "Request timed out, retrying in {delay:?}");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> AirtableResult<T> {
        self.request_with_body(reqwest::Method::POST, path, body)
            .await
    }

    async fn patch_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> AirtableResult<T> {
        self.request_with_body(reqwest::Method::PATCH, path, body)
            .await
    }

    async fn put_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> AirtableResult<T> {
        self.request_with_body(reqwest::Method::PUT, path, body)
            .await
    }

    async fn delete<T: serde::de::DeserializeOwned>(&self, path: &str) -> AirtableResult<T> {
        let url = format!("{}{path}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self.apply_auth(self.client.delete(&url)).send().await;

            match response {
                Ok(resp) => {
                    if let Some(retry_result) = Self::check_rate_limit(&resp) {
                        if attempt <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(path, attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(AirtableError::RateLimited {
                            retry_after_secs: retry_result.map_or(30, |d| d.as_secs()),
                        });
                    }
                    let status = resp.status();
                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(AirtableError::Unauthorized);
                    }
                    if !status.is_success() {
                        return Err(Self::parse_error_response(resp).await);
                    }
                    return resp.json::<T>().await.map_err(Into::into);
                }
                Err(e) if e.is_timeout() && attempt <= self.max_retries => {
                    warn!(path, attempt, "Request timed out, retrying in {delay:?}");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn request_with_body<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &serde_json::Value,
    ) -> AirtableResult<T> {
        let url = format!("{}{path}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut attempt = 0;
        let mut delay = Duration::from_millis(self.initial_delay_ms);

        loop {
            attempt += 1;
            let response = self
                .apply_auth(self.client.request(method.clone(), &url))
                .json(body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if let Some(retry_result) = Self::check_rate_limit(&resp) {
                        if attempt <= self.max_retries {
                            let wait = retry_result.unwrap_or(delay);
                            warn!(path, attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(AirtableError::RateLimited {
                            retry_after_secs: retry_result.map_or(30, |d| d.as_secs()),
                        });
                    }
                    let status = resp.status();
                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(AirtableError::Unauthorized);
                    }
                    if !status.is_success() {
                        return Err(Self::parse_error_response(resp).await);
                    }
                    return resp.json::<T>().await.map_err(Into::into);
                }
                Err(e) if e.is_timeout() && attempt <= self.max_retries => {
                    warn!(path, attempt, "Request timed out, retrying in {delay:?}");
                    fcp_async_core::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(self.max_delay_ms));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &Response) -> Option<Option<Duration>> {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }

    async fn parse_error_response(resp: Response) -> AirtableError {
        let status_code = resp.status().as_u16();
        match resp.json::<AirtableApiError>().await {
            Ok(api_err) => {
                let error_type = api_err
                    .error
                    .as_ref()
                    .and_then(|e| e.error_type.clone())
                    .unwrap_or_else(|| "UNKNOWN_ERROR".into());
                let message = api_err
                    .error
                    .as_ref()
                    .and_then(|e| e.message.clone())
                    .unwrap_or_else(|| format!("HTTP {status_code}"));
                AirtableError::Api {
                    error_type,
                    message,
                    status_code: Some(status_code),
                }
            }
            Err(_) => AirtableError::Api {
                error_type: "UNKNOWN_ERROR".into(),
                message: format!("HTTP {status_code}"),
                status_code: Some(status_code),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{bearer_token, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[fcp_async_core::runtime::test]
    async fn test_list_bases() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/meta/bases"))
            .and(bearer_token("test_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "bases": [
                    { "id": "appTest123", "name": "My Base", "permissionLevel": "create" }
                ]
            })))
            .mount(&server)
            .await;

        let client = AirtableClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());
        let result = client.list_bases(None).await.unwrap();
        assert_eq!(result.bases.len(), 1);
        assert_eq!(result.bases[0].id, "appTest123");
        assert_eq!(result.bases[0].name, "My Base");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_record() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/appABC/tblXYZ/recDEF"))
            .and(bearer_token("test_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "recDEF",
                "fields": { "Name": "Test Record", "Status": "Active" },
                "createdTime": "2025-01-01T00:00:00.000Z"
            })))
            .mount(&server)
            .await;

        let client = AirtableClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());
        let record = client
            .get_record("appABC", "tblXYZ", "recDEF")
            .await
            .unwrap();
        assert_eq!(record.id, "recDEF");
        assert_eq!(record.fields["Name"], "Test Record");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_record() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/appABC/tblXYZ"))
            .and(bearer_token("test_token"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "recNEW",
                "fields": { "Name": "New Record" },
                "createdTime": "2025-01-02T00:00:00.000Z"
            })))
            .mount(&server)
            .await;

        let client = AirtableClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());
        let fields = serde_json::json!({ "Name": "New Record" });
        let record = client
            .create_record("appABC", "tblXYZ", &fields, None)
            .await
            .unwrap();
        assert_eq!(record.id, "recNEW");
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_record() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/appABC/tblXYZ/recDEL"))
            .and(bearer_token("test_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "recDEL",
                "deleted": true
            })))
            .mount(&server)
            .await;

        let client = AirtableClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());
        let result = client
            .delete_record("appABC", "tblXYZ", "recDEL")
            .await
            .unwrap();
        assert!(result.deleted);
        assert_eq!(result.id, "recDEL");
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/meta/bases"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": { "type": "AUTHENTICATION_REQUIRED", "message": "Invalid API key" }
            })))
            .mount(&server)
            .await;

        let client = AirtableClient::new("bad_token")
            .unwrap()
            .with_base_url(server.uri());
        let result = client.list_bases(None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AirtableError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limit_no_retry() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/meta/bases"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&server)
            .await;

        let client = AirtableClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(0, 100, 100);
        let result = client.list_bases(None).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AirtableError::RateLimited {
                retry_after_secs: 30
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_record() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/appABC/tblXYZ/recUPD"))
            .and(bearer_token("test_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "recUPD",
                "fields": { "Status": "Done" },
                "createdTime": "2025-01-01T00:00:00.000Z"
            })))
            .mount(&server)
            .await;

        let client = AirtableClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());
        let fields = serde_json::json!({ "Status": "Done" });
        let record = client
            .update_record("appABC", "tblXYZ", "recUPD", &fields, None)
            .await
            .unwrap();
        assert_eq!(record.id, "recUPD");
        assert_eq!(record.fields["Status"], "Done");
    }

    #[fcp_async_core::runtime::test]
    async fn test_api_error_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/appABC/tblXYZ/recBAD"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": {
                    "type": "NOT_FOUND",
                    "message": "Could not find record"
                }
            })))
            .mount(&server)
            .await;

        let client = AirtableClient::new("test_token")
            .unwrap()
            .with_base_url(server.uri());
        let result = client.get_record("appABC", "tblXYZ", "recBAD").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AirtableError::Api {
                error_type,
                message,
                status_code,
            } => {
                assert_eq!(error_type, "NOT_FOUND");
                assert!(message.contains("Could not find record"));
                assert_eq!(status_code, Some(404));
            }
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }

    // ── Auth unit tests ──────────────────────────────────────────

    #[test]
    fn auth_token_debug_redacts() {
        let auth = AirtableAuth::Token("super-secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_credential_id_debug_shows_id() {
        let id = CredentialId::new();
        let auth = AirtableAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains(&id.to_string()));
    }

    #[test]
    fn auth_token_redacted_label() {
        let auth = AirtableAuth::Token("my-token".into());
        assert_eq!(auth.redacted_label(), "token:redacted");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let id = CredentialId::new();
        let auth = AirtableAuth::CredentialId(id);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
        assert!(label.contains(&id.to_string()));
    }

    #[test]
    fn auth_token_is_not_secretless() {
        let auth = AirtableAuth::Token("tok".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = AirtableAuth::CredentialId(CredentialId::new());
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_clone() {
        let auth = AirtableAuth::Token("test".into());
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert_eq!(auth2.redacted_label(), "token:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let id = CredentialId::new();
        let auth = AirtableAuth::CredentialId(id);
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert!(auth2.is_secretless());
        assert_eq!(auth2.redacted_label(), auth.redacted_label());
    }

    // ── Client construction tests ────────────────────────────────

    #[test]
    fn client_new_creates_with_defaults() {
        let client = AirtableClient::new("test_token").unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
        assert_eq!(client.max_retries, 3);
        assert_eq!(client.total_requests(), 0);
    }

    #[test]
    fn client_with_base_url() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_base_url("https://custom.example.com");
        assert_eq!(client.base_url, "https://custom.example.com");
    }

    #[test]
    fn client_with_retry_config() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_retry_config(5, 2000, 120_000);
        assert_eq!(client.max_retries, 5);
        assert_eq!(client.initial_delay_ms, 2000);
        assert_eq!(client.max_delay_ms, 120_000);
    }

    #[test]
    fn client_debug_redacts_token() {
        let client = AirtableClient::new("my-secret-api-token").unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("my-secret-api-token"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("AirtableClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_base_url("https://test.example.com");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://test.example.com"));
    }

    #[test]
    fn client_debug_shows_max_retries() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_retry_config(7, 500, 30_000);
        let dbg = format!("{client:?}");
        assert!(dbg.contains('7'));
    }

    #[test]
    fn client_new_with_auth_token() {
        let client = AirtableClient::new_with_auth(AirtableAuth::Token("tok".into())).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_with_auth_credential_id() {
        let client =
            AirtableClient::new_with_auth(AirtableAuth::CredentialId(CredentialId::new())).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_total_requests_starts_at_zero() {
        let client = AirtableClient::new("tok").unwrap();
        assert_eq!(client.total_requests(), 0);
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.airtable.com/v0");
    }

    #[test]
    fn client_chained_builders() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_base_url("https://example.com")
            .with_retry_config(1, 100, 500);
        assert_eq!(client.base_url, "https://example.com");
        assert_eq!(client.max_retries, 1);
        assert_eq!(client.initial_delay_ms, 100);
        assert_eq!(client.max_delay_ms, 500);
    }

    #[test]
    fn client_retry_config_zero_retries() {
        let client = AirtableClient::new("tok")
            .unwrap()
            .with_retry_config(0, 0, 0);
        assert_eq!(client.max_retries, 0);
        assert_eq!(client.initial_delay_ms, 0);
        assert_eq!(client.max_delay_ms, 0);
    }
}
