//! `BigQuery` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode, Url};
use tracing::{debug, instrument};

use crate::{
    error::{BigQueryError, BigQueryResult},
    types::ApiErrorResponse,
};

/// Default `BigQuery` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://bigquery.googleapis.com/bigquery/v2";

/// `BigQuery` authentication credentials.
#[derive(Clone)]
pub struct BigQueryAuth {
    pub access_token: String,
}

impl BigQueryAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        "access_token:redacted".to_string()
    }
}

impl fmt::Debug for BigQueryAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BigQueryAuth")
            .field("access_token", &"<redacted>")
            .finish()
    }
}

/// `BigQuery` API client.
pub struct BigQueryClient {
    client: Client,
    auth: BigQueryAuth,
    base_url: String,
    project_id: Option<String>,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for BigQueryClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BigQueryClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("project_id", &self.project_id)
            .finish()
    }
}

/// Validate that a user-supplied string is safe for use as a URL path segment.
///
/// Rejects empty strings plus `/`, `\`, `..`, and percent-encoded traversal
/// sequences so dynamic path segments cannot alter routing semantics.
fn sanitize_path_segment<'a>(value: &'a str, param_name: &str) -> BigQueryResult<&'a str> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
    {
        return Err(BigQueryError::InvalidInput(format!(
            "invalid {param_name}: must be non-empty and must not contain '/', '\\', '..', or encoded traversal sequences"
        )));
    }
    Ok(trimmed)
}

pub(crate) fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub(crate) fn normalize_base_url(base_url: Option<&str>) -> BigQueryResult<String> {
    let raw = base_url.unwrap_or(DEFAULT_BASE_URL).trim();
    if raw.is_empty() {
        return Err(BigQueryError::Config("base_url must not be empty".into()));
    }

    let parsed = Url::parse(raw)
        .map_err(|error| BigQueryError::Config(format!("base_url could not be parsed: {error}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| BigQueryError::Config("base_url must include a host".into()))?;

    let local = is_local_test_host(host);
    let allowed_host = host.eq_ignore_ascii_case("bigquery.googleapis.com") || local;
    if !allowed_host {
        return Err(BigQueryError::Config(
            "base_url must target bigquery.googleapis.com (localhost/127.0.0.1/::1 allowed for tests)"
                .into(),
        ));
    }

    if parsed.scheme() != "https" && !local {
        return Err(BigQueryError::Config(
            "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests".into(),
        ));
    }

    Ok(raw.trim_end_matches('/').to_string())
}

impl BigQueryClient {
    /// Create a new `BigQuery` client.
    pub fn new(
        auth: BigQueryAuth,
        project_id: Option<String>,
        base_url: Option<&str>,
    ) -> BigQueryResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-bigquery/0.1.0 (FCP connector)")
            .build()?;

        let url = normalize_base_url(base_url)?;

        Ok(Self {
            client,
            auth,
            base_url: url,
            project_id,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Return the configured project ID, if any.
    #[must_use]
    pub fn project_id(&self) -> Option<&str> {
        self.project_id.as_deref()
    }

    /// Gracefully shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.bearer_auth(&self.auth.access_token)
    }

    fn resource_url<'a, I>(&self, segments: I) -> BigQueryResult<Url>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut url = Url::parse(&self.base_url)
            .map_err(|error| BigQueryError::Config(format!("invalid client base_url: {error}")))?;
        {
            let mut path_segments = url.path_segments_mut().map_err(|()| {
                BigQueryError::Config("base_url does not support path segments".into())
            })?;
            for (segment, param_name) in segments {
                path_segments.push(sanitize_path_segment(segment, param_name)?);
            }
        }
        Ok(url)
    }

    async fn handle_response(&self, resp: Response) -> BigQueryResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> BigQueryResult<serde_json::Value> {
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
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(BigQueryError::Unauthorized),
            403 => Err(BigQueryError::Forbidden),
            404 => Err(BigQueryError::NotFound { resource: detail }),
            429 => Err(BigQueryError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(BigQueryError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url = %redact_url(url.as_str())))]
    async fn get(&self, url: Url) -> BigQueryResult<serde_json::Value> {
        debug!(url = %redact_url(url.as_str()), "GET request");
        let req = self
            .add_auth(self.client.get(url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url = %redact_url(url.as_str())))]
    async fn post(&self, url: Url, body: &serde_json::Value) -> BigQueryResult<serde_json::Value> {
        debug!(url = %redact_url(url.as_str()), "POST request");
        let req = self
            .add_auth(self.client.post(url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Datasets --

    /// List datasets in a project.
    pub async fn list_datasets(&self, project_id: &str) -> BigQueryResult<serde_json::Value> {
        let url = self.resource_url([
            ("projects", "projects"),
            (project_id, "project_id"),
            ("datasets", "datasets"),
        ])?;
        self.get(url).await
    }

    // -- Tables --

    /// List tables in a dataset.
    pub async fn list_tables(
        &self,
        project_id: &str,
        dataset_id: &str,
    ) -> BigQueryResult<serde_json::Value> {
        let url = self.resource_url([
            ("projects", "projects"),
            (project_id, "project_id"),
            ("datasets", "datasets"),
            (dataset_id, "dataset_id"),
            ("tables", "tables"),
        ])?;
        self.get(url).await
    }

    // -- Jobs --

    /// List recent jobs in a project.
    pub async fn list_jobs(&self, project_id: &str) -> BigQueryResult<serde_json::Value> {
        let url = self.resource_url([
            ("projects", "projects"),
            (project_id, "project_id"),
            ("jobs", "jobs"),
        ])?;
        self.get(url).await
    }

    /// Run a SQL query.
    pub async fn query(
        &self,
        project_id: &str,
        query_str: &str,
        use_legacy_sql: bool,
    ) -> BigQueryResult<serde_json::Value> {
        let url = self.resource_url([
            ("projects", "projects"),
            (project_id, "project_id"),
            ("queries", "queries"),
        ])?;
        let body = serde_json::json!({
            "query": query_str,
            "useLegacySql": use_legacy_sql,
        });
        self.post(url, &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = BigQueryAuth {
            access_token: "ya29.super-secret-token".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("ya29.super-secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_redacted_label() {
        let auth = BigQueryAuth {
            access_token: "secret".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn client_new_with_custom_base_url() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, None, Some("http://localhost:8080/bq/v2")).unwrap();
        assert_eq!(client.base_url, "http://localhost:8080/bq/v2");
    }

    #[test]
    fn client_new_default_url() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, None, None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, None, Some("http://localhost:8080/bq/v2/")).unwrap();
        assert_eq!(client.base_url, "http://localhost:8080/bq/v2");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = BigQueryAuth {
            access_token: "ya29.super-secret-abc".into(),
        };
        let client = BigQueryClient::new(auth, None, Some("http://localhost:8080")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("localhost:8080"));
        assert!(!dbg.contains("ya29.super-secret-abc"));
    }

    #[test]
    fn auth_clone() {
        let auth = BigQueryAuth {
            access_token: "token123".into(),
        };
        let cloned = BigQueryAuth::clone(&auth);
        assert_eq!(cloned.access_token, "token123");
    }

    #[test]
    fn client_project_id_some() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, Some("my-project".into()), None).unwrap();
        assert_eq!(client.project_id(), Some("my-project"));
    }

    #[test]
    fn client_project_id_none() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, None, None).unwrap();
        assert_eq!(client.project_id(), None);
    }

    #[test]
    fn client_debug_shows_project_id() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, Some("proj-123".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("proj-123"));
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(
            DEFAULT_BASE_URL,
            "https://bigquery.googleapis.com/bigquery/v2"
        );
    }

    #[test]
    fn client_new_with_all_options() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(
            auth,
            Some("my-proj".into()),
            Some("http://localhost:8181/v2"),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:8181/v2");
        assert_eq!(client.project_id(), Some("my-proj"));
    }

    #[test]
    fn auth_redacted_label_format() {
        let auth = BigQueryAuth {
            access_token: "ya29.abc".into(),
        };
        assert_eq!(auth.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn client_new_empty_url() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        assert!(BigQueryClient::new(auth, None, Some("")).is_err());
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, None, Some("http://localhost:8080///")).unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_no_trailing_slash() {
        assert!(!DEFAULT_BASE_URL.ends_with('/'));
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("BigQueryClient"));
        assert!(dbg.contains("auth"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn auth_debug_contains_struct_name() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BigQueryAuth"));
    }

    #[test]
    fn client_new_no_trailing_slash_unchanged() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, None, Some("http://localhost:8080")).unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn sanitize_rejects_forward_slash() {
        let result = sanitize_path_segment("my/project", "project_id");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BigQueryError::InvalidInput(_)));
    }

    #[test]
    fn sanitize_rejects_backslash() {
        let result = sanitize_path_segment("my\\project", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_dot_dot() {
        let result = sanitize_path_segment("..admin", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_whitespace_only() {
        let result = sanitize_path_segment("   ", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_encoded_slash() {
        let result = sanitize_path_segment("my%2fproject", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_encoded_backslash() {
        let result = sanitize_path_segment("my%5cproject", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_encoded_slash_uppercase() {
        let result = sanitize_path_segment("my%2Fproject", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_encoded_backslash_uppercase() {
        let result = sanitize_path_segment("my%5Cproject", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_rejects_encoded_dot_uppercase() {
        let result = sanitize_path_segment("my%2Eproject", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn sanitize_accepts_clean_project_id() {
        assert!(sanitize_path_segment("my-project-123", "project_id").is_ok());
    }

    #[test]
    fn sanitize_accepts_underscored_name() {
        assert!(sanitize_path_segment("my_dataset_v2", "dataset_id").is_ok());
    }

    #[test]
    fn sanitize_accepts_dots_without_traversal() {
        assert!(sanitize_path_segment("my.project", "project_id").is_ok());
    }

    #[test]
    fn sanitize_trims_clean_segment() {
        assert_eq!(
            sanitize_path_segment("  my-project-123  ", "project_id").unwrap(),
            "my-project-123"
        );
    }

    #[test]
    fn sanitize_error_message_contains_param_name() {
        let result = sanitize_path_segment("a/b", "dataset_id");
        match result.unwrap_err() {
            BigQueryError::InvalidInput(msg) => {
                assert!(msg.contains("dataset_id"));
            }
            other => panic!("expected InvalidInput error, got {other:?}"),
        }
    }

    #[test]
    fn sanitize_rejects_path_traversal_sequence() {
        let result = sanitize_path_segment("../../../etc/passwd", "project_id");
        assert!(result.is_err());
    }

    #[test]
    fn normalize_base_url_rejects_unknown_host() {
        let result = normalize_base_url(Some("https://evil.example.com"));
        assert!(matches!(result, Err(BigQueryError::Config(_))));
    }

    #[test]
    fn normalize_base_url_rejects_non_local_http() {
        let result = normalize_base_url(Some("http://bigquery.googleapis.com/bigquery/v2"));
        assert!(matches!(result, Err(BigQueryError::Config(_))));
    }

    #[test]
    fn normalize_base_url_accepts_googleapis_https() {
        let normalized =
            normalize_base_url(Some("https://bigquery.googleapis.com/bigquery/v2/")).unwrap();
        assert_eq!(normalized, DEFAULT_BASE_URL);
    }

    #[test]
    fn normalize_base_url_accepts_local_http_for_tests() {
        let normalized = normalize_base_url(Some("http://localhost:8080/bq/v2/")).unwrap();
        assert_eq!(normalized, "http://localhost:8080/bq/v2");
    }

    #[test]
    fn resource_url_preserves_base_prefix() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client =
            BigQueryClient::new(auth, None, Some("http://localhost:8080/bigquery/v2")).unwrap();
        let url = client
            .resource_url([
                ("projects", "projects"),
                ("demo-project", "project_id"),
                ("datasets", "datasets"),
            ])
            .unwrap();
        assert_eq!(
            url.as_str(),
            "http://localhost:8080/bigquery/v2/projects/demo-project/datasets"
        );
    }
}
