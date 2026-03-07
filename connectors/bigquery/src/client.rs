//! `BigQuery` API client.

use std::fmt;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
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

        let url = match base_url {
            Some(u) => u.trim_end_matches('/').to_string(),
            None => DEFAULT_BASE_URL.to_string(),
        };

        Ok(Self {
            client,
            auth,
            base_url: url,
            project_id,
        })
    }

    /// Return the configured project ID, if any.
    #[must_use]
    pub fn project_id(&self) -> Option<&str> {
        self.project_id.as_deref()
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.bearer_auth(&self.auth.access_token)
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

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> BigQueryResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> BigQueryResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Datasets --

    /// List datasets in a project.
    pub async fn list_datasets(&self, project_id: &str) -> BigQueryResult<serde_json::Value> {
        self.get(&format!("/projects/{project_id}/datasets")).await
    }

    // -- Tables --

    /// List tables in a dataset.
    pub async fn list_tables(
        &self,
        project_id: &str,
        dataset_id: &str,
    ) -> BigQueryResult<serde_json::Value> {
        self.get(&format!(
            "/projects/{project_id}/datasets/{dataset_id}/tables"
        ))
        .await
    }

    // -- Jobs --

    /// List recent jobs in a project.
    pub async fn list_jobs(&self, project_id: &str) -> BigQueryResult<serde_json::Value> {
        self.get(&format!("/projects/{project_id}/jobs")).await
    }

    /// Run a SQL query.
    pub async fn query(
        &self,
        project_id: &str,
        query_str: &str,
        use_legacy_sql: bool,
    ) -> BigQueryResult<serde_json::Value> {
        let body = serde_json::json!({
            "query": query_str,
            "useLegacySql": use_legacy_sql,
        });
        self.post(&format!("/projects/{project_id}/queries"), &body)
            .await
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
        let client =
            BigQueryClient::new(auth, None, Some("https://test.example.com/bq/v2")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/bq/v2");
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
        let client =
            BigQueryClient::new(auth, None, Some("https://test.example.com/bq/v2/")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/bq/v2");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = BigQueryAuth {
            access_token: "ya29.super-secret-abc".into(),
        };
        let client = BigQueryClient::new(auth, None, Some("https://example.com")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
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
        let client =
            BigQueryClient::new(auth, Some("my-project".into()), None).unwrap();
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
        let client =
            BigQueryClient::new(auth, Some("proj-123".into()), None).unwrap();
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
            Some("https://custom.bq.example.com/v2"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.bq.example.com/v2");
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
        let client = BigQueryClient::new(auth, None, Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = BigQueryAuth {
            access_token: "tok".into(),
        };
        let client = BigQueryClient::new(auth, None, Some("https://x.com///")).unwrap();
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
        let client =
            BigQueryClient::new(auth, None, Some("https://example.com")).unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }
}
