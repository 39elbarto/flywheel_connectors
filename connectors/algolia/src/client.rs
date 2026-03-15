//! `Algolia` API client.

use std::fmt;
use std::time::Duration;

use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{AlgoliaError, AlgoliaResult},
    types::ApiErrorResponse,
};

/// Default `Algolia` API base URL template.
/// The real URL is `https://{application_id}.algolia.net/1`.
pub const DEFAULT_BASE_URL_TEMPLATE: &str = "https://{app_id}.algolia.net/1";

/// `Algolia` authentication credentials.
#[derive(Clone)]
pub struct AlgoliaAuth {
    pub application_id: String,
    pub api_key: String,
}

impl AlgoliaAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        format!("app_id:{},api_key:redacted", self.application_id)
    }
}

impl fmt::Debug for AlgoliaAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlgoliaAuth")
            .field("application_id", &self.application_id)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

/// `Algolia` API client.
pub struct AlgoliaClient {
    client: Client,
    auth: AlgoliaAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for AlgoliaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlgoliaClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AlgoliaClient {
    /// Create a new `Algolia` client.
    pub fn new(auth: AlgoliaAuth, base_url: Option<&str>) -> AlgoliaResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-algolia/0.1.0 (FCP connector)")
            .build()?;

        let url = match base_url {
            Some(u) => u.trim_end_matches('/').to_string(),
            None => format!("https://{}.algolia.net/1", auth.application_id),
        };

        Ok(Self {
            client,
            auth,
            base_url: url,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default()
                    .with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("X-Algolia-Application-Id", &self.auth.application_id)
            .header("X-Algolia-API-Key", &self.auth.api_key)
    }

    async fn handle_response(&self, resp: Response) -> AlgoliaResult<serde_json::Value> {
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
    ) -> AlgoliaResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(AlgoliaError::Unauthorized),
            403 => Err(AlgoliaError::Forbidden),
            404 => Err(AlgoliaError::NotFound { resource: detail }),
            429 => Err(AlgoliaError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(AlgoliaError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> AlgoliaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> AlgoliaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> AlgoliaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Search --

    /// Search an index.
    pub async fn search(
        &self,
        index_name: &str,
        query: &str,
        hits_per_page: Option<i64>,
    ) -> AlgoliaResult<serde_json::Value> {
        let mut body = serde_json::json!({ "query": query });
        if let Some(hpp) = hits_per_page {
            body["hitsPerPage"] = serde_json::json!(hpp);
        }
        self.post(&format!("/indexes/{index_name}/query"), &body)
            .await
    }

    // -- Indices --

    /// List all indices.
    pub async fn list_indices(&self) -> AlgoliaResult<serde_json::Value> {
        self.get("/indexes").await
    }

    // -- Records --

    /// Get a record by `objectID`.
    pub async fn get_record(
        &self,
        index_name: &str,
        object_id: &str,
    ) -> AlgoliaResult<serde_json::Value> {
        self.get(&format!("/indexes/{index_name}/{object_id}"))
            .await
    }

    /// Delete a record by `objectID`.
    pub async fn delete_record(
        &self,
        index_name: &str,
        object_id: &str,
    ) -> AlgoliaResult<serde_json::Value> {
        self.delete(&format!("/indexes/{index_name}/{object_id}"))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = AlgoliaAuth {
            application_id: "APP123".into(),
            api_key: "secret-key-value".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-key-value"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("APP123"));
    }

    #[test]
    fn auth_redacted_label() {
        let auth = AlgoliaAuth {
            application_id: "APP123".into(),
            api_key: "secret".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("APP123"));
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn client_new_with_custom_base_url() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "KEY".into(),
        };
        let client = AlgoliaClient::new(auth, Some("https://test.example.com/1")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/1");
    }

    #[test]
    fn client_new_default_url() {
        let auth = AlgoliaAuth {
            application_id: "MYAPP".into(),
            api_key: "KEY".into(),
        };
        let client = AlgoliaClient::new(auth, None).unwrap();
        assert_eq!(client.base_url, "https://MYAPP.algolia.net/1");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "KEY".into(),
        };
        let client = AlgoliaClient::new(auth, Some("https://test.example.com/1/")).unwrap();
        assert_eq!(client.base_url, "https://test.example.com/1");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "KEY".into(),
        };
        let client = AlgoliaClient::new(auth, Some("https://example.com")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
        assert!(!dbg.contains("KEY"));
    }

    #[test]
    fn auth_clone() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "KEY".into(),
        };
        let cloned = AlgoliaAuth::clone(&auth);
        assert_eq!(cloned.application_id, "APP");
        assert_eq!(cloned.api_key, "KEY");
    }

    #[test]
    fn default_base_url_template_contains_algolia() {
        assert!(DEFAULT_BASE_URL_TEMPLATE.contains("algolia.net"));
    }

    #[test]
    fn default_base_url_template_is_https() {
        assert!(DEFAULT_BASE_URL_TEMPLATE.starts_with("https://"));
    }

    #[test]
    fn default_base_url_template_has_version() {
        assert!(DEFAULT_BASE_URL_TEMPLATE.contains("/1"));
    }

    #[test]
    fn client_debug_redacts_api_key() {
        let auth = AlgoliaAuth {
            application_id: "TESTAPP".into(),
            api_key: "super-secret-key".into(),
        };
        let client = AlgoliaClient::new(auth, Some("https://example.com")).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret-key"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("TESTAPP"));
    }

    #[test]
    fn auth_redacted_label_format() {
        let auth = AlgoliaAuth {
            application_id: "MY_APP".into(),
            api_key: "secret".into(),
        };
        let label = auth.redacted_label();
        assert_eq!(label, "app_id:MY_APP,api_key:redacted");
    }

    #[test]
    fn client_default_url_uses_app_id() {
        let auth = AlgoliaAuth {
            application_id: "XYZ789".into(),
            api_key: "key".into(),
        };
        let client = AlgoliaClient::new(auth, None).unwrap();
        assert!(client.base_url.contains("XYZ789"));
    }

    #[test]
    fn client_strips_multiple_trailing_slashes() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "KEY".into(),
        };
        let client = AlgoliaClient::new(auth, Some("https://example.com///")).unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_debug_struct_format() {
        let auth = AlgoliaAuth {
            application_id: "A1B2C3".into(),
            api_key: "secret".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("AlgoliaAuth"));
        assert!(dbg.contains("A1B2C3"));
    }

    #[test]
    fn client_custom_url_no_trailing_slash() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "KEY".into(),
        };
        let client = AlgoliaClient::new(auth, Some("https://example.com/v1")).unwrap();
        assert_eq!(client.base_url, "https://example.com/v1");
    }

    #[test]
    fn auth_clone_preserves_fields() {
        let auth = AlgoliaAuth {
            application_id: "ORIG_APP".into(),
            api_key: "ORIG_KEY".into(),
        };
        let cloned = auth.clone();
        assert_eq!(cloned.application_id, "ORIG_APP");
        assert_eq!(cloned.api_key, "ORIG_KEY");
        assert_eq!(auth.application_id, "ORIG_APP");
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "KEY".into(),
        };
        let client = AlgoliaClient::new(auth, Some("https://example.com")).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("AlgoliaClient"));
    }

    #[test]
    fn client_empty_url() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "KEY".into(),
        };
        let client = AlgoliaClient::new(auth, Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn auth_redacted_label_does_not_leak_api_key() {
        let auth = AlgoliaAuth {
            application_id: "APP".into(),
            api_key: "my-super-secret-algolia-key-12345".into(),
        };
        let label = auth.redacted_label();
        assert!(!label.contains("my-super-secret-algolia-key-12345"));
        assert!(label.contains("APP"));
    }
}
