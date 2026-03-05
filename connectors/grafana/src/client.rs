//! Grafana API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{GrafanaError, GrafanaResult},
    types::ApiErrorResponse,
};

/// Default Grafana Cloud API base URL.
pub const DEFAULT_BASE_URL: &str = "https://grafana.com/api";

/// Authentication mode for the Grafana API.
#[derive(Clone)]
pub enum GrafanaAuth {
    /// Bearer token (API key or service account token).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl GrafanaAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for GrafanaAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Grafana API client.
pub struct GrafanaClient {
    client: Client,
    auth: GrafanaAuth,
    base_url: String,
}

impl fmt::Debug for GrafanaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrafanaClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl GrafanaClient {
    /// Create a new Grafana client.
    pub fn new(auth: GrafanaAuth, base_url: Option<&str>) -> GrafanaResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-grafana/0.1.0")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    /// Create a new client with a custom reqwest client (for testing).
    pub fn with_client(client: Client, auth: GrafanaAuth, base_url: &str) -> Self {
        Self {
            client,
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            GrafanaAuth::BearerToken(token) => req.bearer_auth(token),
            GrafanaAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> GrafanaResult<serde_json::Value> {
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
    ) -> GrafanaResult<serde_json::Value> {
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
            401 => Err(GrafanaError::Unauthorized),
            403 => Err(GrafanaError::Forbidden),
            404 => Err(GrafanaError::NotFound { resource: detail }),
            429 => Err(GrafanaError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(GrafanaError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> GrafanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");

        let req = self.client.get(&url);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST request");

        let req = self.client.post(&url).json(body);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> GrafanaResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");

        let req = self.client.delete(&url);
        let req = self.add_auth(req);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Dashboards --

    /// Search/list dashboards.
    pub async fn search_dashboards(
        &self,
        query: Option<&str>,
        tag: Option<&[String]>,
        limit: Option<i64>,
    ) -> GrafanaResult<serde_json::Value> {
        let mut params = Vec::new();
        params.push("type=dash-db".to_string());
        if let Some(q) = query {
            params.push(format!("query={q}"));
        }
        if let Some(tags) = tag {
            for t in tags {
                params.push(format!("tag={t}"));
            }
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        let qs = params.join("&");
        self.get(&format!("/search?{qs}")).await
    }

    /// Get a dashboard by UID.
    pub async fn get_dashboard(&self, uid: &str) -> GrafanaResult<serde_json::Value> {
        self.get(&format!("/dashboards/uid/{uid}")).await
    }

    /// Create or update a dashboard.
    pub async fn save_dashboard(
        &self,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        self.post("/dashboards/db", body).await
    }

    /// Delete a dashboard by UID.
    pub async fn delete_dashboard(&self, uid: &str) -> GrafanaResult<serde_json::Value> {
        self.delete(&format!("/dashboards/uid/{uid}")).await
    }

    // -- Datasources --

    /// List all datasources.
    pub async fn list_datasources(&self) -> GrafanaResult<serde_json::Value> {
        self.get("/datasources").await
    }

    /// Query a datasource via the query API.
    pub async fn query_datasource(
        &self,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        self.post("/ds/query", body).await
    }

    // -- Alerts --

    /// List alert rules.
    pub async fn list_alert_rules(
        &self,
        state: Option<&str>,
        limit: Option<i64>,
    ) -> GrafanaResult<serde_json::Value> {
        let mut params = Vec::new();
        if let Some(s) = state {
            params.push(format!("state={s}"));
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        let qs = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        self.get(&format!("/ruler/grafana/api/v1/rules{qs}"))
            .await
    }

    /// Create an alert rule.
    pub async fn create_alert_rule(
        &self,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        self.post("/ruler/grafana/api/v1/rules", body).await
    }

    // -- Annotations --

    /// Create an annotation.
    pub async fn create_annotation(
        &self,
        body: &serde_json::Value,
    ) -> GrafanaResult<serde_json::Value> {
        self.post("/annotations", body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = GrafanaAuth::BearerToken("supersecret".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let bearer = GrafanaAuth::BearerToken("tok".into());
        assert!(!bearer.is_secretless());

        let cred = GrafanaAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let bearer = GrafanaAuth::BearerToken("tok".into());
        assert_eq!(bearer.redacted_label(), "bearer_token:redacted");

        let cred = GrafanaAuth::CredentialId(CredentialId::new());
        assert!(cred.redacted_label().starts_with("credential_id:"));
    }
}
