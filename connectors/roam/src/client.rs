//! `Roam Research` API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{RoamError, RoamResult},
    types::ApiErrorResponse,
};

/// Default `Roam Research` API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.roamresearch.com/api/graph";

/// Default local fallback URL for `Roam Research` local server.
pub const LOCAL_FALLBACK_URL: &str = "http://localhost:12345";

/// Authentication mode for the `Roam Research` API.
#[derive(Clone)]
pub enum RoamAuth {
    /// Bearer token (API token from Roam settings).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl RoamAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for RoamAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Roam Research` API client.
pub struct RoamClient {
    client: Client,
    auth: RoamAuth,
    base_url: String,
    graph_name: String,
}

impl fmt::Debug for RoamClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoamClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("graph_name", &self.graph_name)
            .finish()
    }
}

impl RoamClient {
    /// Create a new `Roam Research` client.
    pub fn new(auth: RoamAuth, graph_name: &str, base_url: Option<&str>) -> RoamResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-roam/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            graph_name: graph_name.to_string(),
        })
    }

    /// Return the graph name.
    #[must_use]
    pub fn graph_name(&self) -> &str {
        &self.graph_name
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            RoamAuth::BearerToken(token) => req.bearer_auth(token),
            RoamAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    fn graph_url(&self, endpoint: &str) -> String {
        format!("{}/{}{}", self.base_url, self.graph_name, endpoint)
    }

    async fn handle_response(&self, resp: Response) -> RoamResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(json!({}));
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
    ) -> RoamResult<serde_json::Value> {
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
            401 => Err(RoamError::Unauthorized),
            403 => Err(RoamError::Forbidden),
            404 => Err(RoamError::NotFound { resource: detail }),
            429 => Err(RoamError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(RoamError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> RoamResult<serde_json::Value> {
        let url = self.graph_url(path);
        debug!(url = %url, "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Pages --

    /// List all pages in the graph via Datalog query.
    pub async fn list_pages(&self) -> RoamResult<serde_json::Value> {
        let query = json!({
            "query": "[:find (pull ?e [:node/title :block/uid :create/time :edit/time]) :where [?e :node/title]]"
        });
        let result = self.post("/q", &query).await?;
        let pages = unwrap_query_result(&result);
        Ok(json!({ "pages": pages }))
    }

    /// Get a page by title via Datalog query.
    pub async fn get_page(&self, title: &str) -> RoamResult<serde_json::Value> {
        let query = json!({
            "query": "[:find (pull ?e [:node/title :block/uid :create/time :edit/time :block/children]) :in $ ?title :where [?e :node/title ?title]]",
            "args": [title]
        });
        let result = self.post("/q", &query).await?;
        let pages = unwrap_query_result(&result);
        if pages.is_empty() {
            return Err(RoamError::NotFound {
                resource: format!("Page with title: {title}"),
            });
        }
        Ok(pages[0].clone())
    }

    // -- Blocks --

    /// List blocks on a page via Datalog query.
    pub async fn list_blocks(&self, page_uid: &str) -> RoamResult<serde_json::Value> {
        let query = json!({
            "query": "[:find (pull ?c [:block/uid :block/string :block/order :create/time :edit/time :block/open :block/heading :block/children]) :in $ ?uid :where [?e :block/uid ?uid] [?e :block/children ?c]]",
            "args": [page_uid]
        });
        let result = self.post("/q", &query).await?;
        let blocks = unwrap_query_result(&result);
        Ok(json!({ "blocks": blocks }))
    }

    /// Create a block on a page.
    pub async fn create_block(
        &self,
        page_uid: &str,
        content: &str,
    ) -> RoamResult<serde_json::Value> {
        let body = json!({
            "action": "create-block",
            "location": {
                "parent-uid": page_uid,
                "order": "last"
            },
            "block": {
                "string": content
            }
        });
        self.post("/write", &body).await
    }
}

/// Extract the result array from a Roam Datalog query response.
/// Roam returns results as `[[item], [item], ...]`, so we flatten the outer array.
fn unwrap_query_result(value: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(arr) = value.as_array() {
        arr.iter()
            .filter_map(|row| {
                if let Some(inner) = row.as_array() {
                    inner.first().cloned()
                } else {
                    Some(row.clone())
                }
            })
            .collect()
    } else if let Some(result) = value.get("result") {
        if let Some(arr) = result.as_array() {
            arr.iter()
                .filter_map(|row| {
                    if let Some(inner) = row.as_array() {
                        inner.first().cloned()
                    } else {
                        Some(row.clone())
                    }
                })
                .collect()
        } else {
            vec![]
        }
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = RoamAuth::BearerToken("secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = RoamAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = RoamAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = RoamAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_id_label() {
        let cred = RoamAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = RoamAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.roamresearch.com/api/graph");
    }

    #[test]
    fn local_fallback_url_value() {
        assert_eq!(LOCAL_FALLBACK_URL, "http://localhost:12345");
    }

    #[test]
    fn client_new_stores_graph_name() {
        let client =
            RoamClient::new(RoamAuth::BearerToken("tok".into()), "my-graph", None).unwrap();
        assert_eq!(client.graph_name(), "my-graph");
    }

    #[test]
    fn client_new_default_base_url() {
        let client = RoamClient::new(RoamAuth::BearerToken("tok".into()), "g", None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_base_url() {
        let client = RoamClient::new(
            RoamAuth::BearerToken("tok".into()),
            "g",
            Some("http://localhost:12345"),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:12345");
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = RoamClient::new(
            RoamAuth::BearerToken("tok".into()),
            "g",
            Some("http://localhost:12345/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:12345");
    }

    #[test]
    fn graph_url_construction() {
        let client = RoamClient::new(
            RoamAuth::BearerToken("tok".into()),
            "my-graph",
            Some("https://api.roamresearch.com/api/graph"),
        )
        .unwrap();
        assert_eq!(
            client.graph_url("/q"),
            "https://api.roamresearch.com/api/graph/my-graph/q"
        );
    }

    #[test]
    fn graph_url_write_endpoint() {
        let client = RoamClient::new(
            RoamAuth::BearerToken("tok".into()),
            "test-graph",
            Some("http://localhost:12345"),
        )
        .unwrap();
        assert_eq!(
            client.graph_url("/write"),
            "http://localhost:12345/test-graph/write"
        );
    }

    #[test]
    fn client_debug_shows_fields() {
        let client = RoamClient::new(RoamAuth::BearerToken("secret".into()), "g", None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("RoamClient"));
        assert!(dbg.contains("graph_name"));
        assert!(!dbg.contains("secret"));
    }

    #[test]
    fn unwrap_query_result_nested_arrays() {
        let data = json!([[{"uid": "p1", "title": "Page 1"}], [{"uid": "p2", "title": "Page 2"}]]);
        let result = unwrap_query_result(&data);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["uid"], "p1");
        assert_eq!(result[1]["uid"], "p2");
    }

    #[test]
    fn unwrap_query_result_flat_array() {
        let data = json!([{"uid": "p1"}, {"uid": "p2"}]);
        // Each item is not an array, so it's returned as-is
        let result = unwrap_query_result(&data);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn unwrap_query_result_empty() {
        let data = json!([]);
        let result = unwrap_query_result(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn unwrap_query_result_not_array() {
        let data = json!({"something": "else"});
        let result = unwrap_query_result(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn unwrap_query_result_with_result_key() {
        let data = json!({"result": [[{"uid": "p1"}], [{"uid": "p2"}]]});
        let result = unwrap_query_result(&data);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn unwrap_query_result_null() {
        let data = json!(null);
        let result = unwrap_query_result(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn unwrap_query_result_result_not_array() {
        let data = json!({"result": "not an array"});
        let result = unwrap_query_result(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn unwrap_query_result_single_item() {
        let data = json!([[{"uid": "only"}]]);
        let result = unwrap_query_result(&data);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["uid"], "only");
    }

    #[test]
    fn auth_clone_bearer_token() {
        let auth = RoamAuth::BearerToken("tok123".into());
        let cloned = auth.clone();
        // Use original after clone to prevent redundant_clone
        assert!(!auth.is_secretless());
        match cloned {
            RoamAuth::BearerToken(t) => assert_eq!(t, "tok123"),
            RoamAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn auth_clone_credential_id() {
        let cred = RoamAuth::CredentialId(CredentialId::new());
        let cloned = cred.clone();
        // Use original after clone
        assert!(cred.is_secretless());
        assert!(cloned.is_secretless());
    }

    #[test]
    fn graph_url_empty_endpoint() {
        let client = RoamClient::new(
            RoamAuth::BearerToken("tok".into()),
            "graph",
            Some("http://localhost:8080"),
        )
        .unwrap();
        assert_eq!(client.graph_url(""), "http://localhost:8080/graph");
    }

    #[test]
    fn graph_url_root_endpoint() {
        let client = RoamClient::new(
            RoamAuth::BearerToken("tok".into()),
            "graph",
            Some("http://localhost:8080"),
        )
        .unwrap();
        assert_eq!(client.graph_url("/"), "http://localhost:8080/graph/");
    }

    #[test]
    fn client_new_with_credential_id() {
        let client = RoamClient::new(
            RoamAuth::CredentialId(CredentialId::new()),
            "my-graph",
            None,
        )
        .unwrap();
        assert_eq!(client.graph_name(), "my-graph");
    }

    #[test]
    fn unwrap_query_result_mixed_array() {
        let data = json!([
            [{"uid": "p1"}],
            {"uid": "p2"},
            [{"uid": "p3"}]
        ]);
        let result = unwrap_query_result(&data);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn unwrap_query_result_result_key_flat() {
        let data = json!({"result": [{"uid": "p1"}, {"uid": "p2"}]});
        let result = unwrap_query_result(&data);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn unwrap_query_result_empty_inner_arrays() {
        let data = json!([[], []]);
        let result = unwrap_query_result(&data);
        // Each inner empty array has no first() element, so filtered out
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn unwrap_query_result_number() {
        let data = json!(42);
        let result = unwrap_query_result(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn unwrap_query_result_string() {
        let data = json!("hello");
        let result = unwrap_query_result(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn unwrap_query_result_bool() {
        let data = json!(true);
        let result = unwrap_query_result(&data);
        assert!(result.is_empty());
    }
}
