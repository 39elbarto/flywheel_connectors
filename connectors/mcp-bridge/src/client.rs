//! MCP JSON-RPC client over HTTP (Streamable HTTP transport).

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::{Client, Response, StatusCode};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{McpBridgeError, McpBridgeResult},
    types::{ApiErrorResponse, JsonRpcRequest, JsonRpcResponse},
};

/// MCP server authentication.
#[derive(Clone)]
pub struct McpAuth {
    pub api_key: Option<String>,
}

impl McpAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        if self.api_key.is_some() {
            "api_key:redacted".to_string()
        } else {
            "api_key:none".to_string()
        }
    }
}

impl fmt::Debug for McpAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpAuth")
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// MCP JSON-RPC client that communicates with an MCP server over HTTP.
pub struct McpClient {
    client: Client,
    auth: McpAuth,
    base_url: String,
    request_id: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for McpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl McpClient {
    /// Create a new MCP client.
    pub fn new(auth: McpAuth, base_url: &str) -> McpBridgeResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("fcp-mcp-bridge/0.1.0 (FCP connector)")
            .build()?;

        let url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            auth,
            base_url: url,
            request_id: AtomicU64::new(1),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(120)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref key) = self.auth.api_key {
            req.header("Authorization", format!("Bearer {key}"))
        } else {
            req
        }
    }

    async fn handle_http_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> McpBridgeResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message.or(e.error))
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(McpBridgeError::Unauthorized),
            403 => Err(McpBridgeError::Forbidden),
            404 => Err(McpBridgeError::NotFound { resource: detail }),
            429 => Err(McpBridgeError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(McpBridgeError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    /// Send a JSON-RPC request to the MCP server.
    #[instrument(skip(self, params), fields(mcp_method))]
    pub async fn rpc_call(
        &self,
        mcp_method: &str,
        params: serde_json::Value,
    ) -> McpBridgeResult<serde_json::Value> {
        let id = self.next_id();
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: mcp_method.to_string(),
            params,
        };

        let url = format!("{}/mcp", self.base_url);
        debug!(url = %url, method = %mcp_method, id, "MCP JSON-RPC request");

        let req = self
            .add_auth(self.client.post(&url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&request);

        let resp = req.send().await?;
        let status = resp.status();

        if !status.is_success() {
            return self.handle_http_error(status, resp).await;
        }

        let body = resp.text().await?;
        let rpc_response: JsonRpcResponse = serde_json::from_str(&body)?;

        if let Some(err) = rpc_response.error {
            return Err(McpBridgeError::McpError {
                code: err.code,
                message: err.message,
            });
        }

        Ok(rpc_response.result.unwrap_or(serde_json::Value::Null))
    }

    // -- MCP Operations --

    /// List tools from the MCP server.
    pub async fn tools_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("tools/list", json!({})).await
    }

    /// Call a tool on the MCP server.
    pub async fn tools_call(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call(
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments
            }),
        )
        .await
    }

    /// List resources from the MCP server.
    pub async fn resources_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("resources/list", json!({})).await
    }

    /// Read a resource from the MCP server.
    pub async fn resources_read(&self, uri: &str) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("resources/read", json!({"uri": uri})).await
    }

    /// List prompts from the MCP server.
    pub async fn prompts_list(&self) -> McpBridgeResult<serde_json::Value> {
        self.rpc_call("prompts/list", json!({})).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = McpAuth {
            api_key: Some("secret-key-value".into()),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-key-value"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_none_key() {
        let auth = McpAuth { api_key: None };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn auth_redacted_label_with_key() {
        let auth = McpAuth {
            api_key: Some("secret".into()),
        };
        let label = auth.redacted_label();
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn auth_redacted_label_without_key() {
        let auth = McpAuth { api_key: None };
        let label = auth.redacted_label();
        assert!(label.contains("none"));
    }

    #[test]
    fn client_new_with_url() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://mcp.example.com").unwrap();
        assert_eq!(client.base_url, "https://mcp.example.com");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://mcp.example.com/").unwrap();
        assert_eq!(client.base_url, "https://mcp.example.com");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
    }

    #[test]
    fn client_debug_does_not_leak_key() {
        let auth = McpAuth {
            api_key: Some("super-secret".into()),
        };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn auth_clone() {
        let auth = McpAuth {
            api_key: Some("KEY".into()),
        };
        let cloned = McpAuth::clone(&auth);
        assert_eq!(cloned.api_key, Some("KEY".into()));
    }

    #[test]
    fn auth_clone_none() {
        let auth = McpAuth { api_key: None };
        let cloned = McpAuth::clone(&auth);
        assert!(cloned.api_key.is_none());
    }

    #[test]
    fn next_id_increments() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        let id1 = client.next_id();
        let id2 = client.next_id();
        let id3 = client.next_id();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn next_id_starts_at_one() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        assert_eq!(client.next_id(), 1);
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("McpClient"));
    }

    #[test]
    fn auth_debug_contains_struct_name() {
        let auth = McpAuth { api_key: None };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("McpAuth"));
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com///").unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn auth_redacted_label_with_some_key() {
        let auth = McpAuth {
            api_key: Some("key".into()),
        };
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_with_none_key() {
        let auth = McpAuth { api_key: None };
        assert_eq!(auth.redacted_label(), "api_key:none");
    }

    #[test]
    fn client_new_with_localhost_port() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "http://127.0.0.1:3000").unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:3000");
    }

    #[test]
    fn auth_debug_some_key_shows_redacted() {
        let auth = McpAuth {
            api_key: Some("my-super-secret-key".into()),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("my-super-secret-key"));
    }

    #[test]
    fn client_new_preserves_path() {
        let auth = McpAuth { api_key: None };
        let client = McpClient::new(auth, "https://example.com/api/v1").unwrap();
        assert_eq!(client.base_url, "https://example.com/api/v1");
    }
}
