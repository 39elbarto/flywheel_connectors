//! MCP JSON-RPC client over HTTP (Streamable HTTP transport).

use fcp_prelude::{CredentialId, log_redaction::redact_url};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode, Url};
use serde_json::json;
use tracing::{debug, instrument};

use crate::{
    error::{McpBridgeError, McpBridgeResult},
    types::{JsonRpcRequest, JsonRpcResponse},
};

/// MCP server authentication.
#[derive(Clone)]
pub struct McpAuth {
    pub api_key: Option<String>,
    pub credential_id: Option<CredentialId>,
}

impl McpAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        if self.api_key.is_some() {
            "api_key:redacted".to_string()
        } else if let Some(credential_id) = self.credential_id {
            format!("credential_id:{credential_id}")
        } else {
            "none".to_string()
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct McpClientMetrics {
    pub auth_retry_count: u64,
    pub session_expired_retry_count: u64,
}

pub struct McpClient {
    client: Client,
    auth: McpAuth,
    base_url: Url,
    request_id: AtomicU64,
    runtime: ConnectorRuntime,
    auth_retry_count: AtomicU64,
    session_expired_retry_count: AtomicU64,
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
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("fcp-mcp-bridge/0.1.0 (FCP connector)")
            .build()?;

        if auth.api_key.is_some() && auth.credential_id.is_some() {
            return Err(McpBridgeError::InvalidInput(
                "provide exactly one MCP authentication method".into(),
            ));
        }
        let url = Self::canonicalize_base_url(base_url)?;

        Ok(Self {
            client,
            auth,
            base_url: url,
            request_id: AtomicU64::new(1),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(120)),
            ),
            auth_retry_count: AtomicU64::new(0),
            session_expired_retry_count: AtomicU64::new(0),
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

    /// Snapshot retry/session metrics.
    #[must_use]
    pub fn metrics(&self) -> McpClientMetrics {
        McpClientMetrics {
            auth_retry_count: self.auth_retry_count.load(Ordering::Relaxed),
            session_expired_retry_count: self.session_expired_retry_count.load(Ordering::Relaxed),
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

        drop(resp);

        match status.as_u16() {
            401 => Err(McpBridgeError::Unauthorized),
            403 => Err(McpBridgeError::Forbidden),
            404 => Err(McpBridgeError::NotFound {
                resource: "MCP endpoint".into(),
            }),
            429 => Err(McpBridgeError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(McpBridgeError::Api {
                status_code: code,
                message: "MCP provider returned an HTTP error".into(),
            }),
        }
    }

    /// Send a JSON-RPC request to the MCP server.
    #[instrument(skip(self, params), fields(mcp_method))]
    /// Issue an MCP JSON-RPC call.
    ///
    /// Replay safety is derived from the MCP method: the discovery and read
    /// methods are pure reads, while `tools/call` invokes an arbitrary
    /// downstream tool whose effects this bridge cannot see (br-kxd3e).
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

        self.ensure_provider_egress_allowed()?;
        debug!(
            url = %redact_url(self.base_url.as_str()),
            method = %mcp_method,
            id,
            "MCP JSON-RPC request"
        );
        self.rpc_call_once(&request).await
    }

    async fn rpc_call_once(&self, request: &JsonRpcRequest) -> McpBridgeResult<serde_json::Value> {
        let req = self
            .add_auth(self.client.post(self.base_url.clone()))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-06-18")
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
                message: "MCP JSON-RPC provider error".into(),
            });
        }

        Ok(rpc_response.result.unwrap_or(serde_json::Value::Null))
    }

    /// Canonicalize an exact MCP Streamable HTTP endpoint.
    pub fn canonicalize_base_url(base_url: &str) -> McpBridgeResult<Url> {
        let mut parsed = Url::parse(base_url.trim())
            .map_err(|_| McpBridgeError::InvalidInput("mcp_url must be an absolute URL".into()))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must not contain userinfo".into(),
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must not contain query or fragment".into(),
            ));
        }
        let Some(host) = parsed.host_str() else {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must include a host".into(),
            ));
        };
        let local = is_loopback_host(host);
        match parsed.scheme() {
            "http" if local => {}
            "https" if !local => {}
            "https" => {
                return Err(McpBridgeError::InvalidInput(
                    "localhost MCP endpoints are test-only and must use loopback HTTP".into(),
                ));
            }
            _ => {
                return Err(McpBridgeError::InvalidInput(
                    "mcp_url must use HTTPS for production or HTTP only for loopback tests".into(),
                ));
            }
        }
        if !local && (is_ip_literal(host) || is_private_hostname(host)) {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must not target private, tailnet, localhost, or IP-literal production hosts".into(),
            ));
        }
        if !local && parsed.port().is_some_and(|port| port != 443) {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must use production HTTPS port 443".into(),
            ));
        }
        let path = parsed.path();
        if path.contains('%') || !matches!(path, "/mcp" | "/mcp/") {
            return Err(McpBridgeError::InvalidInput(
                "mcp_url must be the exact /mcp endpoint; only a trailing slash may be normalized"
                    .into(),
            ));
        }
        parsed.set_path("/mcp");
        parsed.set_query(None);
        parsed.set_fragment(None);
        if parsed.port() == Some(443) {
            parsed.set_port(None).map_err(|()| {
                McpBridgeError::InvalidInput("mcp_url port could not be canonicalized".into())
            })?;
        }
        Ok(parsed)
    }

    fn ensure_provider_egress_allowed(&self) -> McpBridgeResult<()> {
        if self.auth.credential_id.is_some() {
            return Err(McpBridgeError::InvalidInput(
                "credential_id requires host-mediated secret injection; direct MCP egress is unavailable".into(),
            ));
        }
        if !self.base_url.host_str().is_some_and(is_loopback_host) {
            return Err(McpBridgeError::InvalidInput(
                "production MCP egress requires host-mediated exact-origin enforcement".into(),
            ));
        }
        Ok(())
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

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

fn is_private_hostname(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.strip_suffix(".local").is_some()
        || normalized.strip_suffix(".internal").is_some()
        || normalized.strip_suffix(".home.arpa").is_some()
        || normalized.strip_suffix(".ts.net").is_some()
        || normalized.strip_suffix(".tailnet").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = McpAuth {
            api_key: Some("secret-key-value".into()),
            credential_id: None,
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-key-value"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_none_key() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn auth_redacted_label_with_key() {
        let auth = McpAuth {
            api_key: Some("secret".into()),
            credential_id: None,
        };
        let label = auth.redacted_label();
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn auth_redacted_label_without_key() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let label = auth.redacted_label();
        assert!(label.contains("none"));
    }

    #[test]
    fn client_new_with_url() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://mcp.example.com/mcp").unwrap();
        assert_eq!(client.base_url.as_str(), "https://mcp.example.com/mcp");
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://mcp.example.com/mcp/").unwrap();
        assert_eq!(client.base_url.as_str(), "https://mcp.example.com/mcp");
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
    }

    #[test]
    fn client_debug_does_not_leak_key() {
        let auth = McpAuth {
            api_key: Some("super-secret".into()),
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn auth_clone() {
        let auth = McpAuth {
            api_key: Some("KEY".into()),
            credential_id: None,
        };
        let cloned = McpAuth::clone(&auth);
        assert_eq!(cloned.api_key, Some("KEY".into()));
    }

    #[test]
    fn auth_clone_none() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let cloned = McpAuth::clone(&auth);
        assert!(cloned.api_key.is_none());
    }

    #[test]
    fn next_id_increments() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        let id1 = client.next_id();
        let id2 = client.next_id();
        let id3 = client.next_id();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn next_id_starts_at_one() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        assert_eq!(client.next_id(), 1);
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("McpClient"));
    }

    #[test]
    fn auth_debug_contains_struct_name() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("McpAuth"));
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "https://example.com/mcp/").unwrap();
        assert_eq!(client.base_url.path(), "/mcp");
    }

    #[test]
    fn auth_redacted_label_with_some_key() {
        let auth = McpAuth {
            api_key: Some("key".into()),
            credential_id: None,
        };
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_with_none_key() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        assert_eq!(auth.redacted_label(), "none");
    }

    #[test]
    fn client_new_with_localhost_port() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        let client = McpClient::new(auth, "http://127.0.0.1:3000/mcp").unwrap();
        assert_eq!(client.base_url.as_str(), "http://127.0.0.1:3000/mcp");
    }

    #[test]
    fn auth_debug_some_key_shows_redacted() {
        let auth = McpAuth {
            api_key: Some("my-super-secret-key".into()),
            credential_id: None,
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("my-super-secret-key"));
    }

    #[test]
    fn client_new_rejects_non_mcp_path() {
        let auth = McpAuth {
            api_key: None,
            credential_id: None,
        };
        assert!(McpClient::new(auth, "https://example.com/api/v1").is_err());
    }
}
