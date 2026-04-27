//! Configuration and API types for the Outlook connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

const ALLOWED_GRAPH_HOSTS: &[&str] = &["graph.microsoft.com", "graph.microsoft.us"];

/// Outlook connector configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct OutlookConfig {
    /// Microsoft Graph API access token (`OAuth2` bearer token).
    pub access_token: String,
    /// Optional Graph API base URL override (default: `graph.microsoft.com`).
    #[serde(default = "default_graph_host")]
    pub graph_host: String,
    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl std::fmt::Debug for OutlookConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutlookConfig")
            .field("access_token", &"[REDACTED]")
            .field("graph_host", &self.graph_host)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_graph_host() -> String {
    "https://graph.microsoft.com".into()
}

const fn default_request_timeout_ms() -> u64 {
    15_000
}

impl OutlookConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Outlook config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.access_token.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "access_token must not be empty".into(),
            });
        }
        if self.graph_host.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "graph_host must not be empty".into(),
            });
        }
        validate_graph_host(&self.graph_host)?;
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.graph_host.trim().trim_end_matches('/').to_string()
    }
}

fn validate_graph_host(raw: &str) -> FcpResult<()> {
    let url = Url::parse(raw.trim()).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("graph_host must be a valid absolute URL: {error}"),
    })?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "graph_host must not include userinfo".into(),
        });
    }
    if url.query().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "graph_host must not include a query string".into(),
        });
    }
    if url.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "graph_host must not include a fragment".into(),
        });
    }
    if url.path() != "/" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "graph_host must not include a path".into(),
        });
    }

    let host = url.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "graph_host must include a host".into(),
    })?;
    let is_local_test_host =
        (cfg!(test) || cfg!(debug_assertions)) && matches!(host, "localhost" | "127.0.0.1");
    if !is_local_test_host && url.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "graph_host must use https for non-local hosts".into(),
        });
    }
    if !is_local_test_host && !ALLOWED_GRAPH_HOSTS.contains(&host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("graph_host `{host}` is not an allowed Microsoft Graph host"),
        });
    }

    Ok(())
}

impl std::fmt::Display for OutlookConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OutlookConfig {{ graph_host: {}, timeout: {}ms }}",
            self.graph_host, self.request_timeout_ms
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Value {
        serde_json::json!({ "access_token": "Bearer test-token-123" })
    }

    #[test]
    fn config_parses_with_defaults() {
        let config = OutlookConfig::from_value(valid_config()).unwrap();
        assert_eq!(config.graph_host, "https://graph.microsoft.com");
        assert_eq!(config.request_timeout_ms, 15_000);
    }

    #[test]
    fn config_rejects_empty_token() {
        let result = OutlookConfig::from_value(serde_json::json!({ "access_token": "  " }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_token() {
        let result = OutlookConfig::from_value(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let result = OutlookConfig::from_value(serde_json::json!({
            "access_token": "tok",
            "request_timeout_ms": 0
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_accepts_custom_graph_host() {
        let config = OutlookConfig::from_value(serde_json::json!({
            "access_token": "tok",
            "graph_host": "https://graph.microsoft.us"
        }))
        .unwrap();
        assert_eq!(config.graph_host, "https://graph.microsoft.us");
    }

    #[test]
    fn config_rejects_non_graph_remote_host() {
        let result = OutlookConfig::from_value(serde_json::json!({
            "access_token": "tok",
            "graph_host": "https://evil.example.com"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_remote_http_graph_host() {
        let result = OutlookConfig::from_value(serde_json::json!({
            "access_token": "tok",
            "graph_host": "http://graph.microsoft.com"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_graph_host_with_userinfo_query_fragment_or_path() {
        for graph_host in [
            "https://user:pass@graph.microsoft.com",
            "https://graph.microsoft.com?trace=1",
            "https://graph.microsoft.com#fragment",
            "https://graph.microsoft.com/v1.0",
        ] {
            let result = OutlookConfig::from_value(serde_json::json!({
                "access_token": "tok",
                "graph_host": graph_host
            }));
            assert!(result.is_err(), "{graph_host} must be rejected");
        }
    }

    #[test]
    fn config_accepts_localhost_graph_host_for_tests() {
        let config = OutlookConfig::from_value(serde_json::json!({
            "access_token": "tok",
            "graph_host": "http://localhost:8080"
        }));
        assert!(
            matches!(config.as_ref().map(OutlookConfig::base_url), Ok(base_url) if base_url == "http://localhost:8080"),
            "localhost test override should be accepted, got {config:?}"
        );
    }

    #[test]
    fn config_rejects_empty_graph_host() {
        let result = OutlookConfig::from_value(serde_json::json!({
            "access_token": "tok",
            "graph_host": "  "
        }));
        assert!(result.is_err());
    }

    #[test]
    fn base_url_trims_trailing_slash() {
        let config = OutlookConfig::from_value(serde_json::json!({
            "access_token": "tok",
            "graph_host": "https://graph.microsoft.com/"
        }))
        .unwrap();
        assert_eq!(config.base_url(), "https://graph.microsoft.com");
    }

    #[test]
    fn display_redacts_token() {
        let config = OutlookConfig::from_value(valid_config()).unwrap();
        let display = format!("{config}");
        assert!(!display.contains("test-token"));
        assert!(display.contains("graph.microsoft.com"));
    }

    #[test]
    fn config_accepts_custom_timeout() {
        let config = OutlookConfig::from_value(serde_json::json!({
            "access_token": "tok",
            "request_timeout_ms": 5000
        }))
        .unwrap();
        assert_eq!(config.request_timeout_ms, 5000);
    }

    #[test]
    fn default_graph_host_is_microsoft() {
        assert_eq!(default_graph_host(), "https://graph.microsoft.com");
    }

    #[test]
    fn default_timeout_is_15000() {
        assert_eq!(default_request_timeout_ms(), 15_000);
    }
}
