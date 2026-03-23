//! Configuration types for the Synology Chat connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynologyChatConfig {
    pub incoming_url: String,
    #[serde(default)]
    pub outgoing_token: Option<String>,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub allow_insecure_ssl: bool,
}

const fn default_request_timeout_ms() -> u64 {
    15_000
}

impl SynologyChatConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Synology Chat config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        let parsed =
            Url::parse(self.incoming_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid incoming_url: {error}"),
            })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "incoming_url must use http or https".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn normalized_incoming_url(&self) -> String {
        self.incoming_url.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_accepts_https_url() {
        let config = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/webapi/entry.cgi"
        }))
        .expect("config should parse");
        assert!(config.outgoing_token.is_none());
    }

    #[test]
    fn config_rejects_empty_timeout() {
        let error = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/webapi/entry.cgi",
            "request_timeout_ms": 0
        }))
        .expect_err("timeout must be validated");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
