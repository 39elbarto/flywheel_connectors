//! Configuration types for the `Hue` connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HueConfig {
    pub bridge_url: String,
    pub app_key: String,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub allow_insecure_ssl: bool,
}

const fn default_request_timeout_ms() -> u64 {
    10_000
}

impl HueConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Hue config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        let parsed =
            Url::parse(self.bridge_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid bridge_url: {error}"),
            })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "bridge_url must use http or https".into(),
            });
        }
        if self.app_key.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "app_key must not be empty".into(),
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
    pub fn normalized_bridge_url(&self) -> String {
        self.bridge_url.trim().trim_end_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_successfully() {
        let config = HueConfig::from_value(serde_json::json!({
            "bridge_url": "https://bridge.local",
            "app_key": "app-key"
        }))
        .expect("config should parse");
        assert_eq!(config.normalized_bridge_url(), "https://bridge.local");
    }

    #[test]
    fn config_rejects_blank_app_key() {
        let error = HueConfig::from_value(serde_json::json!({
            "bridge_url": "https://bridge.local",
            "app_key": " "
        }))
        .expect_err("blank app key must fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
