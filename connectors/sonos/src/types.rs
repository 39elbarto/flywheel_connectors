//! Configuration types for the Sonos connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonosConfig {
    pub device_url: String,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub allow_insecure_ssl: bool,
}

const fn default_request_timeout_ms() -> u64 {
    10_000
}

impl SonosConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Sonos config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        let parsed =
            Url::parse(self.device_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid device_url: {error}"),
            })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "device_url must use http or https".into(),
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
    pub fn normalized_device_url(&self) -> String {
        self.device_url.trim().trim_end_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_successfully() {
        let config = SonosConfig::from_value(serde_json::json!({
            "device_url": "http://speaker.local:1400"
        }))
        .expect("config should parse");
        assert_eq!(config.normalized_device_url(), "http://speaker.local:1400");
    }
}
