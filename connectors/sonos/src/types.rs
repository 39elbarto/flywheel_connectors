//! Configuration types for the `Sonos` connector.

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

    #[test]
    fn config_defaults_timeout_to_10000() {
        let config = SonosConfig::from_value(serde_json::json!({
            "device_url": "http://speaker.local:1400"
        }))
        .unwrap();
        assert_eq!(config.request_timeout_ms, 10_000);
    }

    #[test]
    fn config_defaults_insecure_ssl_to_false() {
        let config = SonosConfig::from_value(serde_json::json!({
            "device_url": "http://speaker.local:1400"
        }))
        .unwrap();
        assert!(!config.allow_insecure_ssl);
    }

    #[test]
    fn config_accepts_https() {
        let config = SonosConfig::from_value(serde_json::json!({
            "device_url": "https://speaker.local:1443"
        }));
        assert!(config.is_ok());
    }

    #[test]
    fn config_rejects_ftp_scheme() {
        let result = SonosConfig::from_value(serde_json::json!({
            "device_url": "ftp://speaker.local"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_url() {
        let result = SonosConfig::from_value(serde_json::json!({
            "device_url": ""
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let result = SonosConfig::from_value(serde_json::json!({
            "device_url": "http://speaker.local:1400",
            "request_timeout_ms": 0
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_device_url() {
        let result = SonosConfig::from_value(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn normalized_url_trims_trailing_slash() {
        let config = SonosConfig::from_value(serde_json::json!({
            "device_url": "http://speaker.local:1400/"
        }))
        .unwrap();
        assert_eq!(config.normalized_device_url(), "http://speaker.local:1400");
    }

    #[test]
    fn normalized_url_trims_whitespace() {
        let config = SonosConfig::from_value(serde_json::json!({
            "device_url": "  http://speaker.local:1400  "
        }))
        .unwrap();
        assert_eq!(config.normalized_device_url(), "http://speaker.local:1400");
    }

    #[test]
    fn config_accepts_custom_timeout() {
        let config = SonosConfig::from_value(serde_json::json!({
            "device_url": "http://speaker.local:1400",
            "request_timeout_ms": 5000
        }))
        .unwrap();
        assert_eq!(config.request_timeout_ms, 5000);
    }
}
