//! Configuration and helper types for the Google Places connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GooglePlacesConfig {
    pub api_key: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub default_field_mask: Option<String>,
}

const fn default_request_timeout_ms() -> u64 {
    15_000
}

fn default_base_url() -> String {
    "https://places.googleapis.com".to_string()
}

impl GooglePlacesConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Google Places config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.api_key.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "api_key must not be empty".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        let parsed =
            Url::parse(self.base_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid base_url: {error}"),
            })?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must use http or https".into(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn normalized_base_url(&self) -> String {
        self.base_url.trim().trim_end_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_and_normalizes() {
        let config = GooglePlacesConfig::from_value(serde_json::json!({
            "api_key": "abc",
            "base_url": "https://places.googleapis.com/"
        }))
        .expect("config should parse");
        assert_eq!(
            config.normalized_base_url(),
            "https://places.googleapis.com"
        );
    }

    #[test]
    fn config_rejects_blank_api_key() {
        let error = GooglePlacesConfig::from_value(serde_json::json!({
            "api_key": " "
        }))
        .expect_err("blank api key must fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
