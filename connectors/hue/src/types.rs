//! Configuration types for the `Hue` connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HueConfig {
    pub bridge_url: String,
    pub app_key: String,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub allow_insecure_ssl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SetLightStateInput {
    pub light_id: String,
    pub on: bool,
    #[serde(default)]
    pub brightness: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecallSceneInput {
    pub scene_id: String,
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
        let is_loopback_http = parsed.scheme() == "http"
            && match parsed.host() {
                Some(Host::Domain(host)) => host == "localhost",
                Some(Host::Ipv4(addr)) => addr.is_loopback(),
                Some(Host::Ipv6(addr)) => addr.is_loopback(),
                None => false,
            };
        if parsed.scheme() != "https" && !is_loopback_http {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message:
                    "bridge_url must use https (plain http is only allowed for localhost test endpoints)"
                        .into(),
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

    #[must_use]
    pub fn uses_plain_http_for_local_testing(&self) -> bool {
        self.normalized_bridge_url().starts_with("http://")
    }
}

impl SetLightStateInput {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let input: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid hue.set_light_state input: {error}"),
            })?;
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.light_id.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "light_id must not be empty".into(),
            });
        }
        if let Some(brightness) = self.brightness {
            if !brightness.is_finite() || !(0.0..=100.0).contains(&brightness) {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "brightness must be between 0 and 100".into(),
                });
            }
        }
        Ok(())
    }
}

impl RecallSceneInput {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let input: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid hue.recall_scene input: {error}"),
            })?;
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.scene_id.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "scene_id must not be empty".into(),
            });
        }
        Ok(())
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

    #[test]
    fn config_rejects_http_bridge_url() {
        let error = HueConfig::from_value(serde_json::json!({
            "bridge_url": "http://bridge.local",
            "app_key": "app-key"
        }))
        .expect_err("http bridge url must fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_allows_http_loopback_for_tests() {
        let config = HueConfig::from_value(serde_json::json!({
            "bridge_url": "http://127.0.0.1:8080",
            "app_key": "app-key"
        }))
        .expect("loopback http should be allowed for tests");
        assert!(config.uses_plain_http_for_local_testing());
    }

    #[test]
    fn set_light_state_input_rejects_out_of_range_brightness() {
        let error = SetLightStateInput::from_value(serde_json::json!({
            "light_id": "light-1",
            "on": true,
            "brightness": 101.0
        }))
        .expect_err("brightness above 100 must fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn recall_scene_input_rejects_blank_scene_id() {
        let error = RecallSceneInput::from_value(serde_json::json!({
            "scene_id": " "
        }))
        .expect_err("blank scene id must fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
