//! Configuration types for the `Apple Reminders` connector.

use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleRemindersConfig {
    #[serde(default)]
    pub default_list: Option<String>,
    #[serde(default = "default_osascript_path")]
    pub osascript_path: String,
    /// Per-invocation timeout in seconds for the `osascript`
    /// subprocess. Default 30s per H.1 production hardening
    /// (krxpn). Hitting the timeout kills the child and surfaces
    /// [`crate::error::AppleRemindersError::Timeout`].
    #[serde(default = "default_subprocess_timeout_secs")]
    pub subprocess_timeout_secs: u64,
}

fn default_osascript_path() -> String {
    "/usr/bin/osascript".to_string()
}

const fn default_subprocess_timeout_secs() -> u64 {
    30
}

impl AppleRemindersConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Apple Reminders config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.osascript_path.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "osascript_path must not be empty".into(),
            });
        }
        if self.subprocess_timeout_secs == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "subprocess_timeout_secs must be > 0".into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_osascript_path() {
        let config =
            AppleRemindersConfig::from_value(serde_json::json!({})).expect("config should parse");
        assert_eq!(config.osascript_path, "/usr/bin/osascript");
    }

    #[test]
    fn config_defaults_list_to_none() {
        let config = AppleRemindersConfig::from_value(serde_json::json!({})).unwrap();
        assert!(config.default_list.is_none());
    }

    #[test]
    fn config_accepts_custom_list() {
        let config = AppleRemindersConfig::from_value(serde_json::json!({
            "default_list": "Work"
        }))
        .unwrap();
        assert_eq!(config.default_list.as_deref(), Some("Work"));
    }

    #[test]
    fn config_accepts_custom_osascript() {
        let config = AppleRemindersConfig::from_value(serde_json::json!({
            "osascript_path": "/opt/bin/osascript"
        }))
        .unwrap();
        assert_eq!(config.osascript_path, "/opt/bin/osascript");
    }

    #[test]
    fn config_rejects_empty_osascript_path() {
        let result = AppleRemindersConfig::from_value(serde_json::json!({
            "osascript_path": "  "
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_accepts_empty_json() {
        assert!(AppleRemindersConfig::from_value(serde_json::json!({})).is_ok());
    }
}
