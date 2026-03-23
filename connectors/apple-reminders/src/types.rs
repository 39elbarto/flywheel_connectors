//! Configuration types for the Apple Reminders connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleRemindersConfig {
    #[serde(default)]
    pub default_list: Option<String>,
    #[serde(default = "default_osascript_path")]
    pub osascript_path: String,
}

fn default_osascript_path() -> String {
    "/usr/bin/osascript".to_string()
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_osascript_path() {
        let config = AppleRemindersConfig::from_value(serde_json::json!({}))
            .expect("config should parse");
        assert_eq!(config.osascript_path, "/usr/bin/osascript");
    }
}

