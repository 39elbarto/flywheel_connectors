//! Configuration types for the `Apple Notes` connector.

use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleNotesConfig {
    #[serde(default)]
    pub default_folder: Option<String>,
    #[serde(default = "default_osascript_path")]
    pub osascript_path: String,
}

fn default_osascript_path() -> String {
    "/usr/bin/osascript".to_string()
}

impl AppleNotesConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Apple Notes config: {error}"),
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
        let config =
            AppleNotesConfig::from_value(serde_json::json!({})).expect("config should parse");
        assert_eq!(config.osascript_path, "/usr/bin/osascript");
    }

    #[test]
    fn config_defaults_folder_to_none() {
        let config = AppleNotesConfig::from_value(serde_json::json!({})).unwrap();
        assert!(config.default_folder.is_none());
    }

    #[test]
    fn config_accepts_custom_folder() {
        let config = AppleNotesConfig::from_value(serde_json::json!({
            "default_folder": "Work"
        }))
        .unwrap();
        assert_eq!(config.default_folder.as_deref(), Some("Work"));
    }

    #[test]
    fn config_accepts_custom_osascript_path() {
        let config = AppleNotesConfig::from_value(serde_json::json!({
            "osascript_path": "/opt/bin/osascript"
        }))
        .unwrap();
        assert_eq!(config.osascript_path, "/opt/bin/osascript");
    }

    #[test]
    fn config_rejects_empty_osascript_path() {
        let result = AppleNotesConfig::from_value(serde_json::json!({
            "osascript_path": "  "
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_accepts_empty_json() {
        let config = AppleNotesConfig::from_value(serde_json::json!({}));
        assert!(config.is_ok());
    }
}
