//! Configuration types for the `Apple Reminders` connector.

use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const DEFAULT_OSASCRIPT_PATH: &str = "/usr/bin/osascript";

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
    DEFAULT_OSASCRIPT_PATH.to_string()
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
        validate_osascript_path(&self.osascript_path)?;
        if self.subprocess_timeout_secs == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "subprocess_timeout_secs must be > 0".into(),
            });
        }
        Ok(())
    }
}

fn invalid_osascript_path(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn validate_osascript_path(raw: &str) -> FcpResult<()> {
    if raw.trim().is_empty() {
        return Err(invalid_osascript_path("osascript_path must not be empty"));
    }
    if raw.trim() != raw || raw.chars().any(char::is_whitespace) {
        return Err(invalid_osascript_path(
            "osascript_path must be a single absolute path with no whitespace",
        ));
    }
    if raw != DEFAULT_OSASCRIPT_PATH {
        return Err(invalid_osascript_path(format!(
            "osascript_path must be the canonical {DEFAULT_OSASCRIPT_PATH}; executable overrides are not allowed"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn parsed_manifest() -> fcp_manifest::ConnectorManifest {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw =
            std::fs::read_to_string(&path).expect("Apple Reminders manifest should be readable");
        fcp_manifest::ConnectorManifest::parse_str(&raw).expect("Apple Reminders manifest parses")
    }

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
    fn config_rejects_custom_osascript_path() {
        let result = AppleRemindersConfig::from_value(serde_json::json!({
            "osascript_path": "/opt/bin/osascript"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_osascript_path() {
        let result = AppleRemindersConfig::from_value(serde_json::json!({
            "osascript_path": "  "
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_relative_osascript_path() {
        let result = AppleRemindersConfig::from_value(serde_json::json!({
            "osascript_path": "osascript"
        }));

        assert!(
            matches!(
                result,
                Err(FcpError::InvalidRequest { ref message, .. })
                    if message.contains("must be the canonical")
            ),
            "expected canonical path error, got {result:?}"
        );
    }

    #[test]
    fn config_rejects_command_carrier_paths() {
        for path in [
            "/usr/bin/env",
            "/usr/bin/sudo",
            "/usr/bin/doas",
            "/usr/bin/command",
            "/usr/bin/builtin",
            "/usr/bin/exec",
            "/usr/bin/source",
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
        ] {
            let result = AppleRemindersConfig::from_value(serde_json::json!({
                "osascript_path": path
            }));
            assert!(result.is_err(), "{path} should be rejected");
        }
    }

    #[test]
    fn config_rejects_suspicious_multitoken_paths() {
        for path in [
            "/usr/bin/env osascript",
            "/usr/bin/osascript --",
            "/usr/bin/osascript\n--bad",
            " /usr/bin/osascript",
            "/usr/bin/osascript ",
        ] {
            let result = AppleRemindersConfig::from_value(serde_json::json!({
                "osascript_path": path
            }));
            assert!(result.is_err(), "{path:?} should be rejected");
        }
    }

    #[test]
    fn config_rejects_non_osascript_absolute_paths() {
        for path in ["/opt/bin/osascript-wrapper", "/usr/local/bin/osascript.sh"] {
            let result = AppleRemindersConfig::from_value(serde_json::json!({
                "osascript_path": path
            }));
            assert!(result.is_err(), "{path} should be rejected");
        }
    }

    #[test]
    fn config_rejects_relative_components() {
        let result = AppleRemindersConfig::from_value(serde_json::json!({
            "osascript_path": "/usr/bin/../bin/osascript"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn timeout_zero_rejected_at_config_parse() {
        let result = AppleRemindersConfig::from_value(serde_json::json!({
            "subprocess_timeout_secs": 0
        }));

        assert!(
            matches!(
                result,
                Err(FcpError::InvalidRequest { code: 1003, ref message })
                    if message.contains("subprocess_timeout_secs must be > 0")
            ),
            "expected InvalidRequest timeout error, got {result:?}"
        );
    }

    #[test]
    fn config_accepts_empty_json() {
        assert!(AppleRemindersConfig::from_value(serde_json::json!({})).is_ok());
    }

    #[test]
    fn manifest_forbids_ambient_exec_and_privileged_capabilities() {
        let manifest = parsed_manifest();
        let forbidden = &manifest.capabilities.forbidden;
        for capability in [
            "network.listen",
            "network.outbound",
            "system.exec",
            "system.privileged",
        ] {
            assert!(
                forbidden.iter().any(|item| item.as_str() == capability),
                "{capability} must be explicitly forbidden"
            );
            assert!(
                !manifest
                    .capabilities
                    .required
                    .iter()
                    .chain(manifest.capabilities.optional.iter())
                    .any(|item| item.as_str() == capability),
                "{capability} must not be granted"
            );
        }
        assert!(
            !manifest.sandbox.deny_exec,
            "Apple Reminders uses a bounded connector-local osascript carveout"
        );
    }
}
