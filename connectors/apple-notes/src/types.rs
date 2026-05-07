//! Configuration types for the `Apple Notes` connector.

use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const DEFAULT_OSASCRIPT_PATH: &str = "/usr/bin/osascript";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleNotesConfig {
    #[serde(default)]
    pub default_folder: Option<String>,
    #[serde(default = "default_osascript_path")]
    pub osascript_path: String,
    /// Per-invocation timeout in seconds for the `osascript`
    /// subprocess. The default of 30s matches the H.1 production
    /// hardening bead's recommended bound (krxpn). Hitting the
    /// timeout kills the child via SIGKILL and surfaces
    /// [`crate::error::AppleNotesError::Timeout`].
    #[serde(default = "default_subprocess_timeout_secs")]
    pub subprocess_timeout_secs: u64,
}

fn default_osascript_path() -> String {
    DEFAULT_OSASCRIPT_PATH.to_string()
}

const fn default_subprocess_timeout_secs() -> u64 {
    30
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
        let raw = std::fs::read_to_string(&path).expect("Apple Notes manifest should be readable");
        fcp_manifest::ConnectorManifest::parse_str(&raw).expect("Apple Notes manifest parses")
    }

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
    fn config_rejects_custom_osascript_path() {
        let result = AppleNotesConfig::from_value(serde_json::json!({
            "osascript_path": "/opt/bin/osascript"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_osascript_path() {
        let result = AppleNotesConfig::from_value(serde_json::json!({
            "osascript_path": "  "
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_relative_osascript_path() {
        let result = AppleNotesConfig::from_value(serde_json::json!({
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
            let result = AppleNotesConfig::from_value(serde_json::json!({
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
            let result = AppleNotesConfig::from_value(serde_json::json!({
                "osascript_path": path
            }));
            assert!(result.is_err(), "{path:?} should be rejected");
        }
    }

    #[test]
    fn config_rejects_non_osascript_absolute_paths() {
        for path in ["/opt/bin/osascript-wrapper", "/usr/local/bin/osascript.sh"] {
            let result = AppleNotesConfig::from_value(serde_json::json!({
                "osascript_path": path
            }));
            assert!(result.is_err(), "{path} should be rejected");
        }
    }

    #[test]
    fn config_rejects_relative_components() {
        let result = AppleNotesConfig::from_value(serde_json::json!({
            "osascript_path": "/usr/bin/../bin/osascript"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn timeout_zero_rejected_at_config_parse() {
        let result = AppleNotesConfig::from_value(serde_json::json!({
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
        let config = AppleNotesConfig::from_value(serde_json::json!({}));
        assert!(config.is_ok());
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
            "Apple Notes uses a bounded connector-local osascript carveout"
        );
    }

    #[test]
    fn manifest_ai_hints_are_agent_actionable_and_redacted() {
        let manifest = parsed_manifest();
        let sensitive_markers = ["api_key", "password", "secret", "token", "@example.com"];
        for (operation_id, operation) in &manifest.provides.operations {
            assert!(
                !operation.ai_hints.when_to_use.trim().is_empty(),
                "{operation_id} must explain when to use the operation"
            );
            assert!(
                !operation.ai_hints.examples.is_empty(),
                "{operation_id} must include at least one synthetic example"
            );
            assert!(
                !operation.ai_hints.common_mistakes.is_empty(),
                "{operation_id} must document at least one concrete mistake"
            );
            for example in &operation.ai_hints.examples {
                let parsed = serde_json::from_str::<serde_json::Value>(example);
                assert!(
                    matches!(parsed.as_ref(), Ok(value) if value.is_object()),
                    "{operation_id} example should be a JSON object: {example}"
                );
                let lower = example.to_ascii_lowercase();
                for marker in sensitive_markers {
                    assert!(
                        !lower.contains(marker),
                        "{operation_id} example should not include sensitive marker {marker}"
                    );
                }
            }
        }
    }
}
