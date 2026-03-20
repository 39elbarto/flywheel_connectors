//! Nextcloud Talk connector configuration.

#![allow(clippy::missing_errors_doc)]

use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::{FcpError, FcpResult};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Nextcloud Talk connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextcloudTalkConfig {
    /// Base server URL, including any deployment subpath.
    pub server_url: String,

    /// Authentication mode for the OCS and Talk APIs.
    pub auth: NextcloudTalkAuth,

    /// Default request timeout for outbound requests.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,

    /// Long-poll timeout passed to the chat API.
    #[serde(default = "default_long_poll_timeout_secs")]
    pub long_poll_timeout_secs: u64,

    /// Shared retry policy for outbound request helpers.
    #[serde(default)]
    pub retry: HttpRetryConfig,

    /// Optional forced response language for API requests.
    #[serde(default)]
    pub force_language: Option<String>,
}

/// Authentication strategy for the Nextcloud Talk connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NextcloudTalkAuth {
    /// Basic authentication using the account password.
    Basic { username: String, password: String },

    /// Basic authentication using a recommended app password.
    AppPassword {
        username: String,
        app_password: String,
    },

    /// Bearer-token authentication for OIDC style deployments.
    BearerToken { access_token: String },

    /// Host-managed credential injection.
    CredentialId { credential_id: String },
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

const fn default_long_poll_timeout_secs() -> u64 {
    30
}

impl NextcloudTalkConfig {
    /// Parse and validate connector configuration from JSON.
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Nextcloud Talk config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration invariants.
    pub fn validate(&self) -> FcpResult<()> {
        let parsed =
            Url::parse(self.server_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid server_url: {error}"),
            })?;

        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "server_url must use http or https".into(),
            });
        }

        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "server_url must not contain a query string or fragment".into(),
            });
        }

        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }

        if !(1..=60).contains(&self.long_poll_timeout_secs) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "long_poll_timeout_secs must be between 1 and 60".into(),
            });
        }

        if let Some(force_language) = &self.force_language {
            validate_non_empty("force_language", force_language)?;
        }

        self.auth.validate()?;
        Ok(())
    }

    /// Return the normalized server URL without a trailing slash.
    #[must_use]
    pub fn normalized_server_url(&self) -> String {
        self.server_url.trim().trim_end_matches('/').to_string()
    }
}

impl NextcloudTalkAuth {
    /// Return a stable label for diagnostics.
    #[must_use]
    pub const fn mode_label(&self) -> &'static str {
        match self {
            Self::Basic { .. } => "basic",
            Self::AppPassword { .. } => "app_password",
            Self::BearerToken { .. } => "bearer_token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Validate the selected authentication mode.
    pub fn validate(&self) -> FcpResult<()> {
        match self {
            Self::Basic { username, password } => {
                validate_non_empty("auth.username", username)?;
                validate_non_empty("auth.password", password)?;
            }
            Self::AppPassword {
                username,
                app_password,
            } => {
                validate_non_empty("auth.username", username)?;
                validate_non_empty("auth.app_password", app_password)?;
            }
            Self::BearerToken { access_token } => {
                validate_non_empty("auth.access_token", access_token)?;
            }
            Self::CredentialId { credential_id } => {
                validate_non_empty("auth.credential_id", credential_id)?;
            }
        }
        Ok(())
    }
}

fn validate_non_empty(field: &str, value: &str) -> FcpResult<()> {
    if value.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_app_password_config() {
        let config = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "app_password",
                "username": "alice",
                "app_password": "secret"
            }
        }))
        .expect("config should parse");

        assert_eq!(config.normalized_server_url(), "https://cloud.example.com");
        assert_eq!(config.long_poll_timeout_secs, 30);
        assert!(matches!(config.auth, NextcloudTalkAuth::AppPassword { .. }));
    }

    #[test]
    fn reject_invalid_long_poll_timeout() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            },
            "long_poll_timeout_secs": 0
        }))
        .expect_err("timeout must be validated");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn reject_server_url_with_query_string() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com?foo=bar",
            "auth": {
                "mode": "bearer_token",
                "access_token": "oidc"
            }
        }))
        .expect_err("server_url must reject query strings");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn reject_blank_force_language() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            },
            "force_language": "   "
        }))
        .expect_err("blank force_language must be rejected");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn normalize_server_url_trims_whitespace_and_trailing_slash() {
        let config = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "  https://cloud.example.com/subdir/  ",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            }
        }))
        .expect("config should parse");

        assert_eq!(
            config.normalized_server_url(),
            "https://cloud.example.com/subdir"
        );
    }
}
