//! Configuration types for the generic email connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    pub host: String,
    #[serde(default = "default_imap_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    #[serde(default)]
    pub from_name: Option<String>,
    #[serde(default = "default_true")]
    pub starttls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailGenericConfig {
    pub imap: ImapConfig,
    pub smtp: SmtpConfig,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

const fn default_true() -> bool {
    true
}

const fn default_imap_port() -> u16 {
    993
}

const fn default_smtp_port() -> u16 {
    587
}

const fn default_request_timeout_ms() -> u64 {
    15_000
}

impl EmailGenericConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid generic email config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FcpResult<()> {
        if self.imap.host.trim().is_empty() || self.smtp.host.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "imap.host and smtp.host must not be empty".into(),
            });
        }
        if self.imap.username.trim().is_empty()
            || self.imap.password.trim().is_empty()
            || self.smtp.username.trim().is_empty()
            || self.smtp.password.trim().is_empty()
            || self.smtp.from_address.trim().is_empty()
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "email credentials and from_address must not be empty".into(),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_successfully() {
        let config = EmailGenericConfig::from_value(serde_json::json!({
            "imap": {
                "host": "imap.example.com",
                "username": "user@example.com",
                "password": "secret"
            },
            "smtp": {
                "host": "smtp.example.com",
                "username": "user@example.com",
                "password": "secret",
                "from_address": "user@example.com"
            }
        }))
        .expect("config should parse");
        assert_eq!(config.imap.port, 993);
        assert_eq!(config.smtp.port, 587);
    }
}
