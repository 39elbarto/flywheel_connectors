//! Configuration types for the generic email connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    pub host: String,
    #[serde(default = "default_imap_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub tls: bool,
}

impl std::fmt::Debug for ImapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("tls", &self.tls)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("from_address", &self.from_address)
            .field("from_name", &self.from_name)
            .field("starttls", &self.starttls)
            .finish()
    }
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

    fn valid_config_json() -> Value {
        serde_json::json!({
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
        })
    }

    #[test]
    fn config_parses_successfully() {
        let config =
            EmailGenericConfig::from_value(valid_config_json()).expect("config should parse");
        assert_eq!(config.imap.port, 993);
        assert_eq!(config.smtp.port, 587);
    }

    #[test]
    fn config_defaults_imap_port_to_993() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert_eq!(config.imap.port, 993);
    }

    #[test]
    fn config_defaults_smtp_port_to_587() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert_eq!(config.smtp.port, 587);
    }

    #[test]
    fn config_defaults_tls_to_true() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert!(config.imap.tls);
    }

    #[test]
    fn config_defaults_starttls_to_true() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert!(config.smtp.starttls);
    }

    #[test]
    fn config_defaults_timeout_to_15000() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert_eq!(config.request_timeout_ms, 15_000);
    }

    #[test]
    fn config_accepts_custom_ports() {
        let config = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "port": 143, "username": "u", "password": "p" },
            "smtp": { "host": "h", "port": 25, "username": "u", "password": "p", "from_address": "a@b.com" }
        })).unwrap();
        assert_eq!(config.imap.port, 143);
        assert_eq!(config.smtp.port, 25);
    }

    #[test]
    fn config_rejects_empty_imap_host() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "  ", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_smtp_host() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "  ", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_imap_username() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "  ", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_imap_password() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "  " },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_smtp_from_address() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "  " }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" },
            "request_timeout_ms": 0
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_imap() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_smtp() {
        let result = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" }
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_accepts_optional_from_name() {
        let config = EmailGenericConfig::from_value(serde_json::json!({
            "imap": { "host": "h", "username": "u", "password": "p" },
            "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com", "from_name": "Test User" }
        })).unwrap();
        assert_eq!(config.smtp.from_name.as_deref(), Some("Test User"));
    }

    #[test]
    fn config_from_name_defaults_to_none() {
        let config = EmailGenericConfig::from_value(valid_config_json()).unwrap();
        assert!(config.smtp.from_name.is_none());
    }
}
