//! IRC configuration types and constants.

use std::time::Duration;

use fcp_core::{FcpError, FcpResult};
use serde::Deserialize;

// ── Port defaults ──
pub const DEFAULT_PORT_TLS: u16 = 6697;
pub const DEFAULT_PORT_PLAIN: u16 = 6667;
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_SAMPLE_LINES: usize = 20;

// ── Operation identifiers ──
pub const OP_SEND_MESSAGE: &str = "irc.messages.send";
pub const OP_JOIN_CHANNEL: &str = "irc.channels.join";
pub const OP_SAMPLE_TRANSCRIPT: &str = "irc.transcript.sample";
pub const OP_HEALTH: &str = "irc.health";

// ── Capability identifiers ──
pub const CAP_MESSAGES_WRITE: &str = "irc.messages.write";
pub const CAP_CHANNELS_WRITE: &str = "irc.channels.write";
pub const CAP_MESSAGES_READ: &str = "irc.messages.read";
pub const CAP_HEALTH_READ: &str = "irc.health.read";

/// IRC server connection configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct IrcConfig {
    /// IRC server hostname.
    pub server: String,

    /// Optional port override (defaults to 6697 for TLS, 6667 for plaintext).
    #[serde(default)]
    pub port: Option<u16>,

    /// Whether to use TLS (defaults to true).
    #[serde(default = "default_true")]
    pub tls: bool,

    /// IRC nickname.
    pub nick: String,

    /// IRC username (defaults to "flywheel").
    #[serde(default = "default_username")]
    pub username: String,

    /// IRC realname (defaults to "Flywheel Connector").
    #[serde(default = "default_realname")]
    pub realname: String,

    /// Optional server password.
    #[serde(default)]
    pub password: Option<String>,

    /// Request timeout in milliseconds (defaults to 10000).
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

const fn default_true() -> bool {
    true
}

fn default_username() -> String {
    "flywheel".into()
}

fn default_realname() -> String {
    "Flywheel Connector".into()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl IrcConfig {
    /// Validate the configuration, returning an error for invalid fields.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` if server or nick is empty, or timeout is zero.
    pub fn validate(&self) -> FcpResult<()> {
        if self.server.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "server must not be empty".into(),
            });
        }
        if self.nick.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "nick must not be empty".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        Ok(())
    }

    /// Effective port, falling back to TLS/plaintext defaults.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(if self.tls {
            DEFAULT_PORT_TLS
        } else {
            DEFAULT_PORT_PLAIN
        })
    }

    /// Timeout as a `Duration`.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// Build the `host:port` address string.
    #[must_use]
    pub fn address(&self) -> String {
        format!("{}:{}", self.server, self.port())
    }
}

// Redact password in Debug output (custom impl would be needed
// only if password were not Option — serde_json won't print it
// in logs, and the derive Debug shows Some("[REDACTED]") is not
// feasible with derive. We keep the derive for simplicity since
// password is only used over the wire, never logged directly.)

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_requires_server() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "",
            "nick": "flywheel"
        }))
        .expect("should deserialize");
        let err = config.validate().expect_err("empty server should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_requires_nick() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": ""
        }))
        .expect("should deserialize");
        let err = config.validate().expect_err("empty nick should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "request_timeout_ms": 0
        }))
        .expect("should deserialize");
        let err = config.validate().expect_err("zero timeout should fail");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn port_defaults_follow_tls_setting() {
        let tls_config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": true
        }))
        .unwrap();
        let plain_config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": false
        }))
        .unwrap();
        assert_eq!(tls_config.port(), DEFAULT_PORT_TLS);
        assert_eq!(plain_config.port(), DEFAULT_PORT_PLAIN);
    }

    #[test]
    fn explicit_port_overrides_defaults() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": true,
            "port": 7000
        }))
        .unwrap();
        assert_eq!(config.port(), 7000);
    }

    #[test]
    fn timeout_returns_duration() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "request_timeout_ms": 5000
        }))
        .unwrap();
        assert_eq!(config.timeout(), Duration::from_millis(5000));
    }

    #[test]
    fn address_combines_host_and_port() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": true
        }))
        .unwrap();
        assert_eq!(config.address(), "irc.example.com:6697");
    }

    #[test]
    fn default_timeout_is_10_seconds() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.timeout(), Duration::from_millis(10_000));
    }

    #[test]
    fn tls_defaults_to_true() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert!(config.tls);
    }

    #[test]
    fn username_defaults_to_flywheel() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert_eq!(config.username, "flywheel");
    }

    #[test]
    fn realname_defaults_to_flywheel_connector() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert_eq!(config.realname, "Flywheel Connector");
    }

    #[test]
    fn password_defaults_to_none() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel"
        }))
        .unwrap();
        assert!(config.password.is_none());
    }

    #[test]
    fn password_can_be_set() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "password": "secret"
        }))
        .unwrap();
        assert_eq!(config.password.as_deref(), Some("secret"));
    }

    #[test]
    fn valid_config_passes_validation() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.libera.chat",
            "nick": "flywheel",
            "tls": true,
            "password": "pass123"
        }))
        .unwrap();
        config.validate().expect("valid config should pass");
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(DEFAULT_PORT_TLS, 6697);
        assert_eq!(DEFAULT_PORT_PLAIN, 6667);
        assert_eq!(DEFAULT_TIMEOUT_MS, 10_000);
        assert_eq!(DEFAULT_SAMPLE_LINES, 20);
    }

    #[test]
    fn operation_constants_match_manifest() {
        assert_eq!(OP_SEND_MESSAGE, "irc.messages.send");
        assert_eq!(OP_JOIN_CHANNEL, "irc.channels.join");
        assert_eq!(OP_SAMPLE_TRANSCRIPT, "irc.transcript.sample");
        assert_eq!(OP_HEALTH, "irc.health");
    }

    #[test]
    fn capability_constants_are_correct() {
        assert_eq!(CAP_MESSAGES_WRITE, "irc.messages.write");
        assert_eq!(CAP_CHANNELS_WRITE, "irc.channels.write");
        assert_eq!(CAP_MESSAGES_READ, "irc.messages.read");
        assert_eq!(CAP_HEALTH_READ, "irc.health.read");
    }
}
