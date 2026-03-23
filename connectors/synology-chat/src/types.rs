//! Configuration types for the Synology Chat connector.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 15_000;
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 300_000;

#[derive(Clone, Serialize, Deserialize)]
pub struct SynologyChatConfig {
    incoming_url: String,
    #[serde(default)]
    outgoing_token: Option<String>,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default)]
    allow_insecure_ssl: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SynologyChatDeliveryMode {
    IncomingWebhook,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SynologyChatReceivePath {
    Disabled,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SynologyChatReplySemantics {
    OutboundOnly,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SynologyChatDeliveryTarget {
    pub mode: SynologyChatDeliveryMode,
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub origin: String,
    pub path_hint: String,
    pub incoming_url_redacted: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SynologyChatStateModel {
    pub delivery_target: SynologyChatDeliveryTarget,
    pub request_timeout_ms: u64,
    pub allow_insecure_ssl: bool,
    pub outgoing_token_configured: bool,
    pub receive_path: SynologyChatReceivePath,
    pub reply_semantics: SynologyChatReplySemantics,
}

impl std::fmt::Debug for SynologyChatConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynologyChatConfig")
            .field("incoming_url", &self.incoming_url)
            .field(
                "outgoing_token",
                &self.outgoing_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("allow_insecure_ssl", &self.allow_insecure_ssl)
            .finish()
    }
}

const fn default_request_timeout_ms() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_MS
}

impl SynologyChatConfig {
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Synology Chat config: {error}"),
            })?;
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    fn normalize(&mut self) {
        self.incoming_url = self.incoming_url.trim().to_string();
        self.outgoing_token = self
            .outgoing_token
            .take()
            .and_then(|token| normalize_optional_secret(token));
    }

    pub fn validate(&self) -> FcpResult<()> {
        let parsed = self.parse_incoming_url()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "incoming_url must use http or https".into(),
            });
        }
        if parsed.host_str().is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "incoming_url must include a host".into(),
            });
        }
        if parsed.fragment().is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "incoming_url must not include a fragment".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        if self.request_timeout_ms > MAX_REQUEST_TIMEOUT_MS {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "request_timeout_ms must be less than or equal to {MAX_REQUEST_TIMEOUT_MS}"
                ),
            });
        }
        Ok(())
    }

    fn parse_incoming_url(&self) -> FcpResult<Url> {
        Url::parse(&self.incoming_url).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid incoming_url: {error}"),
        })
    }

    #[must_use]
    pub fn incoming_url(&self) -> &str {
        &self.incoming_url
    }

    #[must_use]
    pub fn outgoing_token(&self) -> Option<&str> {
        self.outgoing_token.as_deref()
    }

    #[must_use]
    pub fn outgoing_token_configured(&self) -> bool {
        self.outgoing_token.is_some()
    }

    #[must_use]
    pub const fn request_timeout_ms(&self) -> u64 {
        self.request_timeout_ms
    }

    #[must_use]
    pub const fn allow_insecure_ssl(&self) -> bool {
        self.allow_insecure_ssl
    }

    #[must_use]
    pub fn normalized_incoming_url(&self) -> String {
        self.incoming_url.clone()
    }

    #[must_use]
    pub fn delivery_target(&self) -> SynologyChatDeliveryTarget {
        let parsed = self
            .parse_incoming_url()
            .expect("incoming_url must already be validated");
        let host = parsed
            .host_str()
            .expect("incoming_url must already have a host")
            .to_string();
        let port = parsed.port_or_known_default();
        let origin = match port {
            Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        };
        let path_hint = redact_path(parsed.path());
        let incoming_url_redacted = format!("{origin}{path_hint}");
        SynologyChatDeliveryTarget {
            mode: SynologyChatDeliveryMode::IncomingWebhook,
            scheme: parsed.scheme().to_string(),
            host,
            port,
            origin,
            path_hint,
            incoming_url_redacted,
        }
    }

    #[must_use]
    pub fn state_model(&self) -> SynologyChatStateModel {
        SynologyChatStateModel {
            delivery_target: self.delivery_target(),
            request_timeout_ms: self.request_timeout_ms,
            allow_insecure_ssl: self.allow_insecure_ssl,
            outgoing_token_configured: self.outgoing_token_configured(),
            receive_path: SynologyChatReceivePath::Disabled,
            reply_semantics: SynologyChatReplySemantics::OutboundOnly,
        }
    }
}

fn normalize_optional_secret(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn redact_path(path: &str) -> String {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    match segments.as_slice() {
        [] => "/".to_string(),
        [segment] if !looks_secret(segment) => format!("/{segment}"),
        [segment] => format!("/{}/...", redact_segment(segment)),
        [first, ..] => format!("/{first}/..."),
    }
}

fn redact_segment(segment: &str) -> String {
    if looks_secret(segment) {
        "[redacted]".to_string()
    } else {
        segment.to_string()
    }
}

fn looks_secret(segment: &str) -> bool {
    segment.len() >= 16
        && segment.bytes().any(|byte| byte.is_ascii_alphabetic())
        && segment.bytes().any(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_accepts_https_url() {
        let config = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/webapi/entry.cgi"
        }))
        .expect("config should parse");
        assert!(config.outgoing_token().is_none());
        let state_model = config.state_model();
        assert_eq!(state_model.delivery_target.host, "nas.example.com");
        assert_eq!(state_model.delivery_target.path_hint, "/webapi/...");
    }

    #[test]
    fn config_rejects_empty_timeout() {
        let error = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/webapi/entry.cgi",
            "request_timeout_ms": 0
        }))
        .expect_err("timeout must be validated");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_redacts_secret_in_debug_output() {
        let config = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/hooks/abcd1234efgh5678",
            "outgoing_token": "super-secret"
        }))
        .expect("config should parse");
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn config_normalizes_blank_outgoing_token() {
        let config = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/webhook",
            "outgoing_token": "   "
        }))
        .expect("config should parse");
        assert_eq!(config.outgoing_token(), None);
        assert!(!config.outgoing_token_configured());
    }

    #[test]
    fn config_rejects_fragment() {
        let error = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/webhook#secret"
        }))
        .expect_err("fragment must be rejected");
        match error {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("must not include a fragment"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_excessive_timeout() {
        let error = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/webhook",
            "request_timeout_ms": MAX_REQUEST_TIMEOUT_MS + 1
        }))
        .expect_err("timeout must be bounded");
        match error {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("less than or equal"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn state_model_redacts_secret_path_segments() {
        let config = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/hooks/abcd1234efgh5678"
        }))
        .expect("config should parse");
        let state_model = config.state_model();
        assert_eq!(
            state_model.delivery_target.incoming_url_redacted,
            "https://nas.example.com:443/hooks/..."
        );
        assert_eq!(
            state_model.reply_semantics,
            SynologyChatReplySemantics::OutboundOnly
        );
        assert_eq!(state_model.receive_path, SynologyChatReceivePath::Disabled);
    }
}
