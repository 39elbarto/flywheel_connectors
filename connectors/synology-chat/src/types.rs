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
    ForwardedOutgoingWebhook,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SynologyChatReplySemantics {
    OutboundOnly,
    OutgoingWebhookResponse,
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
        let outgoing_token = self.outgoing_token.take();
        self.outgoing_token = outgoing_token
            .as_deref()
            .and_then(normalize_optional_secret);
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
    pub const fn outgoing_token_configured(&self) -> bool {
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

    /// # Panics
    ///
    /// Panics if `incoming_url` was not validated before building the delivery target.
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
        let origin = port.map_or_else(
            || format!("{}://{host}", parsed.scheme()),
            |port| format!("{}://{host}:{port}", parsed.scheme()),
        );
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
        let outgoing_token_configured = self.outgoing_token_configured();
        SynologyChatStateModel {
            delivery_target: self.delivery_target(),
            request_timeout_ms: self.request_timeout_ms,
            allow_insecure_ssl: self.allow_insecure_ssl,
            outgoing_token_configured,
            receive_path: if outgoing_token_configured {
                SynologyChatReceivePath::ForwardedOutgoingWebhook
            } else {
                SynologyChatReceivePath::Disabled
            },
            reply_semantics: if outgoing_token_configured {
                SynologyChatReplySemantics::OutgoingWebhookResponse
            } else {
                SynologyChatReplySemantics::OutboundOnly
            },
        }
    }
}

fn normalize_optional_secret(value: &str) -> Option<String> {
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

/// Inbound webhook payload from Synology Chat.
///
/// This represents the flexible shape of an incoming webhook callback
/// from Synology Chat (outgoing webhook integration). All fields are
/// optional because different Synology Chat versions and configurations
/// may include varying subsets.
#[derive(Debug, Clone, Deserialize)]
pub struct InboundWebhookPayload {
    /// The user ID who sent the message.
    pub user_id: Option<serde_json::Value>,
    /// The username who sent the message.
    pub username: Option<String>,
    /// The post ID.
    pub post_id: Option<serde_json::Value>,
    /// The channel ID.
    pub channel_id: Option<serde_json::Value>,
    /// Channel name.
    pub channel_name: Option<String>,
    /// Channel type (1 = group, 2 = DM, etc.).
    pub channel_type: Option<serde_json::Value>,
    /// The message text.
    pub text: Option<String>,
    /// Timestamp (milliseconds since epoch, as string or integer).
    pub timestamp: Option<serde_json::Value>,
    /// Token for verification against configured `outgoing_token`.
    pub token: Option<String>,
    /// Trigger word that matched.
    pub trigger_word: Option<String>,
    /// Thread ID (\"0\" or empty means top-level).
    pub thread_id: Option<serde_json::Value>,
    /// File URL attachment.
    pub file_url: Option<String>,
}

/// Normalized inbound event produced by `synology_chat.webhook.normalize`.
#[derive(Debug, Clone, Serialize)]
pub struct NormalizedInboundEvent {
    /// The event type, always `"inbound_webhook"`.
    pub event_type: String,
    /// Channel identifier (stringified).
    pub channel_id: Option<String>,
    /// Channel display name.
    pub channel_name: Option<String>,
    /// Sender user identifier (stringified).
    pub sender_id: Option<String>,
    /// Sender display name.
    pub sender_name: Option<String>,
    /// Message text.
    pub text: Option<String>,
    /// Timestamp (stringified, milliseconds since epoch).
    pub timestamp: Option<String>,
    /// Trigger word that matched.
    pub trigger_word: Option<String>,
    /// Whether the message is in a thread.
    pub is_threaded: bool,
    /// Thread ID if threaded.
    pub thread_id: Option<String>,
    /// File URL if present.
    pub file_url: Option<String>,
    /// Token verification result.
    pub token_verified: Option<bool>,
    /// Original raw payload for passthrough.
    pub raw: serde_json::Value,
}

/// Result of token verification for an inbound webhook payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenVerification {
    /// Token matched the configured `outgoing_token`.
    Verified,
    /// Token did not match the configured `outgoing_token`.
    Mismatch,
    /// No token was provided in the payload.
    MissingFromPayload,
    /// No `outgoing_token` is configured, so verification was skipped.
    NotConfigured,
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

    #[test]
    fn state_model_enables_forwarded_receive_path_when_outgoing_token_is_configured() {
        let config = SynologyChatConfig::from_value(serde_json::json!({
            "incoming_url": "https://nas.example.com/hooks/abcd1234efgh5678",
            "outgoing_token": "shared-secret"
        }))
        .expect("config should parse");
        let state_model = config.state_model();
        assert_eq!(
            state_model.reply_semantics,
            SynologyChatReplySemantics::OutgoingWebhookResponse
        );
        assert_eq!(
            state_model.receive_path,
            SynologyChatReceivePath::ForwardedOutgoingWebhook
        );
    }

    #[test]
    fn inbound_webhook_payload_deserializes_from_json() {
        let payload: InboundWebhookPayload = serde_json::from_value(serde_json::json!({
            "user_id": 4,
            "username": "mikael",
            "post_id": "146028888128",
            "channel_id": 34,
            "channel_name": "Labb",
            "channel_type": 1,
            "text": "Tjena",
            "timestamp": "1646827836131",
            "token": "shared-secret",
            "trigger_word": "Tjena",
            "thread_id": "0",
            "file_url": "https://nas.local/file.pdf"
        }))
        .expect("payload should deserialize");

        assert_eq!(payload.username.as_deref(), Some("mikael"));
        assert_eq!(payload.text.as_deref(), Some("Tjena"));
        assert_eq!(payload.token.as_deref(), Some("shared-secret"));
        assert_eq!(payload.trigger_word.as_deref(), Some("Tjena"));
        assert_eq!(
            payload.file_url.as_deref(),
            Some("https://nas.local/file.pdf")
        );
    }

    #[test]
    fn inbound_webhook_payload_handles_missing_optional_fields() {
        let payload: InboundWebhookPayload = serde_json::from_value(serde_json::json!({}))
            .expect("empty payload should deserialize");

        assert!(payload.user_id.is_none());
        assert!(payload.username.is_none());
        assert!(payload.post_id.is_none());
        assert!(payload.channel_id.is_none());
        assert!(payload.channel_name.is_none());
        assert!(payload.text.is_none());
        assert!(payload.timestamp.is_none());
        assert!(payload.token.is_none());
        assert!(payload.trigger_word.is_none());
        assert!(payload.thread_id.is_none());
        assert!(payload.file_url.is_none());
    }

    #[test]
    fn inbound_webhook_payload_accepts_string_ids() {
        let payload: InboundWebhookPayload = serde_json::from_value(serde_json::json!({
            "user_id": "user-99",
            "channel_id": "chan-1",
            "post_id": "post-42",
            "timestamp": "1700000000000"
        }))
        .expect("string IDs should deserialize");

        assert!(payload.user_id.is_some());
        assert!(payload.channel_id.is_some());
    }

    #[test]
    fn normalized_inbound_event_serializes_correctly() {
        let event = NormalizedInboundEvent {
            event_type: "inbound_webhook".into(),
            channel_id: Some("34".into()),
            channel_name: Some("Labb".into()),
            sender_id: Some("4".into()),
            sender_name: Some("mikael".into()),
            text: Some("Tjena".into()),
            timestamp: Some("1646827836131".into()),
            trigger_word: Some("Tjena".into()),
            is_threaded: false,
            thread_id: None,
            file_url: None,
            token_verified: Some(true),
            raw: serde_json::json!({}),
        };

        let serialized = serde_json::to_value(&event).expect("event should serialize");
        assert_eq!(serialized["event_type"], "inbound_webhook");
        assert_eq!(serialized["channel_id"], "34");
        assert_eq!(serialized["sender_name"], "mikael");
        assert_eq!(serialized["token_verified"], true);
        assert_eq!(serialized["is_threaded"], false);
    }

    #[test]
    fn token_verification_variants_are_distinct() {
        assert_ne!(TokenVerification::Verified, TokenVerification::Mismatch);
        assert_ne!(
            TokenVerification::Verified,
            TokenVerification::MissingFromPayload
        );
        assert_ne!(
            TokenVerification::Verified,
            TokenVerification::NotConfigured
        );
        assert_ne!(
            TokenVerification::Mismatch,
            TokenVerification::MissingFromPayload
        );
        assert_ne!(
            TokenVerification::Mismatch,
            TokenVerification::NotConfigured
        );
        assert_ne!(
            TokenVerification::MissingFromPayload,
            TokenVerification::NotConfigured
        );
    }
}
