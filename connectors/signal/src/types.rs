//! Signal messenger API types for the signal-cli REST daemon.
//!
//! Covers daemon-mode message structures, request/response payloads, and
//! connector configuration.

use fcp_sdk::prelude::{FcpError, FcpResult};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Signal connector configuration.
#[derive(Clone, Deserialize)]
pub struct SignalConfig {
    /// Base URL for the signal-cli REST daemon.
    #[serde(default = "default_daemon_url")]
    pub daemon_url: String,

    /// Registered phone number in E.164 format (e.g. +15551234567).
    pub phone_number: String,

    /// Trust mode for identity keys.
    #[serde(default = "default_trust_mode")]
    pub trust_mode: TrustMode,

    /// Optional signal-cli data directory hint for operators.
    #[serde(default)]
    pub data_dir: Option<String>,

    /// Receive polling timeout in milliseconds.
    #[serde(default = "default_receive_timeout_ms")]
    pub receive_timeout_ms: u64,

    /// Receive-loop polling cadence in milliseconds.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,

    /// Maximum reconnection backoff in milliseconds after daemon failures.
    #[serde(default = "default_max_reconnect_delay_ms")]
    pub max_reconnect_delay_ms: u64,

    /// Background health-check cadence in milliseconds while connected.
    #[serde(default = "default_health_check_interval_ms")]
    pub health_check_interval_ms: u64,

    /// Directory for storing downloaded attachments.
    #[serde(default)]
    pub attachment_dir: Option<String>,

    /// Maximum attachment size accepted by the bridge in bytes.
    #[serde(default = "default_max_attachment_bytes")]
    pub max_attachment_bytes: u64,

    /// HTTP retry configuration.
    #[serde(default)]
    pub retry: fcp_sdk::migration::HttpRetryConfig,

    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl std::fmt::Debug for SignalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_phone = if self.phone_number.len() >= 4 {
            format!("****{}", &self.phone_number[self.phone_number.len() - 4..])
        } else {
            "****".to_string()
        };
        f.debug_struct("SignalConfig")
            .field("daemon_url", &self.daemon_url)
            .field("phone_number", &redacted_phone)
            .field("trust_mode", &self.trust_mode)
            .field("data_dir", &self.data_dir)
            .field("receive_timeout_ms", &self.receive_timeout_ms)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("max_reconnect_delay_ms", &self.max_reconnect_delay_ms)
            .field("health_check_interval_ms", &self.health_check_interval_ms)
            .field("attachment_dir", &self.attachment_dir)
            .field("max_attachment_bytes", &self.max_attachment_bytes)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

/// Trust mode for Signal identity keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Only trust identities that are explicitly verified.
    OnFirstUse,
    /// Trust all identities automatically.
    Always,
    /// Never trust unverified identities.
    Never,
}

fn default_daemon_url() -> String {
    "http://localhost:8080".into()
}

const fn default_trust_mode() -> TrustMode {
    TrustMode::OnFirstUse
}

const fn default_receive_timeout_ms() -> u64 {
    10_000
}

const fn default_poll_interval_ms() -> u64 {
    5_000
}

const fn default_max_reconnect_delay_ms() -> u64 {
    60_000
}

const fn default_health_check_interval_ms() -> u64 {
    30_000
}

const fn default_max_attachment_bytes() -> u64 {
    100 * 1024 * 1024
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

impl SignalConfig {
    /// Parse and validate connector configuration from JSON.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when the JSON shape is invalid or any
    /// configuration invariant fails validation.
    pub fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Signal config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when the daemon URL, phone number, or
    /// timeout/path settings are invalid.
    pub fn validate(&self) -> FcpResult<()> {
        let parsed =
            Url::parse(self.daemon_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid daemon_url: {error}"),
            })?;

        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "daemon_url must use http or https".into(),
            });
        }

        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "daemon_url must not contain a query string or fragment".into(),
            });
        }

        validate_e164_number("phone_number", &self.phone_number)?;

        if self.receive_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "receive_timeout_ms must be greater than zero".into(),
            });
        }

        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }

        if self.poll_interval_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "poll_interval_ms must be greater than zero".into(),
            });
        }

        if self.max_reconnect_delay_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "max_reconnect_delay_ms must be greater than zero".into(),
            });
        }

        if self.health_check_interval_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "health_check_interval_ms must be greater than zero".into(),
            });
        }

        if self.max_attachment_bytes == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "max_attachment_bytes must be greater than zero".into(),
            });
        }

        validate_optional_non_empty("data_dir", self.data_dir.as_deref())?;
        validate_optional_non_empty("attachment_dir", self.attachment_dir.as_deref())?;

        Ok(())
    }

    /// Return the normalized daemon URL without a trailing slash.
    #[must_use]
    pub fn normalized_daemon_url(&self) -> String {
        self.daemon_url.trim().trim_end_matches('/').to_string()
    }

    /// Return the configured phone number trimmed for runtime use.
    #[must_use]
    pub fn normalized_phone_number(&self) -> String {
        self.phone_number.trim().to_string()
    }

    /// Return the daemon host, if it can be parsed.
    #[must_use]
    pub fn daemon_host(&self) -> Option<String> {
        Url::parse(&self.normalized_daemon_url())
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned))
    }

    /// Whether the daemon host is a local loopback endpoint.
    #[must_use]
    pub fn daemon_host_is_loopback(&self) -> bool {
        self.daemon_host().as_deref().is_some_and(is_loopback_host)
    }

    /// Return the configured receive timeout rounded up to whole seconds.
    #[must_use]
    pub const fn default_receive_timeout_seconds(&self) -> u64 {
        self.receive_timeout_ms.saturating_add(999) / 1000
    }
}

fn validate_optional_non_empty(field: &str, value: Option<&str>) -> FcpResult<()> {
    if let Some(value) = value {
        validate_non_empty(field, value)?;
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> FcpResult<()> {
    if value.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn validate_e164_number(field: &str, value: &str) -> FcpResult<()> {
    let value = value.trim();
    if !value.starts_with('+')
        || value.len() < 8
        || value[1..]
            .chars()
            .any(|character| !character.is_ascii_digit())
    {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("{field} must be a valid E.164 phone number"),
        });
    }
    Ok(())
}

#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim().trim_start_matches('[').trim_end_matches(']');
    normalized.eq_ignore_ascii_case("localhost") || normalized == "127.0.0.1" || normalized == "::1"
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// An incoming Signal message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalMessage {
    /// Sender phone number (E.164).
    pub sender: String,

    /// Message timestamp (Signal epoch ms).
    pub timestamp: u64,

    /// Text body of the message.
    #[serde(default)]
    pub body: Option<String>,

    /// Attached files.
    #[serde(default)]
    pub attachments: Vec<SignalAttachment>,

    /// Group context, if this is a group message.
    #[serde(default)]
    pub group_info: Option<GroupInfo>,

    /// Quote (reply) reference.
    #[serde(default)]
    pub quote: Option<SignalQuote>,
}

/// A quoted (reply-to) message reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalQuote {
    /// Timestamp of the quoted message.
    pub id: u64,
    /// Author of the quoted message.
    pub author: String,
    /// Text of the quoted message.
    #[serde(default)]
    pub text: Option<String>,
}

/// A Signal file attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalAttachment {
    /// Attachment identifier.
    #[serde(default)]
    pub id: Option<String>,

    /// MIME content type.
    #[serde(default)]
    pub content_type: Option<String>,

    /// Original filename.
    #[serde(default)]
    pub filename: Option<String>,

    /// File size in bytes.
    #[serde(default)]
    pub size: Option<u64>,
}

/// Signal group info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalGroup {
    /// Group identifier (base64-encoded group ID).
    pub id: String,

    /// Display name of the group.
    #[serde(default)]
    pub name: Option<String>,

    /// Phone numbers of group members.
    #[serde(default)]
    pub members: Vec<String>,
}

/// Signal delivery receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReceipt {
    /// Timestamp of the original message.
    pub timestamp: u64,

    /// Sender of the receipt.
    pub sender: String,

    /// Receipt type (delivery, read, viewed).
    pub receipt_type: ReceiptType,
}

/// Receipt type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptType {
    Delivery,
    Read,
    Viewed,
}

/// Sync message from a linked device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSyncMessage {
    /// The message that was sent (from another linked device).
    #[serde(default)]
    pub sent_message: Option<SentMessage>,

    /// Read receipts synced from another device.
    #[serde(default)]
    pub read_messages: Vec<ReadMessage>,
}

/// A message sent from a linked device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentMessage {
    /// Destination phone number.
    pub destination: String,
    /// Timestamp of the message.
    pub timestamp: u64,
    /// Text body.
    #[serde(default)]
    pub body: Option<String>,
}

/// A read receipt from a linked device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadMessage {
    /// Sender of the message that was read.
    pub sender: String,
    /// Timestamp of the message.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Requests / Responses (signal-cli REST API)
// ---------------------------------------------------------------------------

/// Request to send a message via signal-cli REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient phone numbers (E.164).
    pub recipients: Vec<String>,

    /// Text message body.
    pub message: String,

    /// Base64-encoded attachments.
    #[serde(default)]
    pub attachments: Vec<String>,

    /// Timestamp of the message to quote (reply to).
    #[serde(default)]
    pub quote_timestamp: Option<u64>,
}

impl SendMessageRequest {
    /// Validate send-message request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when recipients or attachments contain
    /// empty values, or when `quote_timestamp` is zero.
    pub fn validate(&self) -> FcpResult<()> {
        if self.recipients.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "recipients must not be empty".into(),
            });
        }

        if self
            .recipients
            .iter()
            .any(|recipient| recipient.trim().is_empty())
        {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "recipients must not contain empty values".into(),
            });
        }

        if self
            .attachments
            .iter()
            .any(|attachment| attachment.trim().is_empty())
        {
            return Err(FcpError::InvalidRequest {
                code: 1006,
                message: "attachments must not contain empty values".into(),
            });
        }

        if self.quote_timestamp == Some(0) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "quote_timestamp must be greater than zero".into(),
            });
        }

        Ok(())
    }
}

/// Request to receive messages from the REST daemon.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiveMessagesRequest {
    /// Optional override for the receive long-poll timeout.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

impl ReceiveMessagesRequest {
    /// Validate receive-message request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when `timeout_seconds` is zero.
    pub fn validate(&self) -> FcpResult<()> {
        if self.timeout_seconds == Some(0) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "timeout_seconds must be greater than zero".into(),
            });
        }
        Ok(())
    }
}

/// Request to look up a Signal group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupLookupRequest {
    /// Base64-encoded group identifier.
    pub group_id: String,
}

impl GroupLookupRequest {
    /// Validate group lookup request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when `group_id` is blank.
    pub fn validate(&self) -> FcpResult<()> {
        validate_non_empty("group_id", &self.group_id)
    }
}

/// Request to look up a Signal identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRequest {
    /// Phone number in E.164 format.
    pub number: String,
}

impl IdentityRequest {
    /// Validate identity request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when `number` is not a valid E.164
    /// phone number.
    pub fn validate(&self) -> FcpResult<()> {
        validate_e164_number("number", &self.number)
    }
}

/// Request to trust a Signal identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustIdentityRequest {
    /// Phone number in E.164 format.
    pub number: String,

    /// Safety number to trust explicitly.
    #[serde(default)]
    pub verified_safety_number: Option<String>,

    /// Trust every known key for the recipient.
    #[serde(default)]
    pub trust_all_known_keys: bool,
}

impl TrustIdentityRequest {
    /// Validate identity trust request invariants.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::InvalidRequest` when `number` is invalid or when the
    /// request does not specify exactly one trust mode.
    pub fn validate(&self) -> FcpResult<()> {
        validate_e164_number("number", &self.number)?;

        let has_verified_safety_number = self
            .verified_safety_number
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());

        if !has_verified_safety_number && !self.trust_all_known_keys {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "provide verified_safety_number or set trust_all_known_keys=true".into(),
            });
        }

        if has_verified_safety_number && self.trust_all_known_keys {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message:
                    "verified_safety_number and trust_all_known_keys=true are mutually exclusive"
                        .into(),
            });
        }

        Ok(())
    }
}

/// Response from signal-cli REST API after sending a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResponse {
    /// Timestamp assigned by Signal server.
    #[serde(deserialize_with = "deserialize_u64_from_string_or_number")]
    pub timestamp: u64,
}

/// Extended group info (from `list_groups` / `get_group`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Group identifier (base64-encoded).
    pub id: String,

    /// Display name of the group.
    #[serde(default)]
    pub name: Option<String>,

    /// Phone numbers of group members.
    #[serde(default)]
    pub members: Vec<String>,

    /// Phone numbers of group admins.
    #[serde(default)]
    pub admins: Vec<String>,
}

/// Signal identity / trust info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalIdentity {
    /// Phone number (E.164).
    pub number: String,

    /// UUID of the identity.
    #[serde(default)]
    pub uuid: Option<String>,

    /// Trust level (`TRUSTED_UNVERIFIED`, `TRUSTED_VERIFIED`, `UNTRUSTED`).
    #[serde(default)]
    pub trust_level: Option<String>,
}

/// Cursor for receive pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveCursor {
    /// Timestamp of the last received message.
    pub last_timestamp: u64,
}

/// signal-cli REST API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// Error message from signal-cli.
    #[serde(default)]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// signal-cli REST API envelope (receive)
// ---------------------------------------------------------------------------

/// Envelope received from the signal-cli REST daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEnvelope {
    /// Sender number (E.164).
    #[serde(default)]
    pub source: Option<String>,

    /// Sender device ID.
    #[serde(default, rename = "sourceDevice")]
    pub source_device: Option<u32>,

    /// Envelope timestamp.
    #[serde(default)]
    pub timestamp: Option<u64>,

    /// Data message content.
    #[serde(default, rename = "dataMessage")]
    pub data_message: Option<DataMessage>,

    /// Receipt message.
    #[serde(default, rename = "receiptMessage")]
    pub receipt_message: Option<serde_json::Value>,

    /// Sync message.
    #[serde(default, rename = "syncMessage")]
    pub sync_message: Option<serde_json::Value>,
}

/// Data message from signal-cli.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMessage {
    /// Message timestamp.
    #[serde(default)]
    pub timestamp: Option<u64>,

    /// Text body.
    #[serde(default)]
    pub message: Option<String>,

    /// Group context.
    #[serde(default, rename = "groupInfo")]
    pub group_info: Option<GroupInfo>,

    /// Attachments.
    #[serde(default)]
    pub attachments: Vec<SignalAttachment>,

    /// Quote (reply).
    #[serde(default)]
    pub quote: Option<SignalQuote>,
}

fn deserialize_u64_from_string_or_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| D::Error::custom("timestamp must be an unsigned integer")),
        serde_json::Value::String(value) => value
            .parse::<u64>()
            .map_err(|error| D::Error::custom(format!("invalid timestamp: {error}"))),
        other => Err(D::Error::custom(format!(
            "timestamp must be a string or integer, got {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_signal_config_defaults() {
        let json = serde_json::json!({
            "phone_number": "+15551234567"
        });
        let config = SignalConfig::from_value(json).unwrap();
        assert_eq!(config.phone_number, "+15551234567");
        assert_eq!(config.daemon_url, "http://localhost:8080");
        assert_eq!(config.trust_mode, TrustMode::OnFirstUse);
        assert_eq!(config.receive_timeout_ms, 10_000);
        assert_eq!(config.poll_interval_ms, 5_000);
        assert_eq!(config.max_reconnect_delay_ms, 60_000);
        assert_eq!(config.health_check_interval_ms, 30_000);
        assert_eq!(config.max_attachment_bytes, 100 * 1024 * 1024);
        assert_eq!(config.request_timeout_ms, 30_000);
        assert!(config.data_dir.is_none());
        assert!(config.attachment_dir.is_none());
    }

    #[test]
    fn deserialize_signal_config_overrides() {
        let json = serde_json::json!({
            "daemon_url": "https://signal.example.com:9090",
            "phone_number": "+491701234567",
            "trust_mode": "always",
            "data_dir": "/var/lib/signal-cli",
            "receive_timeout_ms": 30000,
            "poll_interval_ms": 7000,
            "max_reconnect_delay_ms": 45000,
            "health_check_interval_ms": 12000,
            "attachment_dir": "/tmp/signal-attachments",
            "max_attachment_bytes": 4096,
            "request_timeout_ms": 60000
        });
        let config = SignalConfig::from_value(json).unwrap();
        assert_eq!(config.daemon_url, "https://signal.example.com:9090");
        assert_eq!(config.trust_mode, TrustMode::Always);
        assert_eq!(config.data_dir, Some("/var/lib/signal-cli".into()));
        assert_eq!(config.receive_timeout_ms, 30000);
        assert_eq!(config.poll_interval_ms, 7000);
        assert_eq!(config.max_reconnect_delay_ms, 45000);
        assert_eq!(config.health_check_interval_ms, 12000);
        assert_eq!(
            config.attachment_dir,
            Some("/tmp/signal-attachments".into())
        );
        assert_eq!(config.max_attachment_bytes, 4096);
    }

    #[test]
    fn normalize_runtime_strings_for_signal_config() {
        let config = SignalConfig::from_value(serde_json::json!({
            "daemon_url": "  https://signal.example.com:9090/  ",
            "phone_number": "  +491701234567  ",
        }))
        .unwrap();

        assert_eq!(
            config.normalized_daemon_url(),
            "https://signal.example.com:9090"
        );
        assert_eq!(config.normalized_phone_number(), "+491701234567");
    }

    #[test]
    fn daemon_host_helpers_support_ipv6_loopback() {
        let config = SignalConfig::from_value(serde_json::json!({
            "daemon_url": "http://[::1]:8080/",
            "phone_number": "+15551234567",
        }))
        .unwrap();

        assert_eq!(config.daemon_host().as_deref(), Some("[::1]"));
        assert!(config.daemon_host_is_loopback());
    }

    #[test]
    fn reject_invalid_signal_config_phone_number() {
        let error = SignalConfig::from_value(serde_json::json!({
            "phone_number": "alice"
        }))
        .unwrap_err();

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn round_up_receive_timeout_to_seconds() {
        let config = SignalConfig::from_value(serde_json::json!({
            "phone_number": "+15551234567",
            "receive_timeout_ms": 10_001
        }))
        .unwrap();

        assert_eq!(config.default_receive_timeout_seconds(), 11);
    }

    #[test]
    fn deserialize_signal_message_full() {
        let json = serde_json::json!({
            "sender": "+15551234567",
            "timestamp": 1_700_000_000_000_u64,
            "body": "Hello, Signal!",
            "attachments": [
                {
                    "id": "att_001",
                    "content_type": "image/png",
                    "filename": "photo.png",
                    "size": 12345
                }
            ],
            "group_info": {
                "id": "Z3JvdXBfaWQ=",
                "name": "Test Group",
                "members": ["+15551111111", "+15552222222"],
                "admins": ["+15551111111"]
            },
            "quote": {
                "id": 1_699_999_999_000_u64,
                "author": "+15559999999",
                "text": "Original message"
            }
        });
        let msg: SignalMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.sender, "+15551234567");
        assert_eq!(msg.timestamp, 1_700_000_000_000);
        assert_eq!(msg.body, Some("Hello, Signal!".into()));
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].filename, Some("photo.png".into()));
        assert!(msg.group_info.is_some());
        let group = msg.group_info.unwrap();
        assert_eq!(group.name, Some("Test Group".into()));
        assert_eq!(group.members.len(), 2);
        assert!(msg.quote.is_some());
        assert_eq!(msg.quote.unwrap().author, "+15559999999");
    }

    #[test]
    fn deserialize_signal_message_minimal() {
        let json = serde_json::json!({
            "sender": "+15551234567",
            "timestamp": 1_700_000_000_000_u64
        });
        let msg: SignalMessage = serde_json::from_value(json).unwrap();
        assert!(msg.body.is_none());
        assert!(msg.attachments.is_empty());
        assert!(msg.group_info.is_none());
        assert!(msg.quote.is_none());
    }

    #[test]
    fn serialize_send_message_request() {
        let req = SendMessageRequest {
            recipients: vec!["+15551234567".into(), "+15559876543".into()],
            message: "Hello from FCP".into(),
            attachments: Vec::new(),
            quote_timestamp: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["recipients"].as_array().unwrap().len(), 2);
        assert_eq!(json["message"], "Hello from FCP");
    }

    #[test]
    fn deserialize_send_message_response() {
        let json = serde_json::json!({
            "timestamp": "1700000001000"
        });
        let resp: SendMessageResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.timestamp, 1_700_000_001_000);
    }

    #[test]
    fn trust_identity_request_requires_exactly_one_trust_mode() {
        let error = TrustIdentityRequest {
            number: "+15551234567".into(),
            verified_safety_number: None,
            trust_all_known_keys: false,
        }
        .validate()
        .unwrap_err();

        assert!(matches!(error, FcpError::InvalidRequest { .. }));

        let error = TrustIdentityRequest {
            number: "+15551234567".into(),
            verified_safety_number: Some("12345".into()),
            trust_all_known_keys: true,
        }
        .validate()
        .unwrap_err();

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn deserialize_signal_identity() {
        let json = serde_json::json!({
            "number": "+15551234567",
            "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "trust_level": "TRUSTED_VERIFIED"
        });
        let identity: SignalIdentity = serde_json::from_value(json).unwrap();
        assert_eq!(identity.number, "+15551234567");
        assert_eq!(identity.trust_level, Some("TRUSTED_VERIFIED".into()));
    }

    #[test]
    fn receive_cursor_roundtrip() {
        let cursor = ReceiveCursor {
            last_timestamp: 1_700_000_000_000,
        };
        let json = serde_json::to_value(&cursor).unwrap();
        let deserialized: ReceiveCursor = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.last_timestamp, 1_700_000_000_000);
    }

    #[test]
    fn trust_mode_serialization() {
        assert_eq!(
            serde_json::to_value(TrustMode::OnFirstUse).unwrap(),
            serde_json::json!("on_first_use")
        );
        assert_eq!(
            serde_json::to_value(TrustMode::Always).unwrap(),
            serde_json::json!("always")
        );
        assert_eq!(
            serde_json::to_value(TrustMode::Never).unwrap(),
            serde_json::json!("never")
        );
    }

    #[test]
    fn receipt_type_deserialization() {
        let json = serde_json::json!({
            "timestamp": 1_700_000_000_000_u64,
            "sender": "+15551234567",
            "receipt_type": "read"
        });
        let receipt: SignalReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(receipt.receipt_type, ReceiptType::Read);
    }

    #[test]
    fn deserialize_sync_message() {
        let json = serde_json::json!({
            "sent_message": {
                "destination": "+15559876543",
                "timestamp": 1_700_000_002_000_u64,
                "body": "Synced text"
            },
            "read_messages": [
                { "sender": "+15551111111", "timestamp": 1_700_000_003_000_u64 }
            ]
        });
        let sync: SignalSyncMessage = serde_json::from_value(json).unwrap();
        assert!(sync.sent_message.is_some());
        assert_eq!(sync.sent_message.unwrap().destination, "+15559876543");
        assert_eq!(sync.read_messages.len(), 1);
    }

    #[test]
    fn deserialize_signal_envelope() {
        let json = serde_json::json!({
            "source": "+15551234567",
            "sourceDevice": 1,
            "timestamp": 1_700_000_000_000_u64,
            "dataMessage": {
                "timestamp": 1_700_000_000_000_u64,
                "message": "Hello from envelope"
            }
        });
        let env: SignalEnvelope = serde_json::from_value(json).unwrap();
        assert_eq!(env.source, Some("+15551234567".into()));
        assert_eq!(env.source_device, Some(1));
        let dm = env.data_message.unwrap();
        assert_eq!(dm.message, Some("Hello from envelope".into()));
    }

    #[test]
    fn deserialize_group_info() {
        let json = serde_json::json!({
            "id": "Z3JvdXBfaWQ=",
            "name": "Engineers",
            "members": ["+15551111111", "+15552222222"],
            "admins": ["+15551111111"]
        });
        let group: GroupInfo = serde_json::from_value(json).unwrap();
        assert_eq!(group.id, "Z3JvdXBfaWQ=");
        assert_eq!(group.name, Some("Engineers".into()));
        assert_eq!(group.members.len(), 2);
        assert_eq!(group.admins.len(), 1);
    }

    #[test]
    fn api_error_response_deserialization() {
        let json = serde_json::json!({
            "error": "User is not registered"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error, Some("User is not registered".into()));
    }
}
