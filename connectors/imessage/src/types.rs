//! `BlueBubbles` API types.
//!
//! Covers the `BlueBubbles` REST API types for `iMessage` bridging.

use fcp_prelude::FcpError;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `BlueBubbles` connector configuration.
#[derive(Clone, Deserialize)]
pub struct BlueBubblesConfig {
    /// Base URL for the `BlueBubbles` server (e.g. `http://localhost:1234`).
    #[serde(default = "default_server_url")]
    pub server_url: String,

    /// Server passcode for API authentication.
    #[serde(rename = "password")]
    pub server_passcode: String,

    /// Polling interval in milliseconds for new messages.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,

    /// Directory for storing downloaded attachments.
    #[serde(default)]
    pub attachment_dir: Option<String>,

    /// HTTP retry configuration.
    #[serde(default)]
    pub retry: fcp_sdk::migration::HttpRetryConfig,

    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,

    /// Host/interface used when constructing the local webhook callback URL.
    #[serde(default = "default_webhook_host")]
    pub webhook_host: String,

    /// Port used when constructing the local webhook callback URL.
    #[serde(default = "default_webhook_port")]
    pub webhook_port: u16,

    /// Path used when constructing the local webhook callback URL.
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,

    /// Account namespace used for inbound webhook dedupe keys.
    #[serde(default = "default_webhook_account_id")]
    pub webhook_account_id: String,
}

impl BlueBubblesConfig {
    /// Parse and validate connector configuration from FCP configure payloads.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidRequest` error when required fields are missing or malformed.
    pub fn from_value(value: serde_json::Value) -> Result<Self, FcpError> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid BlueBubbles config: {error}"),
            })?;
        config.validate()
    }

    /// Validate and normalize the configuration.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidRequest` error when the config is unusable.
    pub fn validate(mut self) -> Result<Self, FcpError> {
        self.server_url = self.server_url.trim().trim_end_matches('/').to_string();
        self.server_passcode = self.server_passcode.trim().to_string();
        self.attachment_dir = self
            .attachment_dir
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        self.webhook_host = self.webhook_host.trim().to_string();
        self.webhook_path = normalize_webhook_path(&self.webhook_path);
        self.webhook_account_id = self.webhook_account_id.trim().to_string();

        if self.server_passcode.is_empty() {
            return Err(invalid_config("password must not be empty"));
        }

        if self.poll_interval_ms == 0 {
            return Err(invalid_config("poll_interval_ms must be greater than zero"));
        }

        if self.request_timeout_ms == 0 {
            return Err(invalid_config(
                "request_timeout_ms must be greater than zero",
            ));
        }

        if self.webhook_host.is_empty() {
            return Err(invalid_config("webhook_host must not be empty"));
        }

        if self.webhook_port == 0 {
            return Err(invalid_config("webhook_port must be greater than zero"));
        }

        if self.webhook_path == "/" {
            return Err(invalid_config("webhook_path must not be the root path"));
        }

        if self.webhook_account_id.is_empty() {
            return Err(invalid_config("webhook_account_id must not be empty"));
        }

        let parsed_url = Url::parse(&self.server_url).map_err(|error| {
            invalid_config(format!("server_url must be a valid absolute URL: {error}"))
        })?;

        if !matches!(parsed_url.scheme(), "http" | "https") {
            return Err(invalid_config("server_url must use http or https"));
        }

        if parsed_url.host_str().is_none() {
            return Err(invalid_config("server_url must include a host"));
        }

        Ok(self)
    }

    /// Extract the configured host for diagnostics.
    #[must_use]
    pub fn server_host(&self) -> Option<String> {
        Url::parse(&self.server_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
    }

    /// Build the URL registered with `BlueBubbles` for inbound webhook callbacks.
    ///
    /// The `BlueBubbles` registration API cannot attach custom headers, so the
    /// bridge password is embedded as a query parameter for inbound auth.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` if the configured host/path cannot form a URL.
    pub fn webhook_registration_url(&self) -> Result<String, FcpError> {
        let host = match self.webhook_host.as_str() {
            "0.0.0.0" | "127.0.0.1" | "localhost" | "::" => "localhost",
            other => other,
        };
        let mut url = Url::parse(&format!(
            "http://{}:{}{}",
            host, self.webhook_port, self.webhook_path
        ))
        .map_err(|error| invalid_config(format!("invalid webhook callback URL: {error}")))?;
        url.query_pairs_mut()
            .append_pair("password", &self.server_passcode);
        Ok(url.to_string())
    }
}

impl std::fmt::Debug for BlueBubblesConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlueBubblesConfig")
            .field("server_url", &self.server_url)
            .field("server_passcode", &"[REDACTED]")
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("attachment_dir", &self.attachment_dir)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("webhook_host", &self.webhook_host)
            .field("webhook_port", &self.webhook_port)
            .field("webhook_path", &self.webhook_path)
            .field("webhook_account_id", &self.webhook_account_id)
            .finish()
    }
}

fn default_server_url() -> String {
    "http://localhost:1234".to_string()
}

const fn default_poll_interval_ms() -> u64 {
    5000
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_webhook_host() -> String {
    "127.0.0.1".to_string()
}

const fn default_webhook_port() -> u16 {
    8645
}

fn default_webhook_path() -> String {
    "/bluebubbles-webhook".to_string()
}

fn default_webhook_account_id() -> String {
    "default".to_string()
}

fn normalize_webhook_path(path: &str) -> String {
    let path = path.trim();
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn invalid_config(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1001,
        message: format!("Invalid BlueBubbles config: {}", message.into()),
    }
}

// ---------------------------------------------------------------------------
// Chat types
// ---------------------------------------------------------------------------

/// A `BlueBubbles` chat (individual or group conversation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    /// Unique chat identifier (e.g. "iMessage;-;+15551234567").
    pub guid: String,

    /// Human-readable display name for the chat.
    #[serde(default)]
    pub display_name: Option<String>,

    /// Participants in this chat.
    #[serde(default)]
    pub participants: Vec<ChatParticipant>,

    /// Group identifier (for group chats).
    #[serde(default)]
    pub group_id: Option<String>,

    /// Whether this is a group chat.
    #[serde(default)]
    pub is_group: bool,

    /// The last message in this chat.
    #[serde(default)]
    pub last_message: Option<Message>,
}

/// A participant in a chat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatParticipant {
    /// Address (phone number or email).
    pub address: String,

    /// Human-readable display name.
    #[serde(default)]
    pub display_name: Option<String>,

    /// Whether this participant is the local user.
    #[serde(default)]
    pub is_me: bool,
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// A `BlueBubbles` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message identifier.
    pub guid: String,

    /// Message text content.
    #[serde(default)]
    pub text: Option<String>,

    /// Timestamp when the message was created (epoch ms).
    #[serde(default)]
    pub date_created: Option<i64>,

    /// Timestamp when the message was delivered (epoch ms).
    #[serde(default)]
    pub date_delivered: Option<i64>,

    /// Timestamp when the message was read (epoch ms).
    #[serde(default)]
    pub date_read: Option<i64>,

    /// Whether this message was sent by the local user.
    #[serde(default)]
    pub is_from_me: bool,

    /// Handle (sender) info.
    #[serde(default)]
    pub handle: Option<MessageHandle>,

    /// Attachments on this message.
    #[serde(default)]
    pub attachments: Vec<Attachment>,

    /// GUID of the thread originator message (for threaded replies).
    #[serde(default)]
    pub thread_originator_guid: Option<String>,

    /// Associated message type (tapback reactions, etc.).
    #[serde(default)]
    pub associated_message_type: Option<i32>,

    /// Group action type (member added/removed, name change, etc.).
    #[serde(default)]
    pub group_action_type: Option<i32>,
}

/// Handle (sender) information for a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHandle {
    /// Address (phone number or email).
    pub address: String,

    /// Human-readable display name.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// An attachment on a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Unique attachment identifier.
    pub guid: String,

    /// MIME type of the attachment.
    #[serde(default)]
    pub mime_type: Option<String>,

    /// Original filename.
    #[serde(default)]
    pub filename: Option<String>,

    /// Total size in bytes.
    #[serde(default)]
    pub total_bytes: Option<u64>,

    /// Transfer name (server-side filename).
    #[serde(default)]
    pub transfer_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Request to send a message via `BlueBubbles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Target chat GUID.
    #[serde(rename = "chatGuid")]
    pub chat_guid: String,

    /// Message text.
    pub message: String,

    /// Temporary GUID for de-duplication.
    #[serde(rename = "tempGuid", default)]
    pub temp_guid: Option<String>,

    /// Sending method ("apple-script" or "private-api").
    #[serde(default = "default_send_method")]
    pub method: String,
}

/// `BlueBubbles` `AppleScript` send mode.
pub const SEND_METHOD_APPLE_SCRIPT: &str = "apple-script";

/// `BlueBubbles` Private API send mode.
pub const SEND_METHOD_PRIVATE_API: &str = "private-api";

fn default_send_method() -> String {
    SEND_METHOD_APPLE_SCRIPT.to_string()
}

/// Response from sending a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResponse {
    /// Status code from the server.
    pub status: i32,

    /// Status message.
    #[serde(default)]
    pub message: Option<String>,

    /// Sent message data.
    #[serde(default)]
    pub data: Option<Message>,
}

/// Server information from the `BlueBubbles` instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// macOS version running `BlueBubbles`.
    #[serde(default)]
    pub os_version: Option<String>,

    /// `BlueBubbles` server version.
    #[serde(default)]
    pub server_version: Option<String>,

    /// Whether the Private API is enabled.
    #[serde(default)]
    pub private_api: bool,

    /// Proxy service in use (e.g. "ngrok", "cloudflare").
    #[serde(default)]
    pub proxy_service: Option<String>,
}

/// Query parameters for paginated endpoints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryParams {
    /// Offset for pagination.
    #[serde(default)]
    pub offset: Option<u64>,

    /// Maximum number of results to return.
    #[serde(default)]
    pub limit: Option<u64>,

    /// Only return results after this timestamp (epoch ms).
    #[serde(default)]
    pub after: Option<i64>,

    /// Only return results before this timestamp (epoch ms).
    #[serde(default)]
    pub before: Option<i64>,

    /// Sort order ("ASC" or "DESC").
    #[serde(default)]
    pub sort: Option<String>,

    /// Related objects to include (e.g. `["chat", "handle"]`).
    #[serde(default)]
    pub with: Vec<String>,
}

/// Paginated response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Total number of results available.
    #[serde(default)]
    pub total: Option<u64>,

    /// Current offset.
    #[serde(default)]
    pub offset: u64,

    /// Page size limit.
    #[serde(default)]
    pub limit: u64,

    /// Response data.
    pub data: Vec<T>,
}

/// API error response from `BlueBubbles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    /// Error message from the server.
    #[serde(default)]
    pub error: Option<String>,

    /// Status code from the server.
    #[serde(default)]
    pub status: Option<i32>,

    /// Human-readable message.
    #[serde(default)]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Webhook registration and ingress types
// ---------------------------------------------------------------------------

/// Default `BlueBubbles` webhook events that carry message activity.
#[must_use]
pub fn default_webhook_events() -> Vec<String> {
    vec!["new-message".to_string(), "updated-message".to_string()]
}

/// Request body for registering a `BlueBubbles` webhook callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRegistrationRequest {
    /// Callback URL to register with the `BlueBubbles` server.
    pub url: String,

    /// Event names the server should POST to the callback URL.
    #[serde(default = "default_webhook_events")]
    pub events: Vec<String>,
}

/// One registered `BlueBubbles` webhook callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRegistration {
    /// Server-assigned webhook ID. Some server versions use numeric IDs.
    #[serde(default, deserialize_with = "deserialize_optional_id")]
    pub id: Option<String>,

    /// Registered callback URL.
    #[serde(default)]
    pub url: Option<String>,

    /// Registered event names.
    #[serde(default)]
    pub events: Vec<String>,
}

/// Attachment metadata normalized from inbound webhook payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedWebhookAttachment {
    /// Attachment GUID.
    pub guid: String,

    /// MIME type, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// Apple UTI, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uti: Option<String>,

    /// Original transfer name, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_name: Option<String>,

    /// Reported byte size, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
}

/// Normalized message-shaped event from a `BlueBubbles` webhook payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedBlueBubblesWebhookMessage {
    /// Original webhook event type, such as `new-message` or `updated-message`.
    pub event_type: String,

    /// FCP event topic derived from the message metadata.
    pub topic: String,

    /// Message GUID used as the primary webhook event ID.
    pub event_id: String,

    /// Chat GUID, when the payload exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_guid: Option<String>,

    /// Chat identifier fallback, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_identifier: Option<String>,

    /// Sender address/handle, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<String>,

    /// Sender display name, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,

    /// Text body, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Whether the message originated from the local `BlueBubbles` account.
    pub is_from_me: bool,

    /// Whether the chat is a group conversation.
    pub is_group: bool,

    /// Attachments on the inbound message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<NormalizedWebhookAttachment>,

    /// Thread/reply originator GUID, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_message_guid: Option<String>,

    /// Associated message GUID used by tapbacks, replies, stickers, and previews.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub associated_message_guid: Option<String>,

    /// Associated message type used by tapback add/remove events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub associated_message_type: Option<i32>,

    /// Balloon bundle ID used by stickers/previews that can coalesce with text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balloon_bundle_id: Option<String>,

    /// Whether this payload represents a tapback-style associated message.
    pub is_tapback: bool,
}

const MAX_WEBHOOK_GUID_CHARS: usize = 512;

fn deserialize_optional_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| match value {
        Value::String(value) => nonempty_string(&value),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }))
}

fn nonempty_string(value: &str) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn read_string(record: Option<&Map<String, Value>>, keys: &[&str]) -> Option<String> {
    let record = record?;
    keys.iter().find_map(|key| {
        record
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn read_bool(record: Option<&Map<String, Value>>, keys: &[&str]) -> Option<bool> {
    let record = record?;
    keys.iter()
        .find_map(|key| record.get(*key).and_then(Value::as_bool))
}

fn read_i64(record: Option<&Map<String, Value>>, keys: &[&str]) -> Option<i64> {
    let record = record?;
    keys.iter().find_map(|key| {
        record.get(*key).and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
        })
    })
}

fn read_u64(record: Option<&Map<String, Value>>, keys: &[&str]) -> Option<u64> {
    let record = record?;
    keys.iter().find_map(|key| {
        record.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        })
    })
}

fn read_record<'a>(
    record: Option<&'a Map<String, Value>>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    let record = record?;
    keys.iter().find_map(|key| record.get(*key)?.as_object())
}

fn first_record_in_array<'a>(
    record: Option<&'a Map<String, Value>>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    let record = record?;
    keys.iter().find_map(|key| {
        record
            .get(*key)?
            .as_array()?
            .iter()
            .find_map(Value::as_object)
    })
}

fn payload_record(payload: &Value) -> Result<&Map<String, Value>, FcpError> {
    let root = payload
        .as_object()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "BlueBubbles webhook payload must be a JSON object".into(),
        })?;

    if let Some(data) = root.get("data") {
        if let Some(record) = data.as_object() {
            return Ok(record);
        }
        if let Some(record) = data
            .as_array()
            .and_then(|items| items.iter().find_map(Value::as_object))
        {
            return Ok(record);
        }
    }

    if let Some(record) = root.get("message").and_then(Value::as_object) {
        return Ok(record);
    }

    Ok(root)
}

fn payload_root(payload: &Value) -> Option<&Map<String, Value>> {
    payload.as_object()
}

fn normalize_attachment(value: &Value) -> Option<NormalizedWebhookAttachment> {
    let record = value.as_object()?;
    let guid = read_string(Some(record), &["guid", "attachmentGuid", "attachment_guid"])?;
    Some(NormalizedWebhookAttachment {
        guid,
        mime_type: read_string(Some(record), &["mimeType", "mime_type"]),
        uti: read_string(Some(record), &["uti"]),
        transfer_name: read_string(Some(record), &["transferName", "transfer_name", "filename"]),
        total_bytes: read_u64(Some(record), &["totalBytes", "total_bytes", "size"]),
    })
}

fn normalize_attachments(record: &Map<String, Value>) -> Vec<NormalizedWebhookAttachment> {
    record
        .get("attachments")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(normalize_attachment).collect())
        .unwrap_or_default()
}

fn is_tapback_type(associated_type: Option<i32>) -> bool {
    associated_type.is_some_and(|value| (2000..4000).contains(&value))
}

fn webhook_topic(event_type: &str, is_from_me: bool, associated_type: Option<i32>) -> &'static str {
    if is_tapback_type(associated_type) {
        "imessage.message.tapback"
    } else if event_type == "updated-message" {
        "imessage.message.updated"
    } else if is_from_me {
        "imessage.message.outbound"
    } else {
        "imessage.message.inbound"
    }
}

/// Normalize a raw `BlueBubbles` webhook payload into FCP event-shaped data.
///
/// # Errors
///
/// Returns `InvalidRequest` when the payload lacks a message GUID or has an
/// invalid shape.
#[allow(clippy::too_many_lines)]
pub fn normalize_bluebubbles_webhook_payload(
    payload: &Value,
    event_type_override: Option<&str>,
) -> Result<NormalizedBlueBubblesWebhookMessage, FcpError> {
    let root = payload_root(payload);
    let record = payload_record(payload)?;
    let chat_record = read_record(Some(record), &["chat", "conversation"]);
    let chat_from_list = first_record_in_array(Some(record), &["chats"]);
    let handle_record = read_record(Some(record), &["handle", "sender"]);

    let event_type = event_type_override
        .and_then(nonempty_string)
        .or_else(|| read_string(root, &["type", "event"]))
        .unwrap_or_else(|| "message".to_string());

    let event_id = read_string(Some(record), &["guid", "messageGuid", "message_id", "id"])
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "BlueBubbles webhook payload is missing a message GUID".into(),
        })?;

    if event_id.len() > MAX_WEBHOOK_GUID_CHARS {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "BlueBubbles webhook message GUID is too long".into(),
        });
    }

    let associated_message_type = read_i64(
        Some(record),
        &["associatedMessageType", "associated_message_type"],
    )
    .and_then(|value| i32::try_from(value).ok());
    let is_from_me =
        read_bool(Some(record), &["isFromMe", "fromMe", "is_from_me"]).unwrap_or(false);
    let chat_guid = read_string(Some(record), &["chatGuid", "chat_guid"])
        .or_else(|| read_string(chat_record, &["chatGuid", "chat_guid", "guid"]))
        .or_else(|| read_string(chat_from_list, &["chatGuid", "chat_guid", "guid"]))
        .or_else(|| read_string(root, &["chatGuid", "chat_guid"]));
    let chat_identifier = read_string(Some(record), &["chatIdentifier", "chat_identifier"])
        .or_else(|| {
            read_string(
                chat_record,
                &["chatIdentifier", "chat_identifier", "identifier"],
            )
        })
        .or_else(|| {
            read_string(
                chat_from_list,
                &["chatIdentifier", "chat_identifier", "identifier"],
            )
        });
    let sender_id = read_string(handle_record, &["address", "handle", "id"])
        .or_else(|| read_string(Some(record), &["senderId", "sender", "from", "address"]));
    let sender_name = read_string(handle_record, &["displayName", "display_name", "name"])
        .or_else(|| read_string(Some(record), &["senderName", "sender_name"]));
    let text = read_string(Some(record), &["text", "message", "body"]);
    let associated_message_guid = read_string(
        Some(record),
        &[
            "associatedMessageGuid",
            "associated_message_guid",
            "associatedMessageId",
        ],
    );
    let reply_to_message_guid = read_string(
        Some(record),
        &[
            "threadOriginatorGuid",
            "replyToMessageGuid",
            "replyToGuid",
            "selectedMessageGuid",
        ],
    )
    .or_else(|| {
        if is_tapback_type(associated_message_type) {
            None
        } else {
            associated_message_guid.clone()
        }
    });
    let balloon_bundle_id = read_string(Some(record), &["balloonBundleId", "balloon_bundle_id"]);
    let group_from_guid = chat_guid.as_deref().and_then(|guid| {
        if guid.contains(";+;") {
            Some(true)
        } else if guid.contains(";-;") {
            Some(false)
        } else {
            None
        }
    });
    let is_group = group_from_guid
        .or_else(|| read_bool(Some(record), &["isGroup", "is_group", "group"]))
        .unwrap_or(false);

    Ok(NormalizedBlueBubblesWebhookMessage {
        topic: webhook_topic(&event_type, is_from_me, associated_message_type).to_string(),
        event_type,
        event_id,
        chat_guid,
        chat_identifier,
        sender_id,
        sender_name,
        text,
        is_from_me,
        is_group,
        attachments: normalize_attachments(record),
        reply_to_message_guid,
        associated_message_guid,
        associated_message_type,
        balloon_bundle_id,
        is_tapback: is_tapback_type(associated_message_type),
    })
}

/// Build an account-scoped atomic dedupe key for a normalized webhook message.
#[must_use]
pub fn bluebubbles_webhook_dedupe_id(
    account_id: &str,
    message: &NormalizedBlueBubblesWebhookMessage,
) -> String {
    let account_id = account_id.trim();
    let account_id = if account_id.is_empty() {
        "default"
    } else {
        account_id
    };
    let base = if message.balloon_bundle_id.is_some() {
        message
            .associated_message_guid
            .as_deref()
            .unwrap_or(message.event_id.as_str())
    } else {
        message.event_id.as_str()
    };
    let suffix = if message.event_type == "updated-message" {
        ":updated"
    } else {
        ""
    };
    format!("{account_id}:{base}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config: BlueBubblesConfig = serde_json::from_str(r#"{"password":"test123"}"#).unwrap();
        assert_eq!(config.server_url, "http://localhost:1234");
        assert_eq!(config.poll_interval_ms, 5000);
        assert_eq!(config.request_timeout_ms, 30_000);
        assert_eq!(config.webhook_host, "127.0.0.1");
        assert_eq!(config.webhook_port, 8645);
        assert_eq!(config.webhook_path, "/bluebubbles-webhook");
        assert_eq!(config.webhook_account_id, "default");
        assert!(config.attachment_dir.is_none());
    }

    #[test]
    fn config_custom_values() {
        let config: BlueBubblesConfig = serde_json::from_str(
            r#"{"server_url":"http://myhost:5555","password":"abc","poll_interval_ms":1000}"#,
        )
        .unwrap();
        assert_eq!(config.server_url, "http://myhost:5555");
        assert_eq!(config.server_passcode, "abc");
        assert_eq!(config.poll_interval_ms, 1000);
    }

    #[test]
    fn config_from_value_trims_and_normalizes() {
        let config = BlueBubblesConfig::from_value(serde_json::json!({
            "server_url": " https://example.com/bridge/ ",
            "password": " secret ",
            "poll_interval_ms": 2500,
            "request_timeout_ms": 45000,
            "attachment_dir": "   "
        }))
        .unwrap();

        assert_eq!(config.server_url, "https://example.com/bridge");
        assert_eq!(config.server_passcode, "secret");
        assert_eq!(config.server_host().as_deref(), Some("example.com"));
        assert!(config.attachment_dir.is_none());
    }

    #[test]
    fn config_from_value_rejects_blank_password() {
        let result = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "   "
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_rejects_zero_poll_interval() {
        let result = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "secret",
            "poll_interval_ms": 0
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_rejects_zero_request_timeout() {
        let result = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "secret",
            "request_timeout_ms": 0
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_rejects_invalid_server_url() {
        let result = BlueBubblesConfig::from_value(serde_json::json!({
            "server_url": "not-a-url",
            "password": "secret"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_rejects_invalid_webhook_callback_config() {
        let cases = [
            serde_json::json!({
                "password": "secret",
                "webhook_host": "   "
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_port": 0
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_path": "/"
            }),
            serde_json::json!({
                "password": "secret",
                "webhook_account_id": "   "
            }),
        ];

        for case in cases {
            assert!(BlueBubblesConfig::from_value(case).is_err());
        }
    }

    #[test]
    fn chat_deserialize() {
        let json = serde_json::json!({
            "guid": "iMessage;-;+15551234567",
            "display_name": "John",
            "participants": [],
            "is_group": false
        });
        let chat: Chat = serde_json::from_value(json).unwrap();
        assert_eq!(chat.guid, "iMessage;-;+15551234567");
        assert_eq!(chat.display_name.as_deref(), Some("John"));
        assert!(!chat.is_group);
    }

    #[test]
    fn chat_group_deserialize() {
        let json = serde_json::json!({
            "guid": "iMessage;+;chat123",
            "display_name": "Family Chat",
            "participants": [
                { "address": "+15551111111", "display_name": "Mom", "is_me": false },
                { "address": "+15552222222", "is_me": true }
            ],
            "is_group": true,
            "group_id": "chat123"
        });
        let chat: Chat = serde_json::from_value(json).unwrap();
        assert!(chat.is_group);
        assert_eq!(chat.participants.len(), 2);
        assert!(chat.participants[1].is_me);
    }

    #[test]
    fn message_deserialize() {
        let json = serde_json::json!({
            "guid": "msg-001",
            "text": "Hello!",
            "date_created": 1_700_000_000_000_i64,
            "is_from_me": false,
            "handle": {
                "address": "+15551234567",
                "display_name": "Alice"
            },
            "attachments": []
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.guid, "msg-001");
        assert_eq!(msg.text.as_deref(), Some("Hello!"));
        assert!(!msg.is_from_me);
        assert_eq!(msg.handle.as_ref().unwrap().address, "+15551234567");
    }

    #[test]
    fn message_with_attachment() {
        let json = serde_json::json!({
            "guid": "msg-002",
            "text": null,
            "is_from_me": true,
            "attachments": [
                {
                    "guid": "att-001",
                    "mime_type": "image/png",
                    "filename": "photo.png",
                    "total_bytes": 12345,
                    "transfer_name": "photo.png"
                }
            ]
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].mime_type.as_deref(), Some("image/png"));
        assert_eq!(msg.attachments[0].total_bytes, Some(12345));
    }

    #[test]
    fn send_message_request_serialize() {
        let req = SendMessageRequest {
            chat_guid: "iMessage;-;+15551234567".to_string(),
            message: "Hello!".to_string(),
            temp_guid: Some("tmp-001".to_string()),
            method: "apple-script".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["chatGuid"], "iMessage;-;+15551234567");
        assert_eq!(json["message"], "Hello!");
        assert_eq!(json["tempGuid"], "tmp-001");
        assert_eq!(json["method"], SEND_METHOD_APPLE_SCRIPT);
    }

    #[test]
    fn send_message_response_deserialize() {
        let json = serde_json::json!({
            "status": 200,
            "message": "Message sent!",
            "data": {
                "guid": "msg-003",
                "text": "Hello!",
                "is_from_me": true,
                "attachments": []
            }
        });
        let resp: SendMessageResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.data.is_some());
        assert_eq!(resp.data.unwrap().guid, "msg-003");
    }

    #[test]
    fn server_info_deserialize() {
        let json = serde_json::json!({
            "os_version": "14.2",
            "server_version": "1.9.0",
            "private_api": true,
            "proxy_service": "cloudflare"
        });
        let info: ServerInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.os_version.as_deref(), Some("14.2"));
        assert!(info.private_api);
        assert_eq!(info.proxy_service.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn paginated_response_deserialize() {
        let json = serde_json::json!({
            "total": 100,
            "offset": 0,
            "limit": 25,
            "data": [
                {
                    "guid": "iMessage;-;+15551234567",
                    "is_group": false,
                    "participants": []
                }
            ]
        });
        let resp: PaginatedResponse<Chat> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total, Some(100));
        assert_eq!(resp.limit, 25);
        assert_eq!(resp.data.len(), 1);
    }

    #[test]
    fn query_params_default() {
        let params = QueryParams::default();
        assert!(params.offset.is_none());
        assert!(params.limit.is_none());
        assert!(params.after.is_none());
        assert!(params.with.is_empty());
    }

    #[test]
    fn api_error_response_deserialize() {
        let json = serde_json::json!({
            "error": "Not Found",
            "status": 404,
            "message": "Chat not found"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.as_deref(), Some("Not Found"));
        assert_eq!(err.status, Some(404));
    }

    #[test]
    fn webhook_registration_url_normalizes_localhost_and_encodes_password() {
        let config = BlueBubblesConfig::from_value(serde_json::json!({
            "password": "W9fTC&L5JL*@",
            "webhook_host": "0.0.0.0",
            "webhook_port": 9999,
            "webhook_path": "custom-hook",
            "webhook_account_id": "personal"
        }))
        .unwrap();

        assert_eq!(config.webhook_path, "/custom-hook");
        let url = config.webhook_registration_url().unwrap();
        assert!(url.starts_with("http://localhost:9999/custom-hook?"));
        assert!(url.contains("%26"));
        assert!(url.contains("%40"));
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert!(
            parsed
                .query_pairs()
                .any(|(key, value)| { key == "password" && value == "W9fTC&L5JL*@" })
        );
    }

    #[test]
    fn webhook_registration_deserializes_numeric_ids() {
        let registration: WebhookRegistration = serde_json::from_value(serde_json::json!({
            "id": 42,
            "url": "http://localhost:8645/bluebubbles-webhook",
            "events": ["new-message"]
        }))
        .unwrap();

        assert_eq!(registration.id.as_deref(), Some("42"));
        assert_eq!(registration.events, vec!["new-message"]);
    }

    #[test]
    fn normalize_webhook_payload_extracts_nested_chat_and_attachments() {
        let payload = serde_json::json!({
            "type": "new-message",
            "data": {
                "guid": "msg-001",
                "text": "hello",
                "isFromMe": false,
                "handle": { "address": "+15551234567", "displayName": "Alice" },
                "chats": [{
                    "guid": "iMessage;+;chat123",
                    "chatIdentifier": "Family"
                }],
                "attachments": [{
                    "guid": "att-1",
                    "mimeType": "image/png",
                    "uti": "public.png",
                    "transferName": "photo.png",
                    "totalBytes": 123
                }],
                "threadOriginatorGuid": "root-1",
                "associatedMessageGuid": "assoc-1",
                "associatedMessageType": 0,
                "balloonBundleId": "com.example.MessagesPlugin"
            }
        });

        let normalized = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        assert_eq!(normalized.event_type, "new-message");
        assert_eq!(normalized.event_id, "msg-001");
        assert_eq!(normalized.topic, "imessage.message.inbound");
        assert_eq!(normalized.chat_guid.as_deref(), Some("iMessage;+;chat123"));
        assert_eq!(normalized.chat_identifier.as_deref(), Some("Family"));
        assert_eq!(normalized.sender_id.as_deref(), Some("+15551234567"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Alice"));
        assert_eq!(normalized.text.as_deref(), Some("hello"));
        assert!(!normalized.is_from_me);
        assert!(normalized.is_group);
        assert_eq!(normalized.attachments.len(), 1);
        assert_eq!(normalized.attachments[0].guid, "att-1");
        assert_eq!(
            normalized.attachments[0].mime_type.as_deref(),
            Some("image/png")
        );
        assert_eq!(normalized.attachments[0].uti.as_deref(), Some("public.png"));
        assert_eq!(
            normalized.attachments[0].transfer_name.as_deref(),
            Some("photo.png")
        );
        assert_eq!(normalized.attachments[0].total_bytes, Some(123));
        assert_eq!(normalized.reply_to_message_guid.as_deref(), Some("root-1"));
        assert_eq!(
            normalized.associated_message_guid.as_deref(),
            Some("assoc-1")
        );
        assert_eq!(normalized.associated_message_type, Some(0));
        assert_eq!(
            normalized.balloon_bundle_id.as_deref(),
            Some("com.example.MessagesPlugin")
        );
        assert!(!normalized.is_tapback);
    }

    #[test]
    fn normalize_webhook_payload_rejects_malformed_and_accepts_data_arrays() {
        let malformed = serde_json::json!({
            "type": "new-message",
            "data": { "text": "missing guid" }
        });
        assert!(normalize_bluebubbles_webhook_payload(&malformed, None).is_err());

        let payload = serde_json::json!({
            "type": "new-message",
            "data": [{
                "guid": "array-msg",
                "chat": {
                    "guid": "iMessage;-;+15551234567",
                    "identifier": "+15551234567"
                },
                "sender": {
                    "id": "+15551234567",
                    "name": "Alice"
                },
                "fromMe": true
            }]
        });
        let normalized = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        assert_eq!(normalized.event_id, "array-msg");
        assert_eq!(
            normalized.chat_guid.as_deref(),
            Some("iMessage;-;+15551234567")
        );
        assert_eq!(normalized.chat_identifier.as_deref(), Some("+15551234567"));
        assert_eq!(normalized.sender_id.as_deref(), Some("+15551234567"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Alice"));
        assert!(normalized.is_from_me);
        assert_eq!(normalized.topic, "imessage.message.outbound");
    }

    #[test]
    fn normalize_webhook_payload_marks_tapbacks_and_updated_dedupe() {
        let payload = serde_json::json!({
            "event": "updated-message",
            "message": {
                "guid": "balloon-1",
                "text": "Loved \"hello\"",
                "associatedMessageGuid": "msg-root",
                "associatedMessageType": 2000,
                "balloonBundleId": "com.apple.messages.URLBalloonProvider",
                "isFromMe": false
            }
        });

        let normalized = normalize_bluebubbles_webhook_payload(&payload, None).unwrap();
        assert!(normalized.is_tapback);
        assert_eq!(normalized.topic, "imessage.message.tapback");
        assert_eq!(
            bluebubbles_webhook_dedupe_id("acct-a", &normalized),
            "acct-a:msg-root:updated"
        );
    }
}
