//! `BlueBubbles` API types.
//!
//! Covers the `BlueBubbles` REST API types for `iMessage` bridging.

use fcp_prelude::FcpError;
use reqwest::Url;
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config: BlueBubblesConfig = serde_json::from_str(r#"{"password":"test123"}"#).unwrap();
        assert_eq!(config.server_url, "http://localhost:1234");
        assert_eq!(config.poll_interval_ms, 5000);
        assert_eq!(config.request_timeout_ms, 30_000);
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
}
