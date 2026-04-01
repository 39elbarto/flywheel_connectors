//! Telegram API types.
//!
//! Types definitions for Telegram Bot API objects.

#![allow(dead_code)]

use std::collections::HashSet;

use fcp_core::{CredentialId, FcpError, FcpResult};
use reqwest::Url;
use serde::{Deserialize, Serialize};

pub const DEFAULT_TELEGRAM_BASE_URL: &str = "https://api.telegram.org";
pub const MIN_POLL_TIMEOUT_SECS: i32 = 1;
pub const MAX_POLL_TIMEOUT_SECS: i32 = 50;
pub const MIN_POLL_LEASE_TTL_SECS: u64 = 10;
pub const KNOWN_ALLOWED_UPDATES: &[&str] = &[
    "message",
    "edited_message",
    "channel_post",
    "edited_channel_post",
    "inline_query",
    "chosen_inline_result",
    "callback_query",
    "shipping_query",
    "pre_checkout_query",
    "poll",
    "poll_answer",
    "my_chat_member",
    "chat_member",
    "chat_join_request",
];

/// Update object representing an incoming event.
/// Telegram API response wrapper.
#[derive(Debug, Deserialize)]
pub struct TelegramResponse<T> {
    pub ok: bool,
    pub result: Option<T>,
    pub description: Option<String>,
    pub error_code: Option<i32>,
}

/// Telegram Update object.
#[derive(Debug, Clone, Deserialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(flatten)]
    pub kind: UpdateKind,
}

/// Different kinds of updates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    Message(Message),
    EditedMessage(Message),
    ChannelPost(Message),
    EditedChannelPost(Message),
    CallbackQuery(CallbackQuery),
    #[serde(other)]
    Unknown,
}

/// Telegram Message object.
#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    pub message_id: i64,
    pub from: Option<User>,
    pub chat: Chat,
    pub date: i64,
    pub text: Option<String>,
    pub caption: Option<String>,
    pub photo: Option<Vec<PhotoSize>>,
    pub document: Option<Document>,
    pub audio: Option<Audio>,
    pub video: Option<Video>,
    pub voice: Option<Voice>,
    pub reply_to_message: Option<Box<Message>>,
    pub message_thread_id: Option<i64>,
}

/// Telegram User object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub id: i64,
    pub is_bot: bool,
    pub first_name: String,
    pub last_name: Option<String>,
    pub username: Option<String>,
    pub language_code: Option<String>,
}

/// Telegram Chat object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Chat {
    pub id: i64,
    #[serde(rename = "type")]
    pub chat_type: String,
    pub title: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Photo size in a photo array.
#[derive(Debug, Clone, Deserialize)]
pub struct PhotoSize {
    pub file_id: String,
    pub file_unique_id: String,
    pub width: i32,
    pub height: i32,
    pub file_size: Option<i64>,
}

/// Document attachment.
#[derive(Debug, Clone, Deserialize)]
pub struct Document {
    pub file_id: String,
    pub file_unique_id: String,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
}

/// Audio attachment.
#[derive(Debug, Clone, Deserialize)]
pub struct Audio {
    pub file_id: String,
    pub file_unique_id: String,
    pub duration: i32,
    pub title: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
}

/// Video attachment.
#[derive(Debug, Clone, Deserialize)]
pub struct Video {
    pub file_id: String,
    pub file_unique_id: String,
    pub width: i32,
    pub height: i32,
    pub duration: i32,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
}

/// Voice message.
#[derive(Debug, Clone, Deserialize)]
pub struct Voice {
    pub file_id: String,
    pub file_unique_id: String,
    pub duration: i32,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
}

/// Callback query from inline keyboard.
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    pub message: Option<Message>,
    pub chat_instance: String,
    pub data: Option<String>,
}

/// File info returned by getFile.
#[derive(Debug, Clone, Deserialize)]
pub struct File {
    pub file_id: String,
    pub file_unique_id: String,
    pub file_size: Option<i64>,
    pub file_path: Option<String>,
}

/// Bot info returned by getMe.
#[derive(Debug, Clone, Deserialize)]
pub struct BotInfo {
    pub id: i64,
    pub is_bot: bool,
    pub first_name: String,
    pub username: Option<String>,
    pub can_join_groups: Option<bool>,
    pub can_read_all_group_messages: Option<bool>,
    pub supports_inline_queries: Option<bool>,
}

/// Send message request parameters.
#[derive(Debug, Serialize)]
pub struct SendMessageRequest {
    pub chat_id: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
}

/// Get updates request parameters.
#[derive(Debug, Serialize)]
pub struct GetUpdatesRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_updates: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramAuthConfig {
    BotToken,
    CredentialId(CredentialId),
}

/// Telegram connector configuration.
#[derive(Clone, Default, Deserialize)]
pub struct TelegramConfig {
    /// Bot credential (required)
    #[serde(default)]
    pub credential: Option<String>,

    /// Credential object reference for secretless setups.
    #[serde(default)]
    pub credential_id: Option<CredentialId>,

    /// Custom API base URL (optional)
    #[serde(default)]
    pub base_url: Option<String>,

    /// Polling timeout in seconds
    #[serde(default = "default_poll_timeout")]
    pub poll_timeout: i32,

    /// Allowed updates filter
    #[serde(default)]
    pub allowed_updates: Vec<String>,
}

impl std::fmt::Debug for TelegramConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramConfig")
            .field("credential", &self.credential.as_ref().map(|_| "[REDACTED]"))
            .field("credential_id", &self.credential_id)
            .field("base_url", &self.base_url)
            .field("poll_timeout", &self.poll_timeout)
            .field("allowed_updates", &self.allowed_updates)
            .finish()
    }
}

pub(crate) fn default_poll_timeout() -> i32 {
    30
}

impl TelegramConfig {
    pub fn resolve_auth_mode(&self) -> FcpResult<TelegramAuthConfig> {
        let token = self
            .credential
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        match (token, self.credential_id) {
            (Some(_), None) => Ok(TelegramAuthConfig::BotToken),
            (None, Some(id)) => Ok(TelegramAuthConfig::CredentialId(id)),
            (Some(_), Some(_)) => Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Provide exactly one of credential or credential_id".into(),
            }),
            (None, None) => Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Missing required credential or credential_id in configuration".into(),
            }),
        }
    }

    pub fn normalize_base_url(&self) -> FcpResult<String> {
        let raw = self
            .base_url
            .as_deref()
            .unwrap_or(DEFAULT_TELEGRAM_BASE_URL)
            .trim();

        if raw.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url cannot be empty".into(),
            });
        }

        let parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid base_url: {error}"),
        })?;
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must use http or https".into(),
            });
        }
        if parsed.host_str().is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must include a host".into(),
            });
        }

        Ok(raw.trim_end_matches('/').to_string())
    }

    pub fn validate_runtime_settings(&self) -> FcpResult<()> {
        if !(MIN_POLL_TIMEOUT_SECS..=MAX_POLL_TIMEOUT_SECS).contains(&self.poll_timeout) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "poll_timeout must be between {MIN_POLL_TIMEOUT_SECS} and {MAX_POLL_TIMEOUT_SECS} seconds"
                ),
            });
        }

        let mut seen = HashSet::new();
        for update in &self.allowed_updates {
            if update.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "allowed_updates entries must not be empty".into(),
                });
            }
            if !seen.insert(update.clone()) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("allowed_updates contains duplicate value: {update}"),
                });
            }
            if !KNOWN_ALLOWED_UPDATES.contains(&update.as_str()) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("allowed_updates contains unsupported type: {update}"),
                });
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn auth_label(&self) -> &'static str {
        if self.credential_id.is_some() {
            "credential_id"
        } else {
            "bot_token"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorResult {
    pub status: DoctorStatus,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub critical: bool,
}

impl DoctorResult {
    #[must_use]
    pub fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        Self { status, checks }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramPollingCursorState {
    pub offset: Option<i64>,
    pub last_poll_count: usize,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramPollLeaseRecord {
    pub holder_instance_id: String,
    pub lease_seq: u64,
    pub updated_at: u64,
    pub expires_at: u64,
}

/// Options for sending messages.
#[derive(Debug, Default, Clone)]
pub struct SendMessageOptions {
    pub parse_mode: Option<String>,
    pub reply_to_message_id: Option<i64>,
    pub message_thread_id: Option<i64>,
}

#[allow(dead_code)] // Helper methods for future use
impl SendMessageOptions {
    /// Set parse mode to HTML.
    #[must_use]
    pub fn html(mut self) -> Self {
        self.parse_mode = Some("HTML".into());
        self
    }

    /// Set parse mode to MarkdownV2.
    #[must_use]
    pub fn markdown_v2(mut self) -> Self {
        self.parse_mode = Some("MarkdownV2".into());
        self
    }

    /// Set reply to a specific message.
    #[must_use]
    pub fn reply_to_message_id(mut self, id: i64) -> Self {
        self.reply_to_message_id = Some(id);
        self
    }
}

/// Options for sending media.
#[derive(Debug, Default, Clone)]
pub struct SendMediaOptions {
    pub caption: Option<String>,
    pub parse_mode: Option<String>,
    pub reply_to_message_id: Option<i64>,
}

/// Request body for send media methods.
///
/// Telegram expects the media field name to vary by type (photo, document, etc.).
/// We use a custom serializer to emit the correct field name.
#[derive(Debug)]
pub struct SendMediaRequest {
    pub chat_id: String,
    pub media_field: String,
    pub media_value: String,
    pub caption: Option<String>,
    pub parse_mode: Option<String>,
    pub reply_to_message_id: Option<i64>,
}

impl Serialize for SendMediaRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut count = 2;
        if self.caption.is_some() {
            count += 1;
        }
        if self.parse_mode.is_some() {
            count += 1;
        }
        if self.reply_to_message_id.is_some() {
            count += 1;
        }

        let mut map = serializer.serialize_map(Some(count))?;
        map.serialize_entry("chat_id", &self.chat_id)?;
        map.serialize_entry(&self.media_field, &self.media_value)?;
        if let Some(caption) = &self.caption {
            map.serialize_entry("caption", caption)?;
        }
        if let Some(parse_mode) = &self.parse_mode {
            map.serialize_entry("parse_mode", parse_mode)?;
        }
        if let Some(reply_to_message_id) = self.reply_to_message_id {
            map.serialize_entry("reply_to_message_id", &reply_to_message_id)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- TelegramResponse ----

    #[test]
    fn telegram_response_ok() {
        let json = r#"{"ok":true,"result":42}"#;
        let resp: TelegramResponse<i32> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.result, Some(42));
        assert!(resp.description.is_none());
    }

    #[test]
    fn telegram_response_error() {
        let json = r#"{"ok":false,"description":"Not Found","error_code":404}"#;
        let resp: TelegramResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error_code, Some(404));
        assert_eq!(resp.description.as_deref(), Some("Not Found"));
    }

    // ---- User ----

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            id: 123,
            is_bot: true,
            first_name: "TestBot".to_string(),
            last_name: None,
            username: Some("test_bot".to_string()),
            language_code: Some("en".to_string()),
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 123);
        assert!(back.is_bot);
    }

    // ---- Chat ----

    #[test]
    fn chat_serde_roundtrip() {
        let chat = Chat {
            id: -100_123_456,
            chat_type: "supergroup".to_string(),
            title: Some("Test Group".to_string()),
            username: None,
            first_name: None,
            last_name: None,
        };
        let json = serde_json::to_string(&chat).unwrap();
        assert!(json.contains("\"type\":\"supergroup\""));
        let back: Chat = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, -100_123_456);
    }

    // ---- Message ----

    #[test]
    fn message_deserialize() {
        let json = json!({
            "message_id": 1,
            "chat": {"id": 123, "type": "private"},
            "date": 1_700_000_000,
            "text": "Hello!"
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.message_id, 1);
        assert_eq!(msg.text.as_deref(), Some("Hello!"));
        assert!(msg.from.is_none());
        assert!(msg.photo.is_none());
    }

    // ---- PhotoSize ----

    #[test]
    fn photo_size_deserialize() {
        let json = json!({
            "file_id": "abc123",
            "file_unique_id": "unique1",
            "width": 320,
            "height": 240,
            "file_size": 15000
        });
        let photo: PhotoSize = serde_json::from_value(json).unwrap();
        assert_eq!(photo.width, 320);
        assert_eq!(photo.file_size, Some(15000));
    }

    // ---- Document ----

    #[test]
    fn document_deserialize() {
        let json = json!({
            "file_id": "doc1",
            "file_unique_id": "uniq1",
            "file_name": "report.pdf",
            "mime_type": "application/pdf"
        });
        let doc: Document = serde_json::from_value(json).unwrap();
        assert_eq!(doc.file_name.as_deref(), Some("report.pdf"));
    }

    // ---- BotInfo ----

    #[test]
    fn bot_info_deserialize() {
        let json = json!({
            "id": 123,
            "is_bot": true,
            "first_name": "MyBot",
            "username": "my_bot",
            "can_join_groups": true,
            "can_read_all_group_messages": false,
            "supports_inline_queries": false
        });
        let bot: BotInfo = serde_json::from_value(json).unwrap();
        assert!(bot.is_bot);
        assert_eq!(bot.can_join_groups, Some(true));
    }

    // ---- File ----

    #[test]
    fn file_deserialize() {
        let json = json!({
            "file_id": "f1",
            "file_unique_id": "fu1",
            "file_size": 1024,
            "file_path": "photos/file_0.jpg"
        });
        let file: File = serde_json::from_value(json).unwrap();
        assert_eq!(file.file_path.as_deref(), Some("photos/file_0.jpg"));
    }

    // ---- SendMessageRequest ----

    #[test]
    fn send_message_request_serialize() {
        let req = SendMessageRequest {
            chat_id: "123".to_string(),
            text: "Hello!".to_string(),
            parse_mode: Some("HTML".to_string()),
            reply_to_message_id: None,
            message_thread_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"parse_mode\":\"HTML\""));
        assert!(!json.contains("reply_to_message_id"));
    }

    // ---- GetUpdatesRequest ----

    #[test]
    fn get_updates_request_serialize_minimal() {
        let req = GetUpdatesRequest {
            offset: None,
            limit: None,
            timeout: None,
            allowed_updates: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "{}");
    }

    // ---- UpdateKind ----

    #[test]
    fn update_with_message() {
        let json = json!({
            "update_id": 100,
            "message": {
                "message_id": 1,
                "chat": {"id": 123, "type": "private"},
                "date": 1_700_000_000,
                "text": "hi"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        assert_eq!(update.update_id, 100);
        match &update.kind {
            UpdateKind::Message(msg) => assert_eq!(msg.text.as_deref(), Some("hi")),
            _ => panic!("expected Message"),
        }
    }

    // ---- CallbackQuery ----

    #[test]
    fn callback_query_deserialize() {
        let json = json!({
            "id": "cb1",
            "from": {"id": 123, "is_bot": false, "first_name": "Alice"},
            "chat_instance": "inst1",
            "data": "button_clicked"
        });
        let cb: CallbackQuery = serde_json::from_value(json).unwrap();
        assert_eq!(cb.data.as_deref(), Some("button_clicked"));
        assert_eq!(cb.from.first_name, "Alice");
    }

    // ---- TelegramResponse additional ----

    #[test]
    fn telegram_response_ok_with_none_result() {
        let json = r#"{"ok":true}"#;
        let resp: TelegramResponse<i32> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert!(resp.result.is_none());
        assert!(resp.description.is_none());
        assert!(resp.error_code.is_none());
    }

    // ---- User additional ----

    #[test]
    fn user_all_optional_fields_none() {
        let json = json!({
            "id": 999,
            "is_bot": false,
            "first_name": "Alice"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, 999);
        assert!(!user.is_bot);
        assert_eq!(user.first_name, "Alice");
        assert!(user.last_name.is_none());
        assert!(user.username.is_none());
        assert!(user.language_code.is_none());
    }

    #[test]
    fn user_clone() {
        let user = User {
            id: 1,
            is_bot: false,
            first_name: "Bob".into(),
            last_name: Some("Smith".into()),
            username: Some("bob_smith".into()),
            language_code: Some("de".into()),
        };
        let cloned = user.clone();
        assert_eq!(cloned.id, user.id);
        assert_eq!(cloned.first_name, user.first_name);
        assert_eq!(cloned.last_name, user.last_name);
        assert_eq!(cloned.username, user.username);
        assert_eq!(cloned.language_code, user.language_code);
    }

    #[test]
    fn user_debug() {
        let user = User {
            id: 42,
            is_bot: true,
            first_name: "DebugBot".into(),
            last_name: None,
            username: None,
            language_code: None,
        };
        let debug = format!("{user:?}");
        assert!(debug.contains("User"));
        assert!(debug.contains("42"));
        assert!(debug.contains("DebugBot"));
    }

    // ---- Chat additional ----

    #[test]
    fn chat_private_type() {
        let json = json!({
            "id": 555,
            "type": "private",
            "first_name": "Carol"
        });
        let chat: Chat = serde_json::from_value(json).unwrap();
        assert_eq!(chat.id, 555);
        assert_eq!(chat.chat_type, "private");
        assert!(chat.title.is_none());
        assert_eq!(chat.first_name.as_deref(), Some("Carol"));
    }

    #[test]
    fn chat_clone() {
        let chat = Chat {
            id: -100_999,
            chat_type: "group".into(),
            title: Some("My Group".into()),
            username: None,
            first_name: None,
            last_name: None,
        };
        let cloned = chat.clone();
        assert_eq!(cloned.id, chat.id);
        assert_eq!(cloned.chat_type, chat.chat_type);
        assert_eq!(cloned.title, chat.title);
    }

    #[test]
    fn chat_debug() {
        let chat = Chat {
            id: 1,
            chat_type: "channel".into(),
            title: Some("Chan".into()),
            username: Some("chan_user".into()),
            first_name: None,
            last_name: None,
        };
        let debug = format!("{chat:?}");
        assert!(debug.contains("Chat"));
        assert!(debug.contains("channel"));
    }

    // ---- Message additional ----

    #[test]
    fn message_with_photo_array() {
        let json = json!({
            "message_id": 10,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "photo": [
                {
                    "file_id": "small",
                    "file_unique_id": "us",
                    "width": 90,
                    "height": 90,
                    "file_size": 1000
                },
                {
                    "file_id": "large",
                    "file_unique_id": "ul",
                    "width": 800,
                    "height": 600,
                    "file_size": 50000
                }
            ]
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let photos = msg.photo.unwrap();
        assert_eq!(photos.len(), 2);
        assert_eq!(photos[0].file_id, "small");
        assert_eq!(photos[1].width, 800);
    }

    #[test]
    fn message_with_document() {
        let json = json!({
            "message_id": 11,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "document": {
                "file_id": "doc_id",
                "file_unique_id": "doc_uniq",
                "file_name": "notes.txt",
                "mime_type": "text/plain",
                "file_size": 256
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let doc = msg.document.unwrap();
        assert_eq!(doc.file_id, "doc_id");
        assert_eq!(doc.file_name.as_deref(), Some("notes.txt"));
    }

    #[test]
    fn message_with_audio() {
        let json = json!({
            "message_id": 12,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "audio": {
                "file_id": "audio_id",
                "file_unique_id": "audio_uniq",
                "duration": 180,
                "title": "Song Title",
                "mime_type": "audio/mpeg",
                "file_size": 3_000_000
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let audio = msg.audio.unwrap();
        assert_eq!(audio.duration, 180);
        assert_eq!(audio.title.as_deref(), Some("Song Title"));
    }

    #[test]
    fn message_with_video() {
        let json = json!({
            "message_id": 13,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "video": {
                "file_id": "vid_id",
                "file_unique_id": "vid_uniq",
                "width": 1920,
                "height": 1080,
                "duration": 60,
                "mime_type": "video/mp4",
                "file_size": 10_000_000
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let video = msg.video.unwrap();
        assert_eq!(video.width, 1920);
        assert_eq!(video.height, 1080);
        assert_eq!(video.duration, 60);
    }

    #[test]
    fn message_with_voice() {
        let json = json!({
            "message_id": 14,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "voice": {
                "file_id": "voice_id",
                "file_unique_id": "voice_uniq",
                "duration": 5,
                "mime_type": "audio/ogg",
                "file_size": 8000
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        let voice = msg.voice.unwrap();
        assert_eq!(voice.duration, 5);
        assert_eq!(voice.mime_type.as_deref(), Some("audio/ogg"));
    }

    #[test]
    fn message_with_reply_to_message() {
        let json = json!({
            "message_id": 20,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_001,
            "text": "This is a reply",
            "reply_to_message": {
                "message_id": 19,
                "chat": {"id": 100, "type": "private"},
                "date": 1_700_000_000,
                "text": "Original message"
            }
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.text.as_deref(), Some("This is a reply"));
        let reply = msg.reply_to_message.unwrap();
        assert_eq!(reply.message_id, 19);
        assert_eq!(reply.text.as_deref(), Some("Original message"));
    }

    #[test]
    fn message_with_message_thread_id() {
        let json = json!({
            "message_id": 30,
            "chat": {"id": -100_555, "type": "supergroup", "title": "Forum"},
            "date": 1_700_000_000,
            "message_thread_id": 42,
            "text": "Topic reply"
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.message_thread_id, Some(42));
        assert_eq!(msg.text.as_deref(), Some("Topic reply"));
    }

    #[test]
    fn message_with_caption_no_text() {
        let json = json!({
            "message_id": 31,
            "chat": {"id": 100, "type": "private"},
            "date": 1_700_000_000,
            "caption": "Photo caption here",
            "photo": [{
                "file_id": "p1",
                "file_unique_id": "pu1",
                "width": 320,
                "height": 240
            }]
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert!(msg.text.is_none());
        assert_eq!(msg.caption.as_deref(), Some("Photo caption here"));
        assert!(msg.photo.is_some());
    }

    // ---- PhotoSize additional ----

    #[test]
    fn photo_size_without_file_size() {
        let json = json!({
            "file_id": "ph1",
            "file_unique_id": "phu1",
            "width": 160,
            "height": 120
        });
        let photo: PhotoSize = serde_json::from_value(json).unwrap();
        assert_eq!(photo.width, 160);
        assert_eq!(photo.height, 120);
        assert!(photo.file_size.is_none());
    }

    #[test]
    fn photo_size_clone() {
        let photo = PhotoSize {
            file_id: "ph2".into(),
            file_unique_id: "phu2".into(),
            width: 640,
            height: 480,
            file_size: Some(25000),
        };
        let cloned = photo.clone();
        assert_eq!(cloned.file_id, photo.file_id);
        assert_eq!(cloned.width, photo.width);
        assert_eq!(cloned.file_size, photo.file_size);
    }

    // ---- Document additional ----

    #[test]
    fn document_minimal() {
        let json = json!({
            "file_id": "doc_min",
            "file_unique_id": "doc_min_u"
        });
        let doc: Document = serde_json::from_value(json).unwrap();
        assert_eq!(doc.file_id, "doc_min");
        assert!(doc.file_name.is_none());
        assert!(doc.mime_type.is_none());
        assert!(doc.file_size.is_none());
    }

    #[test]
    fn document_clone() {
        let doc = Document {
            file_id: "d1".into(),
            file_unique_id: "du1".into(),
            file_name: Some("data.csv".into()),
            mime_type: Some("text/csv".into()),
            file_size: Some(4096),
        };
        let cloned = doc.clone();
        assert_eq!(cloned.file_id, doc.file_id);
        assert_eq!(cloned.file_name, doc.file_name);
        assert_eq!(cloned.mime_type, doc.mime_type);
        assert_eq!(cloned.file_size, doc.file_size);
    }

    // ---- Audio additional ----

    #[test]
    fn audio_full_fields() {
        let json = json!({
            "file_id": "aud1",
            "file_unique_id": "audu1",
            "duration": 240,
            "title": "My Song",
            "mime_type": "audio/mpeg",
            "file_size": 5_000_000
        });
        let audio: Audio = serde_json::from_value(json).unwrap();
        assert_eq!(audio.file_id, "aud1");
        assert_eq!(audio.duration, 240);
        assert_eq!(audio.title.as_deref(), Some("My Song"));
        assert_eq!(audio.mime_type.as_deref(), Some("audio/mpeg"));
        assert_eq!(audio.file_size, Some(5_000_000));
    }

    #[test]
    fn audio_minimal() {
        let json = json!({
            "file_id": "aud2",
            "file_unique_id": "audu2",
            "duration": 10
        });
        let audio: Audio = serde_json::from_value(json).unwrap();
        assert_eq!(audio.duration, 10);
        assert!(audio.title.is_none());
        assert!(audio.mime_type.is_none());
        assert!(audio.file_size.is_none());
    }

    #[test]
    fn audio_clone() {
        let audio = Audio {
            file_id: "ac".into(),
            file_unique_id: "acu".into(),
            duration: 60,
            title: Some("Clone Test".into()),
            mime_type: Some("audio/ogg".into()),
            file_size: Some(100_000),
        };
        let cloned = audio.clone();
        assert_eq!(cloned.file_id, audio.file_id);
        assert_eq!(cloned.duration, audio.duration);
        assert_eq!(cloned.title, audio.title);
    }

    // ---- Video additional ----

    #[test]
    fn video_full_fields() {
        let json = json!({
            "file_id": "vid1",
            "file_unique_id": "vidu1",
            "width": 3840,
            "height": 2160,
            "duration": 300,
            "mime_type": "video/mp4",
            "file_size": 100_000_000
        });
        let video: Video = serde_json::from_value(json).unwrap();
        assert_eq!(video.width, 3840);
        assert_eq!(video.height, 2160);
        assert_eq!(video.duration, 300);
        assert_eq!(video.mime_type.as_deref(), Some("video/mp4"));
        assert_eq!(video.file_size, Some(100_000_000));
    }

    #[test]
    fn video_clone() {
        let video = Video {
            file_id: "vc".into(),
            file_unique_id: "vcu".into(),
            width: 1280,
            height: 720,
            duration: 30,
            mime_type: None,
            file_size: None,
        };
        let cloned = video.clone();
        assert_eq!(cloned.file_id, video.file_id);
        assert_eq!(cloned.width, video.width);
        assert_eq!(cloned.height, video.height);
    }

    // ---- Voice additional ----

    #[test]
    fn voice_full_fields() {
        let json = json!({
            "file_id": "v1",
            "file_unique_id": "vu1",
            "duration": 15,
            "mime_type": "audio/ogg",
            "file_size": 12000
        });
        let voice: Voice = serde_json::from_value(json).unwrap();
        assert_eq!(voice.duration, 15);
        assert_eq!(voice.mime_type.as_deref(), Some("audio/ogg"));
        assert_eq!(voice.file_size, Some(12000));
    }

    #[test]
    fn voice_minimal() {
        let json = json!({
            "file_id": "v2",
            "file_unique_id": "vu2",
            "duration": 1
        });
        let voice: Voice = serde_json::from_value(json).unwrap();
        assert_eq!(voice.duration, 1);
        assert!(voice.mime_type.is_none());
        assert!(voice.file_size.is_none());
    }

    #[test]
    fn voice_clone() {
        let voice = Voice {
            file_id: "vcl".into(),
            file_unique_id: "vclu".into(),
            duration: 7,
            mime_type: Some("audio/ogg".into()),
            file_size: Some(5000),
        };
        let cloned = voice.clone();
        assert_eq!(cloned.file_id, voice.file_id);
        assert_eq!(cloned.duration, voice.duration);
        assert_eq!(cloned.mime_type, voice.mime_type);
    }

    // ---- CallbackQuery additional ----

    #[test]
    fn callback_query_without_message_and_data() {
        let json = json!({
            "id": "cb_no_msg",
            "from": {"id": 555, "is_bot": false, "first_name": "Dave"},
            "chat_instance": "inst2"
        });
        let cb: CallbackQuery = serde_json::from_value(json).unwrap();
        assert_eq!(cb.id, "cb_no_msg");
        assert!(cb.message.is_none());
        assert!(cb.data.is_none());
    }

    #[test]
    fn callback_query_clone() {
        let cb = CallbackQuery {
            id: "cb_clone".into(),
            from: User {
                id: 1,
                is_bot: false,
                first_name: "Eve".into(),
                last_name: None,
                username: None,
                language_code: None,
            },
            message: None,
            chat_instance: "ci".into(),
            data: Some("action".into()),
        };
        let cloned = cb.clone();
        assert_eq!(cloned.id, cb.id);
        assert_eq!(cloned.from.first_name, cb.from.first_name);
        assert_eq!(cloned.data, cb.data);
    }

    // ---- File additional ----

    #[test]
    fn file_minimal() {
        let json = json!({
            "file_id": "f_min",
            "file_unique_id": "fu_min"
        });
        let file: File = serde_json::from_value(json).unwrap();
        assert_eq!(file.file_id, "f_min");
        assert!(file.file_size.is_none());
        assert!(file.file_path.is_none());
    }

    #[test]
    fn file_clone() {
        let file = File {
            file_id: "fc".into(),
            file_unique_id: "fcu".into(),
            file_size: Some(2048),
            file_path: Some("documents/file.pdf".into()),
        };
        let cloned = file.clone();
        assert_eq!(cloned.file_id, file.file_id);
        assert_eq!(cloned.file_size, file.file_size);
        assert_eq!(cloned.file_path, file.file_path);
    }

    // ---- BotInfo additional ----

    #[test]
    fn bot_info_minimal() {
        let json = json!({
            "id": 777,
            "is_bot": true,
            "first_name": "MinBot"
        });
        let bot: BotInfo = serde_json::from_value(json).unwrap();
        assert_eq!(bot.id, 777);
        assert!(bot.is_bot);
        assert_eq!(bot.first_name, "MinBot");
        assert!(bot.username.is_none());
        assert!(bot.can_join_groups.is_none());
        assert!(bot.can_read_all_group_messages.is_none());
        assert!(bot.supports_inline_queries.is_none());
    }

    #[test]
    fn bot_info_clone() {
        let bot = BotInfo {
            id: 888,
            is_bot: true,
            first_name: "CloneBot".into(),
            username: Some("clone_bot".into()),
            can_join_groups: Some(true),
            can_read_all_group_messages: Some(false),
            supports_inline_queries: Some(true),
        };
        let cloned = bot.clone();
        assert_eq!(cloned.id, bot.id);
        assert_eq!(cloned.first_name, bot.first_name);
        assert_eq!(cloned.username, bot.username);
        assert_eq!(cloned.can_join_groups, bot.can_join_groups);
        assert_eq!(cloned.supports_inline_queries, bot.supports_inline_queries);
    }

    // ---- SendMessageRequest additional ----

    #[test]
    fn send_message_request_with_all_fields() {
        let req = SendMessageRequest {
            chat_id: "12345".into(),
            text: "Hi!".into(),
            parse_mode: Some("MarkdownV2".into()),
            reply_to_message_id: Some(7),
            message_thread_id: Some(99),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"chat_id\":\"12345\""));
        assert!(json.contains("\"text\":\"Hi!\""));
        assert!(json.contains("\"parse_mode\":\"MarkdownV2\""));
        assert!(json.contains("\"reply_to_message_id\":7"));
        assert!(json.contains("\"message_thread_id\":99"));
    }

    #[test]
    fn send_message_request_skip_serializing_none_fields() {
        let req = SendMessageRequest {
            chat_id: "999".into(),
            text: "Minimal".into(),
            parse_mode: None,
            reply_to_message_id: None,
            message_thread_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"chat_id\""));
        assert!(json.contains("\"text\""));
        assert!(!json.contains("parse_mode"));
        assert!(!json.contains("reply_to_message_id"));
        assert!(!json.contains("message_thread_id"));
    }

    // ---- GetUpdatesRequest additional ----

    #[test]
    fn get_updates_request_with_all_fields() {
        let req = GetUpdatesRequest {
            offset: Some(500),
            limit: Some(100),
            timeout: Some(30),
            allowed_updates: Some(vec!["message".into(), "callback_query".into()]),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"offset\":500"));
        assert!(json.contains("\"limit\":100"));
        assert!(json.contains("\"timeout\":30"));
        assert!(json.contains("\"allowed_updates\""));
        assert!(json.contains("\"message\""));
        assert!(json.contains("\"callback_query\""));
    }

    #[test]
    fn get_updates_request_serialize_with_allowed_updates() {
        let req = GetUpdatesRequest {
            offset: None,
            limit: None,
            timeout: None,
            allowed_updates: Some(vec![
                "message".into(),
                "edited_message".into(),
                "channel_post".into(),
            ]),
        };
        let val: serde_json::Value = serde_json::to_value(&req).unwrap();
        let updates = val["allowed_updates"].as_array().unwrap();
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0], "message");
        assert_eq!(updates[2], "channel_post");
    }

    // ---- UpdateKind additional ----

    #[test]
    fn update_kind_edited_message() {
        let json = json!({
            "update_id": 200,
            "edited_message": {
                "message_id": 5,
                "chat": {"id": 100, "type": "private"},
                "date": 1_700_000_000,
                "text": "edited text"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        assert_eq!(update.update_id, 200);
        match &update.kind {
            UpdateKind::EditedMessage(msg) => {
                assert_eq!(msg.message_id, 5);
                assert_eq!(msg.text.as_deref(), Some("edited text"));
            }
            other => panic!("expected EditedMessage, got {other:?}"),
        }
    }

    #[test]
    fn update_kind_channel_post() {
        let json = json!({
            "update_id": 201,
            "channel_post": {
                "message_id": 77,
                "chat": {"id": -100_222, "type": "channel", "title": "News"},
                "date": 1_700_000_000,
                "text": "Channel announcement"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        match &update.kind {
            UpdateKind::ChannelPost(msg) => {
                assert_eq!(msg.message_id, 77);
                assert_eq!(msg.chat.chat_type, "channel");
                assert_eq!(msg.text.as_deref(), Some("Channel announcement"));
            }
            other => panic!("expected ChannelPost, got {other:?}"),
        }
    }

    #[test]
    fn update_kind_callback_query_variant() {
        let json = json!({
            "update_id": 202,
            "callback_query": {
                "id": "cq_update",
                "from": {"id": 42, "is_bot": false, "first_name": "Frank"},
                "chat_instance": "ci_val",
                "data": "btn_press"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        match &update.kind {
            UpdateKind::CallbackQuery(cq) => {
                assert_eq!(cq.id, "cq_update");
                assert_eq!(cq.data.as_deref(), Some("btn_press"));
            }
            other => panic!("expected CallbackQuery, got {other:?}"),
        }
    }

    #[test]
    fn update_kind_unknown_constructed_directly() {
        // #[serde(other)] with #[serde(flatten)] has limitations with
        // unrecognized keys in JSON. Test that the Unknown variant exists
        // and can be pattern-matched.
        let kind = UpdateKind::Unknown;
        assert!(matches!(kind, UpdateKind::Unknown));
        let debug = format!("{kind:?}");
        assert!(debug.contains("Unknown"));
    }

    #[test]
    fn update_kind_unknown_clone() {
        let kind = UpdateKind::Unknown;
        let cloned = kind.clone();
        assert!(matches!(kind, UpdateKind::Unknown));
        assert!(matches!(cloned, UpdateKind::Unknown));
    }

    #[test]
    fn update_kind_edited_channel_post() {
        let json = json!({
            "update_id": 204,
            "edited_channel_post": {
                "message_id": 88,
                "chat": {"id": -100_333, "type": "channel", "title": "EditedChan"},
                "date": 1_700_000_000,
                "text": "Corrected post"
            }
        });
        let update: Update = serde_json::from_value(json).unwrap();
        match &update.kind {
            UpdateKind::EditedChannelPost(msg) => {
                assert_eq!(msg.message_id, 88);
                assert_eq!(msg.text.as_deref(), Some("Corrected post"));
            }
            other => panic!("expected EditedChannelPost, got {other:?}"),
        }
    }
}
