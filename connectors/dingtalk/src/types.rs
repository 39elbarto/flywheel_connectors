//! `DingTalk` API and configuration types.

use serde::{Deserialize, Serialize};

pub const DEFAULT_BASE_URL: &str = "https://api.dingtalk.com";
pub const DEFAULT_MEDIA_BASE_URL: &str = "https://oapi.dingtalk.com";
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

#[derive(Clone, Deserialize)]
pub struct DingTalkConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_media_base_url")]
    pub media_base_url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl DingTalkConfig {
    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.base_url = self.base_url.trim().to_string();
        self.media_base_url = self.media_base_url.trim().to_string();
        self.client_id = self.client_id.trim().to_string();
        self.client_secret = self.client_secret.trim().to_string();
        self
    }
}

// Redact client_secret in Debug output
impl std::fmt::Debug for DingTalkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DingTalkConfig")
            .field("base_url", &self.base_url)
            .field("media_base_url", &self.media_base_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

fn default_media_base_url() -> String {
    DEFAULT_MEDIA_BASE_URL.to_string()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub expire_in: u64,
}

impl std::fmt::Debug for AccessTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expire_in", &self.expire_in)
            .finish()
    }
}

/// `DingTalk` robot callback event (inbound message via stream or HTTP callback).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DingTalkCallbackEvent {
    /// Message type: `"text"`, `"richText"`, `"picture"`, etc.
    pub msg_type: Option<String>,
    /// Text content (present when `msg_type` is `"text"`).
    pub text: Option<TextContent>,
    /// Sender `userId` (`DingTalk` open id).
    pub sender_id: Option<String>,
    /// Sender display name.
    pub sender_nick: Option<String>,
    /// Sender staff id within the organisation.
    pub sender_staff_id: Option<String>,
    /// Conversation open id.
    pub conversation_id: Option<String>,
    /// `"1"` = private (1-to-1), `"2"` = group chat.
    pub conversation_type: Option<String>,
    /// Group chat title (only present for group messages).
    pub conversation_title: Option<String>,
    /// Users that were @-mentioned in the message.
    pub at_users: Option<Vec<AtUser>>,
    /// The robot's own `userId`.
    pub chatbot_user_id: Option<String>,
    /// Message creation timestamp in milliseconds.
    pub create_at: Option<i64>,
    /// Unique message identifier.
    pub msg_id: Option<String>,
}

/// Text body inside a callback event.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TextContent {
    pub content: Option<String>,
}

/// An @-mentioned user inside a callback event.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AtUser {
    pub dingtalk_id: Option<String>,
    pub staff_id: Option<String>,
}

/// Normalized inbound event produced by [`normalize_callback_event`](crate::client::normalize_callback_event).
#[derive(Debug, Clone, Serialize)]
pub struct NormalizedDingTalkEvent {
    /// Always `"message"` for robot callback events.
    pub event_type: String,
    /// Unique message id from the callback.
    pub message_id: Option<String>,
    /// Conversation open id.
    pub conversation_id: Option<String>,
    /// `"private"` or `"group"`.
    pub conversation_type: String,
    /// Sender open id.
    pub sender_id: Option<String>,
    /// Sender display name.
    pub sender_name: Option<String>,
    /// Extracted plain-text body.
    pub text: Option<String>,
    /// Creation timestamp in milliseconds.
    pub timestamp_ms: Option<i64>,
    /// Whether the bot was @-mentioned in this message.
    pub at_bot: bool,
    /// The original callback payload for pass-through.
    pub raw: serde_json::Value,
}

/// Identity of a `DingTalk` conversation.
#[derive(Debug, Clone, Serialize)]
pub struct ConversationIdentity {
    /// Conversation open id.
    pub id: String,
    /// `"private"` or `"group"`.
    pub conversation_type: String,
    /// Group title (None for private chats).
    pub title: Option<String>,
}

/// Metadata for a media attachment inside a callback event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub media_id: Option<String>,
    pub file_name: Option<String>,
    pub file_type: Option<String>,
    pub download_url: Option<String>,
}

/// Parsed target for `DingTalk` message routing.
#[derive(Debug, Clone, Copy)]
pub struct ParsedTarget<'a> {
    pub id: &'a str,
    pub is_group: bool,
}

impl<'a> ParsedTarget<'a> {
    #[allow(clippy::option_if_let_else)]
    #[must_use]
    pub fn parse(raw: &'a str) -> Self {
        if let Some(id) = raw.strip_prefix("chat:") {
            Self { id, is_group: true }
        } else if let Some(id) = raw.strip_prefix("user:") {
            Self {
                id,
                is_group: false,
            }
        } else {
            Self {
                id: raw,
                is_group: false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserializes_defaults() {
        let json = r#"{
            "client_id": "test_id",
            "client_secret": "test_secret"
        }"#;
        let config: DingTalkConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.media_base_url, DEFAULT_MEDIA_BASE_URL);
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.client_id, "test_id");
        assert_eq!(config.client_secret, "test_secret");
    }

    #[test]
    fn config_debug_redacts_secret() {
        let json = r#"{
            "client_id": "myid",
            "client_secret": "super_secret_value"
        }"#;
        let config: DingTalkConfig = serde_json::from_str(json).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_value"));
        assert!(debug.contains("myid"));
    }

    #[test]
    fn config_normalized_trims_whitespace() {
        let config = DingTalkConfig {
            base_url: " https://api.dingtalk.com ".into(),
            media_base_url: " https://oapi.dingtalk.com ".into(),
            client_id: " ding-app ".into(),
            client_secret: " secret ".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        }
        .normalized();
        assert_eq!(config.base_url, "https://api.dingtalk.com");
        assert_eq!(config.media_base_url, "https://oapi.dingtalk.com");
        assert_eq!(config.client_id, "ding-app");
        assert_eq!(config.client_secret, "secret");
    }

    #[test]
    fn parsed_target_chat_prefix() {
        let target = ParsedTarget::parse("chat:group123");
        assert_eq!(target.id, "group123");
        assert!(target.is_group);
    }

    #[test]
    fn parsed_target_user_prefix() {
        let target = ParsedTarget::parse("user:user456");
        assert_eq!(target.id, "user456");
        assert!(!target.is_group);
    }

    #[test]
    fn parsed_target_bare_id() {
        let target = ParsedTarget::parse("some_bare_id");
        assert_eq!(target.id, "some_bare_id");
        assert!(!target.is_group);
    }

    #[test]
    fn access_token_response_deserializes() {
        let json = r#"{"accessToken": "tok_abc", "expireIn": 7200}"#;
        let resp: AccessTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok_abc");
        assert_eq!(resp.expire_in, 7200);
    }

    // ── Callback event deserialization tests ──────────────────────

    #[test]
    fn callback_event_deserializes_full_payload() {
        let json = r#"{
            "msgType": "text",
            "text": { "content": "hello bot" },
            "senderId": "user-001",
            "senderNick": "Alice",
            "senderStaffId": "staff-001",
            "conversationId": "conv-123",
            "conversationType": "2",
            "conversationTitle": "Dev Team",
            "atUsers": [
                { "dingtalkId": "bot-999", "staffId": "staff-bot" }
            ],
            "chatbotUserId": "bot-999",
            "createAt": 1700000000000,
            "msgId": "msg-abc"
        }"#;
        let event: DingTalkCallbackEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.msg_type.as_deref(), Some("text"));
        assert_eq!(
            event.text.as_ref().unwrap().content.as_deref(),
            Some("hello bot")
        );
        assert_eq!(event.sender_id.as_deref(), Some("user-001"));
        assert_eq!(event.sender_nick.as_deref(), Some("Alice"));
        assert_eq!(event.sender_staff_id.as_deref(), Some("staff-001"));
        assert_eq!(event.conversation_id.as_deref(), Some("conv-123"));
        assert_eq!(event.conversation_type.as_deref(), Some("2"));
        assert_eq!(event.conversation_title.as_deref(), Some("Dev Team"));
        assert_eq!(event.chatbot_user_id.as_deref(), Some("bot-999"));
        assert_eq!(event.create_at, Some(1_700_000_000_000));
        assert_eq!(event.msg_id.as_deref(), Some("msg-abc"));
        let at = event.at_users.as_ref().unwrap();
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].dingtalk_id.as_deref(), Some("bot-999"));
    }

    #[test]
    fn callback_event_deserializes_minimal_payload() {
        let json = r"{}";
        let event: DingTalkCallbackEvent = serde_json::from_str(json).unwrap();
        assert!(event.msg_type.is_none());
        assert!(event.text.is_none());
        assert!(event.sender_id.is_none());
        assert!(event.conversation_id.is_none());
        assert!(event.at_users.is_none());
        assert!(event.chatbot_user_id.is_none());
        assert!(event.create_at.is_none());
        assert!(event.msg_id.is_none());
    }

    #[test]
    fn callback_event_private_conversation() {
        let json = r#"{ "conversationType": "1", "conversationId": "priv-1" }"#;
        let event: DingTalkCallbackEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.conversation_type.as_deref(), Some("1"));
    }

    #[test]
    fn text_content_with_none() {
        let json = r#"{ "content": null }"#;
        let tc: TextContent = serde_json::from_str(json).unwrap();
        assert!(tc.content.is_none());
    }

    #[test]
    fn text_content_serializes() {
        let tc = TextContent {
            content: Some("hello".into()),
        };
        let json = serde_json::to_string(&tc).unwrap();
        assert!(json.contains("hello"));
    }

    #[test]
    fn at_user_serializes_roundtrip() {
        let user = AtUser {
            dingtalk_id: Some("dt-1".into()),
            staff_id: Some("s-1".into()),
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: AtUser = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dingtalk_id.as_deref(), Some("dt-1"));
        assert_eq!(back.staff_id.as_deref(), Some("s-1"));
    }

    // ── Attachment metadata tests ────────────────────────────────

    #[test]
    fn attachment_meta_deserializes() {
        let json = r#"{
            "media_id": "m-1",
            "file_name": "report.pdf",
            "file_type": "application/pdf",
            "download_url": "https://example.com/report.pdf"
        }"#;
        let meta: AttachmentMeta = serde_json::from_str(json).unwrap();
        assert_eq!(meta.media_id.as_deref(), Some("m-1"));
        assert_eq!(meta.file_name.as_deref(), Some("report.pdf"));
        assert_eq!(meta.file_type.as_deref(), Some("application/pdf"));
        assert_eq!(
            meta.download_url.as_deref(),
            Some("https://example.com/report.pdf")
        );
    }

    #[test]
    fn attachment_meta_serializes_roundtrip() {
        let meta = AttachmentMeta {
            media_id: Some("m-2".into()),
            file_name: None,
            file_type: Some("image/png".into()),
            download_url: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: AttachmentMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.media_id.as_deref(), Some("m-2"));
        assert!(back.file_name.is_none());
        assert_eq!(back.file_type.as_deref(), Some("image/png"));
        assert!(back.download_url.is_none());
    }

    #[test]
    fn attachment_meta_all_none() {
        let json = r"{}";
        let meta: AttachmentMeta = serde_json::from_str(json).unwrap();
        assert!(meta.media_id.is_none());
        assert!(meta.file_name.is_none());
        assert!(meta.file_type.is_none());
        assert!(meta.download_url.is_none());
    }

    // ── ConversationIdentity tests ───────────────────────────────

    #[test]
    fn conversation_identity_serializes() {
        let ci = ConversationIdentity {
            id: "conv-1".into(),
            conversation_type: "group".into(),
            title: Some("Engineering".into()),
        };
        let json = serde_json::to_string(&ci).unwrap();
        assert!(json.contains("conv-1"));
        assert!(json.contains("group"));
        assert!(json.contains("Engineering"));
    }

    // ── NormalizedDingTalkEvent tests ─────────────────────────────

    #[test]
    fn normalized_event_serializes() {
        let event = NormalizedDingTalkEvent {
            event_type: "message".into(),
            message_id: Some("msg-1".into()),
            conversation_id: Some("conv-1".into()),
            conversation_type: "private".into(),
            sender_id: Some("u-1".into()),
            sender_name: Some("Bob".into()),
            text: Some("hi".into()),
            timestamp_ms: Some(1_700_000_000_000),
            at_bot: false,
            raw: serde_json::json!({}),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"message\""));
        assert!(json.contains("\"at_bot\":false"));
        assert!(json.contains("\"conversation_type\":\"private\""));
    }
}
